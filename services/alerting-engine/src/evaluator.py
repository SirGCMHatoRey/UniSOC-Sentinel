"""
Rule evaluator for the alerting-engine service.

The evaluator processes a single ECS-normalised event against every loaded
alert rule and returns a list of alert dicts for any rules whose threshold
was crossed and which were not suppressed by deduplication or throttling.

Sliding window counters are maintained in Redis using sorted sets:
  - Members: "<stream_msg_id>:<epoch_ms>" (unique per event within a window)
  - Score:   epoch_ms timestamp of the event
  - ZREMRANGEBYSCORE removes entries older than window_seconds
  - ZCARD returns the current count within the window

This approach is O(log N) per event and O(N) per ZCARD, which is efficient
for the typical cardinalities seen in a SIEM sliding window.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

import structlog
from redis.asyncio import Redis

from .deduplicator import AlertDeduplicator
from .metrics import Metrics
from .rules.loader import AlertRule
from .throttler import AlertThrottler

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class RuleEvaluator:
    """
    Evaluates alert rules against incoming events.

    For each event:
      1. Filter by dataset (skip if event.dataset not in rule.dataset_filter).
      2. Check rule condition field == condition value.
      3. Extract the group_by value (e.g. source IP) using dot notation.
      4. Increment the sliding window counter in Redis.
      5. Compare counter to threshold.
      6. If threshold crossed: check deduplication and throttling.
      7. If alert passes all checks: build and return the alert dict.

    Args:
        rules:         Loaded alert rules from YAML configuration.
        redis:         Async Redis client for sliding window counters.
        deduplicator:  AlertDeduplicator instance.
        throttler:     AlertThrottler instance.
        metrics:       Prometheus metrics instance.
    """

    def __init__(
        self,
        rules: list[AlertRule],
        redis: Redis,
        deduplicator: AlertDeduplicator,
        throttler: AlertThrottler,
        metrics: Metrics,
    ) -> None:
        self._rules = rules
        self._redis = redis
        self._deduplicator = deduplicator
        self._throttler = throttler
        self._metrics = metrics

    async def evaluate(self, event: dict) -> list[dict]:
        """
        Evaluate all applicable rules against *event*.

        Args:
            event: ECS-normalised event dict from the parser pipeline.

        Returns:
            List of alert dicts (may be empty) for rules that fired.
        """
        triggered: list[dict] = []
        event_dataset = self._get_nested(event, "event.dataset") or ""
        # Use a unique event id for the sliding window sorted set member
        event_id = str(uuid.uuid4())
        epoch_ms = int(time.time() * 1000)

        for rule in self._rules:
            timer = self._metrics.rule_evaluation_duration_seconds.labels(
                rule_id=rule.id
            ).time()
            with timer:
                self._metrics.rules_evaluated_total.labels(rule_id=rule.id).inc()

                # Step 1: dataset filter
                if rule.dataset_filter and event_dataset not in rule.dataset_filter:
                    continue

                # Step 2: field condition check
                if rule.condition.value is not None:
                    field_value = self._get_nested(event, rule.condition.field)
                    if str(field_value) != str(rule.condition.value):
                        continue

                # Step 3: extract group_by value
                group_value = self._get_nested(event, rule.condition.group_by)
                if group_value is None:
                    group_value = "unknown"
                group_key = str(group_value)

                # Step 4 & 5: sliding window counter in Redis
                count = await self._increment_window(
                    rule_id=rule.id,
                    group_key=group_key,
                    event_id=event_id,
                    epoch_ms=epoch_ms,
                    window_seconds=rule.condition.window_seconds,
                )

                if count < rule.condition.threshold:
                    continue

                # Step 6a: build template context
                context = self._build_context(event, group_key, count)

                # Step 6b: deduplication check
                rendered_dedup_key = self._render_template(rule.dedup_key, context)
                if await self._deduplicator.is_duplicate(
                    rendered_dedup_key, rule.dedup_ttl_seconds
                ):
                    self._metrics.alerts_deduplicated_total.labels(
                        rule_id=rule.id
                    ).inc()
                    continue

                # Step 6c: throttle check
                if await self._throttler.is_throttled(
                    rule.id, group_key, rule.throttle_seconds
                ):
                    self._metrics.alerts_throttled_total.labels(rule_id=rule.id).inc()
                    continue

                # Step 7: build alert dict
                alert = self._build_alert(rule, context, event, count)
                self._metrics.alerts_triggered_total.labels(
                    rule_id=rule.id, severity=rule.severity
                ).inc()

                log.info(
                    "Alert triggered",
                    rule_id=rule.id,
                    severity=rule.severity,
                    group_key=group_key,
                    event_count=count,
                    alert_id=alert["id"],
                )
                triggered.append(alert)

        return triggered

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _increment_window(
        self,
        rule_id: str,
        group_key: str,
        event_id: str,
        epoch_ms: int,
        window_seconds: int,
    ) -> int:
        """
        Update the sliding window sorted set for rule+group and return the
        current event count within the window.

        Uses a Redis pipeline for atomic ZADD + ZREMRANGEBYSCORE + ZCARD.

        The sorted set key is:
            alert:window:<rule_id>:<group_key>

        Each member encodes uniqueness with the event UUID + timestamp so that
        multiple events at the same millisecond are correctly counted.

        Args:
            rule_id:        Alert rule identifier.
            group_key:      The grouped value (e.g. "1.2.3.4").
            event_id:       UUID string uniquely identifying this event.
            epoch_ms:       Current Unix time in milliseconds (the score).
            window_seconds: Width of the sliding window in seconds.

        Returns:
            Number of events in the window after adding this event.
        """
        zset_key = f"alert:window:{rule_id}:{group_key}"
        cutoff_ms = epoch_ms - (window_seconds * 1000)
        member = f"{event_id}:{epoch_ms}"
        # Expire the key slightly beyond the window to allow natural cleanup
        key_ttl = window_seconds * 2

        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.zadd(zset_key, {member: epoch_ms})
            pipe.zremrangebyscore(zset_key, "-inf", cutoff_ms)
            pipe.zcard(zset_key)
            pipe.expire(zset_key, key_ttl)
            results = await pipe.execute()

        # results[2] is the ZCARD return value
        count: int = results[2]
        return count

    def _get_nested(self, obj: dict, path: str):
        """
        Retrieve a value from a nested dict using dot-notation path.

        Args:
            obj:  The dict to traverse.
            path: Dot-separated key path, e.g. "source.ip" or "event.outcome".

        Returns:
            The value at that path, or None if any key along the path is absent.
        """
        parts = path.split(".")
        current = obj
        for part in parts:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
            if current is None:
                return None
        return current

    def _render_template(self, template: str, context: dict) -> str:
        """
        Render a template string using str.format_map with the given context.

        Missing keys in the context are rendered as the literal key name
        (via a defaultdict-like fallback) to avoid KeyError on partial data.

        Args:
            template: Template string with {field} placeholders.
            context:  Dict of substitution values.

        Returns:
            Rendered string.
        """
        class SafeDict(dict):
            def __missing__(self, key: str) -> str:
                return f"{{{key}}}"

        return template.format_map(SafeDict(context))

    def _build_context(self, event: dict, group_key: str, count: int) -> dict:
        """
        Build a flat template substitution context from the event.

        Flattens common ECS fields into a single-level dict so templates
        like "{source.ip}" work with str.format_map (dots replaced by
        underscores would break, so we provide both).

        Args:
            event:     Raw event dict.
            group_key: The resolved group_by value for this evaluation.
            count:     Current sliding window event count.

        Returns:
            Flat dict suitable for str.format_map.
        """
        ctx: dict = {"event_count": count, "group_key": group_key}

        # Add flattened dot-notation values directly (e.g. "source.ip")
        def _flatten(d: dict, prefix: str = "") -> None:
            for k, v in d.items():
                full_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    _flatten(v, full_key)
                else:
                    ctx[full_key] = v if v is not None else ""

        _flatten(event)

        # Convenience shorthand aliases used in templates
        ctx.setdefault("source.ip", "unknown")
        ctx.setdefault("destination.ip", "unknown")
        ctx.setdefault("host.name", "unknown")
        return ctx

    def _build_alert(
        self,
        rule: AlertRule,
        context: dict,
        event: dict,
        count: int,
    ) -> dict:
        """
        Construct the canonical alert dict conforming to the shared interface
        contract.

        Args:
            rule:    The triggered alert rule.
            context: Template substitution context.
            event:   Original event dict (used to extract metadata).
            count:   Event count at threshold-crossing time.

        Returns:
            Alert dict with all required fields populated.
        """
        now = datetime.now(timezone.utc)
        alert_id = str(uuid.uuid4())

        # Build metadata from common ECS fields
        metadata: dict = {}
        for path in (
            "source.ip",
            "destination.ip",
            "host.name",
            "host.mac",
            "user.name",
            "network.name",
            "event.action",
        ):
            val = self._get_nested(event, path)
            if val is not None:
                metadata[path.replace(".", "_")] = val

        # Merge any extra metadata already on the event
        raw_metadata = event.get("metadata") or {}
        if isinstance(raw_metadata, dict):
            metadata.update(raw_metadata)

        return {
            "id": alert_id,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "title": self._render_template(rule.title_template, context),
            "description": self._render_template(rule.body_template, context),
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "event_count": count,
            "metadata": metadata,
        }
