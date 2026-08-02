"""
Correlation engine — reads from Redis stream "siem:parsed_logs",
evaluates each event against all correlation rules, persists triggered
alerts to PostgreSQL, and broadcasts them to WebSocket clients.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from src.config import Settings
from src.correlation.rules import (
    AdminAbuseRule,
    BruteForceRule,
    LateralMovementRule,
    PortScanRule,
    RogueDeviceRule,
    VPNAnomalyRule,
)
from src.correlation.rules.base import BaseCorrelationRule

log = structlog.get_logger(__name__)

_STREAM_KEY = "siem:parsed_logs"
_LIVE_CHANNEL = "siem:live_stream"
_NOTIFICATION_CHANNEL = "siem:alert_notifications"
_READ_COUNT = 100
_BLOCK_MS = 1000  # block for 1s waiting for new messages


class CorrelationEngine:
    """
    Background asyncio task that consumes the parsed-logs Redis stream
    and fires correlation rules against each event.

    Rules are evaluated in sequence; evaluation errors are caught per-rule
    so a buggy rule cannot crash the engine.
    """

    def __init__(
        self,
        redis,
        db_session_factory,
        settings: Settings,
    ) -> None:
        self._redis = redis
        self._db_factory = db_session_factory
        self._settings = settings
        self._running = True

        # Instantiate all rules
        self._rules: list[BaseCorrelationRule] = [
            BruteForceRule(),
            PortScanRule(),
            RogueDeviceRule(),
            VPNAnomalyRule(),
            LateralMovementRule(),
            AdminAbuseRule(),
        ]

        log.info(
            "Correlation engine initialised",
            rules=[r.rule_id for r in self._rules],
        )

    async def run(self) -> None:
        """
        Main loop: XREAD from siem:parsed_logs, evaluate each event.

        Uses "$" as the initial last_id so we only process new events
        (not replay the full stream history on startup).
        """
        log.info("Correlation engine starting", stream=_STREAM_KEY)
        last_id = "$"

        while self._running:
            try:
                results = await self._redis.xread(
                    {_STREAM_KEY: last_id},
                    count=_READ_COUNT,
                    block=_BLOCK_MS,
                )
                if not results:
                    continue

                for stream, messages in results:
                    for msg_id, data in messages:
                        last_id = msg_id if isinstance(msg_id, str) else msg_id.decode()
                        await self._process_message(data)

            except asyncio.CancelledError:
                log.info("Correlation engine cancelled")
                self._running = False
                break
            except Exception as exc:
                log.error(
                    "Correlation engine loop error — retrying in 2s",
                    error=str(exc),
                )
                await asyncio.sleep(2)

        log.info("Correlation engine stopped")

    async def _process_message(self, data: dict) -> None:
        """Deserialise a stream message and evaluate all rules."""
        try:
            raw = data.get(b"event") or data.get("event")
            if raw is None:
                return
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            event = json.loads(raw)
        except (json.JSONDecodeError, Exception) as exc:
            log.warning("Failed to deserialise stream message", error=str(exc))
            return

        await self._evaluate(event)

    async def _evaluate(self, event: dict[str, Any]) -> None:
        """Run all rules against the event; persist any triggered alerts."""
        for rule in self._rules:
            try:
                alert = await rule.evaluate(event, self._redis)
                if alert is not None:
                    alert["id"] = str(uuid.uuid4())
                    log.info(
                        "Correlation rule triggered",
                        rule_id=rule.rule_id,
                        title=alert.get("title"),
                    )
                    await self._persist_alert(alert)
                    await self._publish_alert(alert)
                    await self._notify_alert(alert)
            except asyncio.CancelledError:
                raise  # propagate cancellation
            except Exception as exc:
                log.error(
                    "Correlation rule evaluation failed",
                    rule_id=rule.rule_id,
                    error=str(exc),
                )

    async def _persist_alert(self, alert: dict[str, Any]) -> None:
        """Insert the triggered alert into the PostgreSQL alerts table."""
        from src.models.alert import Alert

        record = Alert(
            id=alert["id"],
            rule_id=alert["rule_id"],
            rule_name=alert["rule_name"],
            severity=alert["severity"],
            title=alert["title"],
            description=alert.get("description"),
            event_count=alert.get("event_count", 1),
            metadata_=alert.get("metadata"),
            created_at=datetime.now(timezone.utc),
        )

        try:
            async with self._db_factory() as session:
                session.add(record)
                await session.commit()
        except Exception as exc:
            log.error("Failed to persist alert", error=str(exc), rule_id=alert["rule_id"])

    async def _publish_alert(self, alert: dict[str, Any]) -> None:
        """Publish the alert to the Redis live-stream channel for WebSocket broadcast."""
        try:
            payload = json.dumps(
                {
                    "type": "alert",
                    "data": {
                        **alert,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    },
                }
            )
            await self._redis.publish(_LIVE_CHANNEL, payload)
        except Exception as exc:
            log.error("Failed to publish alert to Redis", error=str(exc))

    async def _notify_alert(self, alert: dict[str, Any]) -> None:
        """
        Publish the bare alert dict to the notification channel consumed by
        email-notifier. Unlike _publish_alert, this is NOT wrapped in a
        {"type": ..., "data": ...} envelope — email-notifier reads fields
        (id, rule_id, severity, title, ...) directly off the top-level JSON.
        """
        try:
            payload = json.dumps(
                {**alert, "created_at": datetime.now(timezone.utc).isoformat()}
            )
            await self._redis.publish(_NOTIFICATION_CHANNEL, payload)
        except Exception as exc:
            log.error("Failed to publish alert notification to Redis", error=str(exc))

    def stop(self) -> None:
        """Signal the engine to stop after the current iteration."""
        self._running = False
