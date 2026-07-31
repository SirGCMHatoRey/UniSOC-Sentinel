"""
Alert throttling using Redis SET NX.

Throttling differs from deduplication: it limits how frequently alerts for
a specific rule+group combination are emitted, regardless of the dedup key.
This prevents alert storms where many distinct events trigger the same rule
rapidly in succession.
"""

from __future__ import annotations

import structlog
from redis.asyncio import Redis

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class AlertThrottler:
    """
    Rate-limits alert emission using Redis SET NX with a per-rule window.

    Each rule+group pair gets a throttle key:
        alert:throttle:<rule_id>:<group_key>  ->  "1"  (expires after throttle_seconds)

    The first SET NX within the throttle window succeeds, allowing the alert.
    Subsequent firings within the same window are suppressed.

    Args:
        redis: An async Redis client instance.
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def is_throttled(
        self,
        rule_id: str,
        group_key: str,
        throttle_seconds: int,
    ) -> bool:
        """
        Check whether an alert for this rule+group is within its throttle window.

        Args:
            rule_id:          The rule identifier (used in the Redis key).
            group_key:        The grouped value (e.g. a source IP address).
            throttle_seconds: How long to suppress repeat alerts after the first.

        Returns:
            True  — alert is throttled; caller should drop it.
            False — alert passes throttle check; caller should continue processing.
        """
        key = f"alert:throttle:{rule_id}:{group_key}"
        result = await self._redis.set(key, "1", nx=True, ex=throttle_seconds)
        is_throttled = result is None
        if is_throttled:
            log.debug(
                "Alert throttled",
                rule_id=rule_id,
                group_key=group_key,
                throttle_seconds=throttle_seconds,
            )
        return is_throttled
