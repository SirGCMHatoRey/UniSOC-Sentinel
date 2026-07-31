"""
Alert deduplication using Redis SET NX (set-if-not-exists).

A deduplication key marks that an alert has already been raised recently.
When the same alert would fire again within the TTL window, it is silently
discarded.  The key expires automatically, so alerts resume after the TTL.
"""

from __future__ import annotations

import structlog
from redis.asyncio import Redis

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class AlertDeduplicator:
    """
    Suppresses duplicate alerts using Redis SET NX with a configurable TTL.

    Each unique dedup key is stored in Redis as:
        alert:dedup:<rendered_dedup_key>  ->  "1"  (expires after dedup_ttl_seconds)

    The first SET NX succeeds (returns True) meaning the alert is *new*.
    Subsequent calls within the TTL window return None (key already present),
    meaning the alert is a *duplicate* and should be dropped.

    Args:
        redis: An async Redis client instance (connection pool shared across
               the process).
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def is_duplicate(self, dedup_key: str, ttl: int) -> bool:
        """
        Check whether an alert with this dedup key was recently triggered.

        Sets the key in Redis with NX+EX semantics atomically.  If the key
        already existed (SET returns None), the alert is a duplicate.

        Args:
            dedup_key: Rendered deduplication key string (e.g. "brute_force:1.2.3.4").
            ttl:       Time-to-live in seconds for the dedup marker.

        Returns:
            True  — alert is a duplicate; caller should drop it.
            False — alert is new; caller should emit it and set the dedup marker.
        """
        redis_key = f"alert:dedup:{dedup_key}"
        result = await self._redis.set(redis_key, "1", nx=True, ex=ttl)
        # SET NX returns True when the key was set (new alert),
        # and None when the key already existed (duplicate).
        is_dup = result is None
        if is_dup:
            log.debug("Alert deduplicated", dedup_key=dedup_key)
        return is_dup
