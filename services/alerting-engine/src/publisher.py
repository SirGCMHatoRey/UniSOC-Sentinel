"""
Alert publisher — broadcasts alert JSON to the Redis pub/sub channel.

The email-notifier service (and any other downstream consumers) subscribe to
"siem:alert_notifications" and receive the serialised alert dict immediately
when publish() is called.
"""

from __future__ import annotations

import json

import structlog
from redis.asyncio import Redis

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

ALERT_CHANNEL = "siem:alert_notifications"


class AlertPublisher:
    """
    Publishes alert dicts to the Redis pub/sub channel.

    Args:
        redis: An async Redis client instance.
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def publish(self, alert: dict) -> None:
        """
        Serialise *alert* as JSON and publish it to the alert channel.

        Args:
            alert: The alert dict conforming to the shared interface contract.
                   Must be JSON-serialisable.

        Raises:
            redis.exceptions.RedisError: On connection or command failure.
        """
        payload = json.dumps(alert, default=str)
        subscriber_count = await self._redis.publish(ALERT_CHANNEL, payload)
        log.info(
            "Alert published",
            alert_id=alert.get("id"),
            rule_id=alert.get("rule_id"),
            severity=alert.get("severity"),
            subscribers=subscriber_count,
        )
