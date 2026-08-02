"""
Alert publisher — broadcasts alert JSON to Redis pub/sub channels.

The email-notifier service (and any other downstream consumers) subscribe to
"siem:alert_notifications" and receive the serialised alert dict immediately
when publish() is called.

The dashboard's WebSocket bridge (services/siem-core) subscribes to
"siem:live_stream" and expects each message wrapped in the same
{"type": "alert", "data": {...}} envelope used by the correlation engine
(services/siem-core/src/correlation/engine.py::_publish_alert), so alerts
raised by YAML rules render identically to correlation-engine alerts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import structlog
from redis.asyncio import Redis

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

ALERT_CHANNEL = "siem:alert_notifications"
LIVE_STREAM_CHANNEL = "siem:live_stream"


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
        Publish *alert* to both the notification channel and the dashboard
        live-stream channel.

        The two publishes are independently fault-isolated: a failure on one
        channel does not prevent the other from being attempted. The
        live-stream publish is attempted first and never raises (failures are
        caught and logged, matching the correlation engine's convention); the
        notification publish runs afterwards and keeps its original,
        unchanged behaviour of propagating Redis errors to the caller.

        Args:
            alert: The alert dict conforming to the shared interface contract.
                   Must be JSON-serialisable.

        Raises:
            redis.exceptions.RedisError: On connection or command failure
                while publishing to the notification channel.
        """
        await self._publish_live_stream(alert)

        payload = json.dumps(alert, default=str)
        subscriber_count = await self._redis.publish(ALERT_CHANNEL, payload)
        log.info(
            "Alert published",
            alert_id=alert.get("id"),
            rule_id=alert.get("rule_id"),
            severity=alert.get("severity"),
            subscribers=subscriber_count,
        )

    async def _publish_live_stream(self, alert: dict) -> None:
        """
        Publish *alert* to the dashboard live-stream channel, wrapped in the
        same {"type": "alert", "data": {...}} envelope used by
        services/siem-core/src/correlation/engine.py::_publish_alert.

        Failures are caught and logged rather than propagated, so a
        live-stream outage never blocks the (higher-priority) notification
        publish.
        """
        try:
            envelope = {
                "type": "alert",
                "data": {
                    **alert,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            }
            payload = json.dumps(envelope, default=str)
            await self._redis.publish(LIVE_STREAM_CHANNEL, payload)
        except Exception as exc:
            log.error(
                "Failed to publish alert to live-stream channel",
                error=str(exc),
                alert_id=alert.get("id"),
                rule_id=alert.get("rule_id"),
            )
