"""
Redis pub/sub subscriber for the email-notifier service.

Listens on the "siem:alert_notifications" channel (published by the
alerting-engine) and dispatches each received alert to the email sender.

Deduplication:
  The alerting-engine already deduplicates at the source, but the subscriber
  also maintains a local seen-set in Redis (``notifier:seen:<alert_id>``)
  with a short TTL (default 1 hour) to prevent duplicate emails in edge
  cases where the pub/sub message is delivered more than once (e.g. during
  a restart race or if multiple notifier replicas are running).

Error isolation:
  SMTP send failures do not crash the subscriber loop.  They are caught,
  logged, and counted in Prometheus so they are visible without interrupting
  the processing of subsequent alerts.
"""

from __future__ import annotations

import asyncio
import json

import structlog
from redis.asyncio import Redis

from .metrics import Metrics
from .renderer import EmailRenderer
from .sender import EmailSender

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

ALERT_CHANNEL = "siem:alert_notifications"
SEEN_TTL_SECONDS = 3600  # 1 hour dedup window for the notifier


class AlertSubscriber:
    """
    Subscribes to the Redis alert channel and sends email notifications.

    Args:
        redis:      Async Redis client.
        renderer:   EmailRenderer instance for building email bodies.
        sender:     EmailSender instance for SMTP delivery.
        recipients: List of email addresses to notify.
        metrics:    Prometheus metrics instance.
    """

    def __init__(
        self,
        redis: Redis,
        renderer: EmailRenderer,
        sender: EmailSender,
        recipients: list[str],
        metrics: Metrics,
    ) -> None:
        self._redis = redis
        self._renderer = renderer
        self._sender = sender
        self._recipients = recipients
        self._metrics = metrics
        self._running = False

    async def start(self) -> None:
        """Start the subscription loop in a background asyncio task."""
        self._running = True
        self._task = asyncio.create_task(self._subscribe_loop(), name="alert-subscriber")
        log.info(
            "AlertSubscriber started",
            channel=ALERT_CHANNEL,
            recipient_count=len(self._recipients),
        )

    async def stop(self) -> None:
        """Cancel the subscription task and wait for it to finish."""
        self._running = False
        if hasattr(self, "_task"):
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("AlertSubscriber stopped")

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    async def _subscribe_loop(self) -> None:
        """
        Main pub/sub loop.

        Creates a dedicated pubsub connection, subscribes to the alert
        channel, and processes messages as they arrive.  On connection
        errors the loop backs off for 5 seconds before reconnecting.
        """
        while self._running:
            pubsub = self._redis.pubsub()
            try:
                await pubsub.subscribe(ALERT_CHANNEL)
                log.info("Subscribed to Redis channel", channel=ALERT_CHANNEL)

                async for message in pubsub.listen():
                    if not self._running:
                        break
                    if message.get("type") != "message":
                        continue
                    await self._handle_message(message)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error(
                    "Pub/sub connection error; reconnecting",
                    error=str(exc),
                    exc_info=True,
                )
                await asyncio.sleep(5)
            finally:
                try:
                    await pubsub.unsubscribe(ALERT_CHANNEL)
                    await pubsub.aclose()
                except Exception:
                    pass

    async def _handle_message(self, message: dict) -> None:
        """
        Process a single pub/sub message: deserialise, dedup, render, send.

        Args:
            message: Raw Redis pub/sub message dict with a ``data`` field.
        """
        try:
            raw = message.get("data", b"")
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            alert = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            log.warning("Failed to deserialise alert message", error=str(exc))
            return

        alert_id = alert.get("id", "")
        rule_id = alert.get("rule_id", "unknown")

        # Local deduplication guard
        if alert_id and await self._is_duplicate(alert_id):
            log.debug("Duplicate alert suppressed by notifier", alert_id=alert_id)
            return

        log.info(
            "Alert received",
            alert_id=alert_id,
            rule_id=rule_id,
            severity=alert.get("severity"),
            title=alert.get("title"),
        )

        # Render email
        try:
            subject, html_body = self._renderer.render(rule_id, alert)
        except Exception as exc:
            log.error(
                "Template rendering failed",
                alert_id=alert_id,
                rule_id=rule_id,
                error=str(exc),
                exc_info=True,
            )
            return

        # Send email — failures are isolated and do not crash the loop
        with self._metrics.email_send_duration_seconds.time():
            try:
                await self._sender.send(subject, html_body, self._recipients)
                self._metrics.emails_sent_total.labels(rule_id=rule_id).inc()
                log.info(
                    "Alert email sent",
                    alert_id=alert_id,
                    rule_id=rule_id,
                    subject=subject,
                )
            except Exception as exc:
                # email_errors_total already incremented inside EmailSender
                log.error(
                    "Email delivery failed",
                    alert_id=alert_id,
                    rule_id=rule_id,
                    error=str(exc),
                )

    async def _is_duplicate(self, alert_id: str) -> bool:
        """
        Check and mark an alert as seen using Redis SET NX.

        The seen key expires after SEEN_TTL_SECONDS so the dedup window
        is bounded and memory usage stays constant.

        Args:
            alert_id: UUID string of the alert.

        Returns:
            True if the alert was already processed; False if it is new.
        """
        key = f"notifier:seen:{alert_id}"
        result = await self._redis.set(key, "1", nx=True, ex=SEEN_TTL_SECONDS)
        return result is None  # None = key already existed = duplicate
