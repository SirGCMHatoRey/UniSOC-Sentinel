"""
Redis stream consumer for the alerting-engine service.

Reads events from the "siem:parsed_logs" stream using a consumer group
("siem-alerting") so that multiple alerting-engine replicas can share the
workload without processing duplicate events.

Processing flow per message:
  1. Deserialise the JSON event payload.
  2. Evaluate all alert rules (via RuleEvaluator).
  3. For each triggered alert: persist to PostgreSQL and publish to Redis.
  4. Acknowledge the stream message (XACK) so it is not redelivered.

If the evaluator raises an unexpected exception the message is logged and
acknowledged anyway to prevent the consumer from blocking on a poison message.
Unacknowledged messages will be claimed by a future XAUTOCLAIM sweep.
"""

from __future__ import annotations

import asyncio
import json

import structlog
from redis.asyncio import Redis

from .evaluator import RuleEvaluator
from .metrics import Metrics
from .persistence import AlertPersistence
from .publisher import AlertPublisher

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

STREAM_KEY = "siem:parsed_logs"
CONSUMER_GROUP = "siem-alerting"
CONSUMER_NAME = "alerting-0"
BATCH_SIZE = 50
BLOCK_MS = 2000  # block for 2 s waiting for new messages


class AlertingWorker:
    """
    Async consumer that reads from the Redis stream and drives the alerting pipeline.

    Args:
        redis:       Async Redis client (shared connection pool).
        evaluator:   RuleEvaluator instance.
        persistence: AlertPersistence instance for PostgreSQL writes.
        publisher:   AlertPublisher instance for Redis pub/sub.
        metrics:     Prometheus metrics instance.
        consumer_id: Optional integer suffix appended to the consumer name
                     (useful when running multiple worker instances).
    """

    def __init__(
        self,
        redis: Redis,
        evaluator: RuleEvaluator,
        persistence: AlertPersistence,
        publisher: AlertPublisher,
        metrics: Metrics,
        consumer_id: int = 0,
    ) -> None:
        self._redis = redis
        self._evaluator = evaluator
        self._persistence = persistence
        self._publisher = publisher
        self._metrics = metrics
        self._consumer_name = f"alerting-{consumer_id}"
        self._running = False

    async def start(self) -> None:
        """
        Ensure the consumer group exists and start consuming in a background task.

        XGROUP CREATE with MKSTREAM creates the stream if it does not yet exist.
        The BUSYGROUP error is swallowed — it just means the group was already
        created by a previous run or a sibling replica.
        """
        await self._ensure_consumer_group()
        self._running = True
        self._task = asyncio.create_task(self._consume_loop(), name="alerting-consumer")
        log.info(
            "AlertingWorker started",
            consumer=self._consumer_name,
            stream=STREAM_KEY,
            group=CONSUMER_GROUP,
        )

    async def stop(self) -> None:
        """Signal the consumer loop to exit and wait for it to finish."""
        self._running = False
        if hasattr(self, "_task"):
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("AlertingWorker stopped")

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    async def _ensure_consumer_group(self) -> None:
        """
        Create the consumer group on the stream (XGROUP CREATE … MKSTREAM).

        Tolerates the BUSYGROUP error that Redis raises when the group already
        exists so that concurrent startups and service restarts are safe.
        """
        try:
            await self._redis.xgroup_create(
                STREAM_KEY,
                CONSUMER_GROUP,
                id="$",
                mkstream=True,
            )
            log.info(
                "Consumer group created",
                group=CONSUMER_GROUP,
                stream=STREAM_KEY,
            )
        except Exception as exc:
            if "BUSYGROUP" in str(exc):
                log.debug("Consumer group already exists", group=CONSUMER_GROUP)
            else:
                raise

    async def _consume_loop(self) -> None:
        """
        Main consume loop.  Reads batches of messages and dispatches them.

        Blocks up to BLOCK_MS milliseconds waiting for new messages so that
        the loop does not spin-wait when the stream is idle.
        """
        log.info("Consume loop running", consumer=self._consumer_name)
        while self._running:
            try:
                messages = await self._redis.xreadgroup(
                    CONSUMER_GROUP,
                    self._consumer_name,
                    {STREAM_KEY: ">"},
                    count=BATCH_SIZE,
                    block=BLOCK_MS,
                )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("xreadgroup failed", error=str(exc))
                await asyncio.sleep(1)
                continue

            if not messages:
                continue

            for _stream, msgs in messages:
                for msg_id, data in msgs:
                    await self._process_message(msg_id, data)

    async def _process_message(self, msg_id: bytes, data: dict) -> None:
        """
        Process a single stream message: evaluate, persist, publish, ack.

        Args:
            msg_id: Redis stream message identifier.
            data:   Raw field dict from the stream entry.
        """
        self._metrics.events_consumed_total.inc()
        try:
            raw = data.get(b"event") or data.get("event") or b"{}"
            if isinstance(raw, bytes):
                raw = raw.decode()
            event = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            log.warning(
                "Failed to deserialise stream message",
                msg_id=msg_id,
                error=str(exc),
            )
            await self._ack(msg_id)
            return

        try:
            alerts = await self._evaluator.evaluate(event)
        except Exception as exc:
            log.error(
                "Rule evaluation error",
                msg_id=msg_id,
                error=str(exc),
                exc_info=True,
            )
            await self._ack(msg_id)
            return

        for alert in alerts:
            try:
                await self._persistence.save(alert)
            except Exception as exc:
                log.error(
                    "Failed to persist alert",
                    alert_id=alert.get("id"),
                    error=str(exc),
                    exc_info=True,
                )
            try:
                await self._publisher.publish(alert)
            except Exception as exc:
                log.error(
                    "Failed to publish alert",
                    alert_id=alert.get("id"),
                    error=str(exc),
                    exc_info=True,
                )

        await self._ack(msg_id)

    async def _ack(self, msg_id: bytes) -> None:
        """Acknowledge a stream message so it is not redelivered."""
        try:
            await self._redis.xack(STREAM_KEY, CONSUMER_GROUP, msg_id)
        except Exception as exc:
            log.warning("XACK failed", msg_id=msg_id, error=str(exc))
