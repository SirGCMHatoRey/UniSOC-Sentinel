"""
Redis stream publisher for the syslog-ingestion service.

Each call to publish() atomically writes one syslog message to the Redis
stream "siem:raw_logs" using XADD with approximate MAXLEN trimming.

Retry behaviour: up to MAX_RETRIES attempts with exponential back-off
(base 0.5 s, cap 30 s) on transient Redis errors.  After exhausting
retries the error is logged and the redis_publish_errors_total counter
is incremented; the caller decides whether to discard or re-queue.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError

from .config import Settings
from .metrics import Metrics

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

# Redis stream name — shared contract with downstream parser-pipeline
STREAM_NAME = "siem:raw_logs"

# Approximate maximum stream length (~ operator keeps it non-blocking)
STREAM_MAXLEN = 50_000

# Retry configuration for transient Redis failures
MAX_RETRIES = 5
RETRY_BASE_DELAY = 0.5   # seconds
RETRY_MAX_DELAY = 30.0   # seconds


class RedisPublisher:
    """
    Async Redis stream publisher.

    Must be initialised with ``await publisher.connect()`` before use,
    and cleaned up with ``await publisher.close()``.
    """

    def __init__(self, settings: Settings, metrics: Metrics) -> None:
        self._settings = settings
        self._metrics = metrics
        self._redis: Redis | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Open the Redis connection pool and verify connectivity.

        Also ensures the target stream exists so downstream consumer groups
        can be created even before the first message arrives.
        """
        password = self._settings.redis_password

        self._redis = Redis(
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            password=password,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
        )

        # Verify the connection is live
        await self._redis.ping()

        # Create the stream with a sentinel entry if it does not yet exist.
        # This allows downstream services to create consumer groups before the
        # first real message is written.
        stream_exists = await self._redis.exists(STREAM_NAME)
        if not stream_exists:
            await self._redis.xadd(
                STREAM_NAME,
                {"_init": "1"},
                maxlen=STREAM_MAXLEN,
                approximate=True,
            )
            log.info("Redis stream initialised", stream=STREAM_NAME)

        log.info(
            "Redis publisher connected",
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            stream=STREAM_NAME,
        )

    async def close(self) -> None:
        """Close the Redis connection pool gracefully."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None
            log.info("Redis publisher closed")

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def publish(self, raw_message: str, source_ip: str) -> None:
        """
        Write one syslog message to the Redis stream.

        The message envelope matches the shared interface contract::

            {
                "id":          "<uuid4>",
                "raw":         "<original syslog line>",
                "received_at": "<ISO8601 UTC>",
                "source_ip":   "<dotted-quad or IPv6>"
            }

        Args:
            raw_message: The decoded syslog line, already stripped of nulls.
            source_ip:   Source IP extracted from the UDP datagram address.

        Raises:
            RedisError: After MAX_RETRIES failed attempts, re-raises the last
                        exception so the caller can decide disposition.
        """
        if self._redis is None:
            raise RuntimeError("RedisPublisher.connect() has not been called")

        message: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "raw": raw_message,
            "received_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "source_ip": source_ip,
        }

        last_exc: Exception | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                await self._redis.xadd(
                    STREAM_NAME,
                    message,
                    maxlen=STREAM_MAXLEN,
                    approximate=True,
                )
                self._metrics.packets_processed_total.inc()
                return  # success — exit retry loop

            except RedisError as exc:
                last_exc = exc
                self._metrics.redis_publish_errors_total.inc()

                if attempt < MAX_RETRIES:
                    delay = min(
                        RETRY_BASE_DELAY * (2 ** (attempt - 1)),
                        RETRY_MAX_DELAY,
                    )
                    log.warning(
                        "Redis publish failed — retrying",
                        attempt=attempt,
                        max_retries=MAX_RETRIES,
                        delay_seconds=delay,
                        error=str(exc),
                        message_id=message["id"],
                        source_ip=source_ip,
                    )
                    await asyncio.sleep(delay)
                else:
                    log.error(
                        "Redis publish failed after all retries — discarding message",
                        attempts=MAX_RETRIES,
                        error=str(exc),
                        message_id=message["id"],
                        source_ip=source_ip,
                    )

        # Re-raise so WorkerPool can track the failure
        raise last_exc  # type: ignore[misc]
