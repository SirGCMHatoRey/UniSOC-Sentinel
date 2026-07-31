"""
Entry point for the alerting-engine service.

Start-up order:
  1. Load Settings (env / secret files)
  2. Configure structlog with JSON renderer at the configured log level
  3. Load alert rules from YAML
  4. Create Prometheus Metrics instance
  5. Connect async Redis client
  6. Initialise PostgreSQL persistence (create schema)
  7. Build RuleEvaluator, AlertPublisher, AlertPersistence
  8. Start AlertingWorker (Redis stream consumer)
  9. Start HealthServer (HTTP /health + /metrics on METRICS_PORT)
 10. Block until SIGTERM or SIGINT

Shutdown order (reverse of start-up to avoid data loss):
  1. Stop AlertingWorker — no new events processed
  2. Stop HealthServer   — HTTP server no longer needed
  3. Close AlertPersistence — release DB connection pool
  4. Close Redis client   — release connection pool
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import structlog
from redis.asyncio import Redis

from .config import Settings
from .consumer import AlertingWorker
from .deduplicator import AlertDeduplicator
from .evaluator import RuleEvaluator
from .health import HealthServer
from .metrics import Metrics
from .persistence import AlertPersistence
from .publisher import AlertPublisher
from .rules import load_rules
from .throttler import AlertThrottler


def _configure_logging(log_level: str) -> None:
    """
    Configure structlog to emit JSON-formatted log records.

    The standard library root logger is also configured at the same level
    so that third-party libraries (redis, aiohttp, sqlalchemy) produce
    structured output.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    logging.getLogger("redis").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)


async def _run() -> None:
    """Async main — orchestrates the entire service lifecycle."""

    # ------------------------------------------------------------------
    # 1. Settings
    # ------------------------------------------------------------------
    settings = Settings()

    # ------------------------------------------------------------------
    # 2. Logging
    # ------------------------------------------------------------------
    _configure_logging(settings.log_level)
    log = structlog.get_logger(__name__)

    log.info(
        "alerting-engine service starting",
        redis_host=settings.redis_host,
        redis_port=settings.redis_port,
        postgres_host=settings.postgres_host,
        postgres_db=settings.postgres_db,
        rules_path=settings.rules_path,
        metrics_port=settings.metrics_port,
        log_level=settings.log_level,
    )

    # ------------------------------------------------------------------
    # 3. Load alert rules
    # ------------------------------------------------------------------
    rules = load_rules(settings.rules_path)
    log.info("Alert rules loaded", count=len(rules), rules=[r.id for r in rules])

    # ------------------------------------------------------------------
    # 4. Prometheus metrics
    # ------------------------------------------------------------------
    metrics = Metrics()

    # ------------------------------------------------------------------
    # 5. Redis client
    # ------------------------------------------------------------------
    redis = Redis.from_url(
        settings.redis_url,
        decode_responses=False,  # Keep raw bytes; we decode manually
        max_connections=20,
    )
    log.info("Redis client created", url=settings.redis_url.split("@")[-1])

    # ------------------------------------------------------------------
    # 6. PostgreSQL persistence
    # ------------------------------------------------------------------
    persistence = AlertPersistence(db_url=settings.db_url)
    await persistence.init_schema()

    # ------------------------------------------------------------------
    # 7. Build pipeline components
    # ------------------------------------------------------------------
    deduplicator = AlertDeduplicator(redis=redis)
    throttler = AlertThrottler(redis=redis)
    publisher = AlertPublisher(redis=redis)
    evaluator = RuleEvaluator(
        rules=rules,
        redis=redis,
        deduplicator=deduplicator,
        throttler=throttler,
        metrics=metrics,
    )

    # ------------------------------------------------------------------
    # 8. Stream consumer
    # ------------------------------------------------------------------
    worker = AlertingWorker(
        redis=redis,
        evaluator=evaluator,
        persistence=persistence,
        publisher=publisher,
        metrics=metrics,
        consumer_id=0,
    )

    # ------------------------------------------------------------------
    # 9. Health / metrics HTTP server
    # ------------------------------------------------------------------
    health_server = HealthServer(
        metrics=metrics,
        host="0.0.0.0",
        port=settings.metrics_port,
    )

    # ------------------------------------------------------------------
    # 10. Graceful shutdown plumbing
    # ------------------------------------------------------------------
    shutdown_event = asyncio.Event()

    def _request_shutdown(signame: str) -> None:
        log.info("Shutdown signal received", signal=signame)
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _request_shutdown, sig.name)
        except NotImplementedError:
            signal.signal(sig, lambda s, f: _request_shutdown(signal.Signals(s).name))

    # ------------------------------------------------------------------
    # Start all components
    # ------------------------------------------------------------------
    await health_server.start()
    await worker.start()

    log.info(
        "alerting-engine service ready",
        metrics=f"http://0.0.0.0:{settings.metrics_port}",
    )

    # ------------------------------------------------------------------
    # Block until shutdown is requested
    # ------------------------------------------------------------------
    await shutdown_event.wait()

    # ------------------------------------------------------------------
    # Graceful shutdown (reverse order)
    # ------------------------------------------------------------------
    log.info("Beginning graceful shutdown sequence")

    await worker.stop()
    await health_server.stop()
    await persistence.close()
    await redis.aclose()

    log.info("alerting-engine service stopped cleanly")


def main() -> None:
    """Synchronous entry point called by ``python -m src.main``."""
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass  # SIGINT handled inside _run; suppress the traceback


if __name__ == "__main__":
    main()
