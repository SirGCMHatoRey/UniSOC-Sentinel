"""
Entry point for the syslog-ingestion service.

Start-up order:
  1. Load Settings (env / secret files)
  2. Configure structlog with JSON renderer at the configured log level
  3. Create shared asyncio.Queue (backpressure buffer)
  4. Create Metrics instance (Prometheus collectors)
  5. Connect RedisPublisher
  6. Start WorkerPool
  7. Start HealthServer (HTTP /health + /metrics)
  8. Start UDP listener
  9. Block until SIGTERM or SIGINT

Shutdown order (reverse of start-up to avoid data loss):
  1. Stop UDP listener  — no new packets accepted
  2. Drain WorkerPool   — publish everything already queued
  3. Stop HealthServer  — HTTP server no longer needed
  4. Close Redis        — connection pool released
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import structlog

from .buffer import WorkerPool
from .config import Settings
from .health import HealthServer
from .listener import UDPListener
from .metrics import Metrics
from .publisher import RedisPublisher


def _configure_logging(log_level: str) -> None:
    """
    Configure structlog to emit JSON-formatted log records.

    The standard library root logger is also configured at the same level
    so that third-party libraries (redis, aiohttp) produce structured output.
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

    # Mirror to stdlib so aiohttp/redis logs flow through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )
    # Quieten verbose third-party loggers
    logging.getLogger("redis").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)


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
        "syslog-ingestion service starting",
        listen_host=settings.listen_host,
        listen_port=settings.listen_port,
        redis_host=settings.redis_host,
        redis_port=settings.redis_port,
        redis_db=settings.redis_db,
        worker_count=settings.worker_count,
        buffer_size=settings.buffer_size,
        metrics_port=settings.metrics_port,
        log_level=settings.log_level,
    )

    # ------------------------------------------------------------------
    # 3. Shared queue (backpressure)
    # ------------------------------------------------------------------
    queue: asyncio.Queue = asyncio.Queue(maxsize=settings.buffer_size)

    # ------------------------------------------------------------------
    # 4. Prometheus metrics
    # ------------------------------------------------------------------
    metrics = Metrics()

    # ------------------------------------------------------------------
    # 5. Redis publisher
    # ------------------------------------------------------------------
    publisher = RedisPublisher(settings, metrics)
    await publisher.connect()

    # ------------------------------------------------------------------
    # 6. Worker pool
    # ------------------------------------------------------------------
    worker_pool = WorkerPool(
        queue=queue,
        publisher=publisher,
        metrics=metrics,
        worker_count=settings.worker_count,
    )

    # ------------------------------------------------------------------
    # 7. Health / metrics HTTP server
    # ------------------------------------------------------------------
    health_server = HealthServer(
        queue=queue,
        metrics=metrics,
        host="0.0.0.0",
        port=settings.metrics_port,
    )

    # ------------------------------------------------------------------
    # 8. UDP listener
    # ------------------------------------------------------------------
    udp_listener = UDPListener(
        queue=queue,
        metrics=metrics,
        settings=settings,
    )

    # ------------------------------------------------------------------
    # 9. Graceful shutdown plumbing
    # ------------------------------------------------------------------
    shutdown_event = asyncio.Event()

    def _request_shutdown(signame: str) -> None:
        log.info("Shutdown signal received", signal=signame)
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(
                sig,
                _request_shutdown,
                sig.name,
            )
        except NotImplementedError:
            # Windows does not support add_signal_handler for all signals;
            # fall back to signal.signal so Ctrl-C still works.
            signal.signal(sig, lambda s, f: _request_shutdown(signal.Signals(s).name))

    # ------------------------------------------------------------------
    # Start all components
    # ------------------------------------------------------------------
    await worker_pool.start()
    await health_server.start()
    await udp_listener.start()

    log.info(
        "syslog-ingestion service ready",
        listen=f"{settings.listen_host}:{settings.listen_port}",
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

    # Step 1: stop accepting new UDP packets
    await udp_listener.stop()

    # Step 2: drain the queue — publish everything already buffered
    await worker_pool.stop()

    # Step 3: stop the HTTP server
    await health_server.stop()

    # Step 4: release Redis connections
    await publisher.close()

    log.info("syslog-ingestion service stopped cleanly")


def main() -> None:
    """Synchronous entry point called by ``python -m src.main``."""
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass  # SIGINT handled inside _run; suppress the traceback


if __name__ == "__main__":
    main()
