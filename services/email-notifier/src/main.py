"""
Entry point for the email-notifier service.

Start-up order:
  1. Load Settings (env / secret files)
  2. Configure structlog with JSON renderer at the configured log level
  3. Create Prometheus Metrics instance
  4. Connect async Redis client
  5. Initialise EmailRenderer (Jinja2 templates)
  6. Initialise EmailSender (async SMTP)
  7. Start AlertSubscriber (Redis pub/sub)
  8. Start HealthServer (HTTP /health + /metrics on METRICS_PORT)
  9. Block until SIGTERM or SIGINT

Shutdown order (reverse of start-up):
  1. Stop AlertSubscriber — no new alerts processed
  2. Stop HealthServer    — HTTP server no longer needed
  3. Close Redis client   — release connection pool
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

import structlog
from redis.asyncio import Redis

from .config import Settings
from .health import HealthServer
from .metrics import Metrics
from .renderer import EmailRenderer
from .sender import EmailSender
from .subscriber import AlertSubscriber


def _configure_logging(log_level: str) -> None:
    """
    Configure structlog to emit JSON-formatted log records.

    The standard library root logger is also configured at the same level
    so that third-party libraries (redis, aiohttp, aiosmtplib) produce
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
    logging.getLogger("aiosmtplib").setLevel(logging.WARNING)


def _resolve_template_dir() -> str:
    """
    Locate the templates directory relative to this module's location.

    Returns the absolute path to src/templates/ so it works both in
    the Docker container and in local development.
    """
    here = Path(__file__).parent
    template_dir = here / "templates"
    if not template_dir.is_dir():
        raise RuntimeError(f"Template directory not found: {template_dir}")
    return str(template_dir)


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
        "email-notifier service starting",
        redis_host=settings.redis_host,
        redis_port=settings.redis_port,
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_from=settings.smtp_from,
        smtp_starttls=settings.smtp_starttls,
        recipient_count=len(settings.recipients_list),
        metrics_port=settings.metrics_port,
        log_level=settings.log_level,
    )

    if not settings.recipients_list:
        log.warning(
            "ALERT_RECIPIENTS is not configured; alert emails will be discarded"
        )

    # ------------------------------------------------------------------
    # 3. Prometheus metrics
    # ------------------------------------------------------------------
    metrics = Metrics()

    # ------------------------------------------------------------------
    # 4. Redis client
    # ------------------------------------------------------------------
    redis = Redis.from_url(
        settings.redis_url,
        decode_responses=False,
        max_connections=10,
    )
    log.info("Redis client created", url=settings.redis_url.split("@")[-1])

    # ------------------------------------------------------------------
    # 5. Jinja2 template renderer
    # ------------------------------------------------------------------
    template_dir = _resolve_template_dir()
    renderer = EmailRenderer(template_dir=template_dir)
    log.info("Email renderer initialised", template_dir=template_dir)

    # ------------------------------------------------------------------
    # 6. SMTP sender
    # ------------------------------------------------------------------
    sender = EmailSender(config=settings, metrics=metrics)

    # ------------------------------------------------------------------
    # 7. Pub/sub subscriber
    # ------------------------------------------------------------------
    subscriber = AlertSubscriber(
        redis=redis,
        renderer=renderer,
        sender=sender,
        recipients=settings.recipients_list,
        metrics=metrics,
    )

    # ------------------------------------------------------------------
    # 8. Health / metrics HTTP server
    # ------------------------------------------------------------------
    health_server = HealthServer(
        metrics=metrics,
        host="0.0.0.0",
        port=settings.metrics_port,
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
            loop.add_signal_handler(sig, _request_shutdown, sig.name)
        except NotImplementedError:
            signal.signal(sig, lambda s, f: _request_shutdown(signal.Signals(s).name))

    # ------------------------------------------------------------------
    # Start all components
    # ------------------------------------------------------------------
    await health_server.start()
    await subscriber.start()

    log.info(
        "email-notifier service ready",
        metrics=f"http://0.0.0.0:{settings.metrics_port}",
        channel="siem:alert_notifications",
    )

    # ------------------------------------------------------------------
    # Block until shutdown is requested
    # ------------------------------------------------------------------
    await shutdown_event.wait()

    # ------------------------------------------------------------------
    # Graceful shutdown (reverse order)
    # ------------------------------------------------------------------
    log.info("Beginning graceful shutdown sequence")

    await subscriber.stop()
    await health_server.stop()
    await redis.aclose()

    log.info("email-notifier service stopped cleanly")


def main() -> None:
    """Synchronous entry point called by ``python -m src.main``."""
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass  # SIGINT handled inside _run; suppress the traceback


if __name__ == "__main__":
    main()
