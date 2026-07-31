"""
HTTP health and metrics server for the syslog-ingestion service.

Endpoints:
    GET /health  — JSON liveness/readiness payload for Docker/k8s probes.
    GET /metrics — Prometheus text exposition format.

Built on aiohttp for non-blocking I/O that integrates cleanly with the
main asyncio event loop.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog
from aiohttp import web
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .metrics import Metrics

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class HealthServer:
    """
    Lightweight aiohttp HTTP server exposing /health and /metrics.

    Args:
        queue:   The shared asyncio.Queue so /health can report queue_size.
        metrics: The Metrics instance for counter snapshots in /health.
        host:    Interface to bind (default 0.0.0.0).
        port:    TCP port to listen on (default 8081).
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        metrics: Metrics,
        host: str = "0.0.0.0",
        port: int = 8081,
    ) -> None:
        self._queue = queue
        self._metrics = metrics
        self._host = host
        self._port = port
        self._start_time = time.monotonic()
        self._runner: web.AppRunner | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Build the aiohttp app, create the runner, and start listening."""
        app = web.Application()
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/metrics", self._handle_metrics)

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()

        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()

        log.info(
            "Health/metrics server started",
            host=self._host,
            port=self._port,
        )

    async def stop(self) -> None:
        """Shut down the aiohttp runner gracefully."""
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            log.info("Health/metrics server stopped")

    # ------------------------------------------------------------------
    # Request handlers
    # ------------------------------------------------------------------

    async def _handle_health(self, request: web.Request) -> web.Response:
        """
        Return a JSON health payload.

        Snapshot counter values are read from the underlying prometheus_client
        Collector objects; this avoids storing duplicated state.
        """
        uptime_seconds = time.monotonic() - self._start_time

        # Read current counter values from prometheus_client internal state.
        # Each Counter exposes ._value.get() which returns the float total.
        try:
            packets_received = int(
                self._metrics.packets_received_total._value.get()  # type: ignore[attr-defined]
            )
        except AttributeError:
            packets_received = 0

        try:
            packets_dropped = int(
                self._metrics.packets_dropped_total._value.get()  # type: ignore[attr-defined]
            )
        except AttributeError:
            packets_dropped = 0

        payload: dict[str, Any] = {
            "status": "ok",
            "queue_size": self._queue.qsize(),
            "uptime_seconds": round(uptime_seconds, 2),
            "packets_received": packets_received,
            "packets_dropped": packets_dropped,
        }

        return web.json_response(payload)

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """Return Prometheus text-format metrics."""
        output = generate_latest()
        return web.Response(
            body=output,
            content_type=CONTENT_TYPE_LATEST,
        )
