"""
HTTP health and metrics server for the alerting-engine service.

Endpoints:
    GET /health  — JSON liveness/readiness payload for Docker/k8s probes.
    GET /metrics — Prometheus text exposition format.

Built on aiohttp for non-blocking I/O that integrates cleanly with the
main asyncio event loop.
"""

from __future__ import annotations

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
        metrics: The Metrics instance — counters are snapshotted for /health.
        host:    Interface to bind (default 0.0.0.0).
        port:    TCP port to listen on (default 8083).
    """

    def __init__(
        self,
        metrics: Metrics,
        host: str = "0.0.0.0",
        port: int = 8083,
    ) -> None:
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

        Reports uptime and key counter snapshots so orchestrators and humans
        can quickly assess service state.
        """
        uptime_seconds = time.monotonic() - self._start_time

        def _counter_value(counter) -> int:
            try:
                return int(counter._value.get())  # type: ignore[attr-defined]
            except AttributeError:
                return 0

        payload: dict[str, Any] = {
            "status": "ok",
            "uptime_seconds": round(uptime_seconds, 2),
            "events_consumed": _counter_value(self._metrics.events_consumed_total),
        }
        return web.json_response(payload)

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """Return Prometheus text-format metrics."""
        output = generate_latest()
        return web.Response(body=output, content_type=CONTENT_TYPE_LATEST)
