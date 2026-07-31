"""Health and metrics HTTP server for the parser-pipeline service."""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from aiohttp import web
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

logger = logging.getLogger(__name__)


class HealthServer:
    """
    Minimal aiohttp server exposing:
      GET /health   → 200 {"status": "ok"} or 503 {"status": "degraded"}
      GET /metrics  → Prometheus text exposition
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8082) -> None:
        self._host = host
        self._port = port
        self._app = web.Application()
        self._runner: Optional[web.AppRunner] = None
        self._ready = False

        self._app.router.add_get("/health", self._handle_health)
        self._app.router.add_get("/metrics", self._handle_metrics)
        self._app.router.add_get("/ready", self._handle_ready)

    def set_ready(self, ready: bool = True) -> None:
        """Signal that the service is ready to receive traffic."""
        self._ready = ready

    async def start(self) -> None:
        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()
        logger.info("Health server listening on %s:%d", self._host, self._port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Liveness probe — always 200 if the process is running."""
        return web.json_response(
            {"status": "ok", "service": "parser-pipeline"},
            status=200,
        )

    async def _handle_ready(self, request: web.Request) -> web.Response:
        """Readiness probe — 200 once all workers + enrichers are initialized."""
        if self._ready:
            return web.json_response({"status": "ready"}, status=200)
        return web.json_response({"status": "starting"}, status=503)

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """Prometheus metrics endpoint."""
        data = generate_latest()
        return web.Response(
            body=data,
            content_type=CONTENT_TYPE_LATEST,
        )
