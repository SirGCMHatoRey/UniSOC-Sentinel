"""
WebSocket connection manager.

Maintains the set of active WebSocket connections and broadcasts messages
to all of them, silently removing any that have disconnected.
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from fastapi import WebSocket
from starlette.websockets import WebSocketState

log = structlog.get_logger(__name__)


class ConnectionManager:
    """Thread-safe (asyncio-safe) manager for WebSocket connections."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        """Accept the WebSocket handshake and register the connection."""
        await ws.accept()
        self._connections.add(ws)
        log.info(
            "WebSocket client connected",
            total_connections=len(self._connections),
        )

    def disconnect(self, ws: WebSocket) -> None:
        """Remove a WebSocket from the active set (idempotent)."""
        self._connections.discard(ws)
        log.info(
            "WebSocket client disconnected",
            total_connections=len(self._connections),
        )

    async def broadcast(self, message: dict[str, Any]) -> None:
        """
        Send a JSON-serialised message to all connected clients.

        Dead connections are silently removed.
        """
        if not self._connections:
            return

        data = json.dumps(message)
        dead: set[WebSocket] = set()

        for ws in list(self._connections):
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_text(data)
                else:
                    dead.add(ws)
            except Exception as exc:
                log.debug("WebSocket send failed — removing connection", error=str(exc))
                dead.add(ws)

        for ws in dead:
            self._connections.discard(ws)

    @property
    def connection_count(self) -> int:
        """Return the current number of active connections."""
        return len(self._connections)


# Module-level singleton used by the WebSocket router and lifespan
ws_manager = ConnectionManager()
