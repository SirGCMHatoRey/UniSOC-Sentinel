"""
WebSocket live-stream endpoint.

GET /ws/live

Authentication is via:
  • Query parameter ?token=<JWT>
  • Sec-WebSocket-Protocol header containing the JWT

Messages from Redis pub/sub channel "siem:live_stream" are forwarded to all
connected clients. A ping frame is sent every 30 seconds to detect dead connections.
"""

from __future__ import annotations

import asyncio
import json

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy import select

from src.config import settings
from src.database import AsyncSessionLocal
from src.models.user import User
from src.websocket.manager import ws_manager

log = structlog.get_logger(__name__)
router = APIRouter(tags=["websocket"])

_PING_INTERVAL = 30  # seconds


async def _authenticate_ws(token: str | None) -> bool:
    """
    Validate a JWT token for WebSocket authentication.
    Returns True if valid and user is active, False otherwise.
    """
    if token is None:
        return False
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        user_id = payload.get("sub")
        token_type = payload.get("type", "access")
        if user_id is None or token_type != "access":
            return False

        if AsyncSessionLocal is None:
            return False

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(User).where(User.id == user_id, User.is_active.is_(True))
            )
            user = result.scalar_one_or_none()
            return user is not None
    except JWTError:
        return False


@router.websocket("/ws/live")
async def websocket_live(
    websocket: WebSocket,
    token: str | None = Query(None, description="JWT access token"),
) -> None:
    """
    Live event stream WebSocket endpoint.

    Clients connect and receive real-time ECS events and alerts as they arrive
    via Redis pub/sub. Authentication is required.
    """
    # --- Authenticate ---
    # Try query param first, then Sec-WebSocket-Protocol header
    auth_token = token
    if auth_token is None:
        proto_header = websocket.headers.get("Sec-WebSocket-Protocol", "")
        if proto_header:
            auth_token = proto_header.split(",")[0].strip()

    if not await _authenticate_ws(auth_token):
        await websocket.close(code=4001, reason="Unauthorized")
        log.warning("WebSocket auth failed — closing connection")
        return

    # --- Connect ---
    await ws_manager.connect(websocket)

    # --- Start ping task to detect dead connections ---
    async def _ping_loop() -> None:
        while True:
            await asyncio.sleep(_PING_INTERVAL)
            try:
                await websocket.send_json({"type": "ping"})
            except Exception:
                break

    ping_task = asyncio.create_task(_ping_loop())

    try:
        # Keep the connection alive — wait for client disconnect
        while True:
            try:
                # Receive and discard any client messages (e.g. pong)
                await asyncio.wait_for(websocket.receive_text(), timeout=_PING_INTERVAL + 5)
            except asyncio.TimeoutError:
                # No message received in time — ping will detect dead conn
                pass
    except WebSocketDisconnect:
        log.debug("WebSocket client disconnected cleanly")
    except Exception as exc:
        log.warning("WebSocket error", error=str(exc))
    finally:
        ping_task.cancel()
        ws_manager.disconnect(websocket)


async def redis_to_websocket_bridge(redis, manager: "ConnectionManager") -> None:
    """
    Long-running async task that subscribes to the Redis pub/sub channel
    "siem:live_stream" and forwards every message to all WebSocket clients.

    Runs as a background task in the app lifespan.
    """
    log.info("Redis→WebSocket bridge starting", channel="siem:live_stream")

    while True:
        pubsub = None
        try:
            pubsub = redis.pubsub()
            await pubsub.subscribe("siem:live_stream")

            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                data = message.get("data", b"")
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                try:
                    payload = json.loads(data)
                except json.JSONDecodeError:
                    payload = {"type": "raw", "data": data}

                if manager.connection_count > 0:
                    await manager.broadcast(payload)

        except asyncio.CancelledError:
            log.info("Redis→WebSocket bridge cancelled")
            break
        except Exception as exc:
            log.error(
                "Redis→WebSocket bridge error — reconnecting in 5s",
                error=str(exc),
            )
            await asyncio.sleep(5)
        finally:
            if pubsub is not None:
                try:
                    await pubsub.unsubscribe("siem:live_stream")
                    await pubsub.close()
                except Exception:
                    pass
