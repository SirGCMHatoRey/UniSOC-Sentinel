"""
Audit logging middleware.

Logs all state-changing requests (POST, PATCH, DELETE, PUT) to the
audit_log table, capturing: user identity, HTTP method, path, status
code, IP address, and user-agent.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from fastapi import Request, Response
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from src.config import settings

log = structlog.get_logger(__name__)

_AUDITED_METHODS = {"POST", "PATCH", "DELETE", "PUT"}


def _get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _extract_user_from_request(request: Request) -> tuple[str | None, str | None]:
    """
    Try to extract user_id and username from the JWT without raising.
    Returns (user_id, username) or (None, None) on failure.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None
    token = auth[7:]
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        return payload.get("sub"), payload.get("username")
    except JWTError:
        return None, None


def _derive_action(method: str, path: str) -> str:
    """Derive a human-readable action string from HTTP method + path."""
    parts = [p for p in path.strip("/").split("/") if p]
    resource = parts[-1] if parts else "unknown"
    mapping = {
        "POST": "create",
        "PATCH": "update",
        "PUT": "update",
        "DELETE": "delete",
    }
    verb = mapping.get(method, method.lower())
    return f"{verb}:{resource}"


class AuditMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware that persists audit records for mutating HTTP requests.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        if request.method not in _AUDITED_METHODS:
            return await call_next(request)

        # Capture caller identity before processing (token may be valid even
        # if the route returns an error)
        user_id, username = _extract_user_from_request(request)

        response = await call_next(request)

        # Fire-and-forget DB write — must not affect response latency
        try:
            db_factory = getattr(request.app.state, "db_factory", None)
            if db_factory is not None:
                await _write_audit_record(
                    db_factory=db_factory,
                    user_id=user_id,
                    username=username,
                    method=request.method,
                    path=request.url.path,
                    status_code=response.status_code,
                    ip_address=_get_client_ip(request),
                    user_agent=request.headers.get("User-Agent"),
                )
        except Exception as exc:
            log.error("Audit log write failed", error=str(exc))

        return response


async def _write_audit_record(
    *,
    db_factory,
    user_id: str | None,
    username: str | None,
    method: str,
    path: str,
    status_code: int,
    ip_address: str | None,
    user_agent: str | None,
) -> None:
    """Insert a single audit_log row."""
    from src.models.audit import AuditLog

    record = AuditLog(
        id=str(uuid.uuid4()),
        user_id=user_id,
        username=username,
        action=_derive_action(method, path),
        method=method,
        path=path,
        status_code=status_code,
        ip_address=ip_address,
        user_agent=user_agent,
        created_at=datetime.now(timezone.utc),
    )
    async with db_factory() as session:
        session.add(record)
        await session.commit()
