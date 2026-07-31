"""
Redis-backed per-IP rate limiting middleware.

Limit: 100 requests per minute for paths matching /api/.
Returns HTTP 429 with Retry-After header when the limit is exceeded.
"""

from __future__ import annotations

import time

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

log = structlog.get_logger(__name__)

_RATE_LIMIT = 100          # requests per window
_WINDOW_SECONDS = 60       # sliding window size
_PREFIX = "ratelimit:"     # Redis key prefix


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, honouring X-Forwarded-For if set."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware that enforces 100 req/min per IP on /api/ routes.

    Uses Redis INCR + EXPIRE for a fixed-window counter approach.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Only rate-limit API paths
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        redis = getattr(request.app.state, "redis", None)
        if redis is None:
            # Redis not yet available (startup race) — let through
            return await call_next(request)

        client_ip = _get_client_ip(request)
        # Use a per-minute bucket so the window resets cleanly
        minute_bucket = int(time.time()) // _WINDOW_SECONDS
        key = f"{_PREFIX}{client_ip}:{minute_bucket}"

        try:
            count = await redis.incr(key)
            if count == 1:
                # Set TTL only on first increment (avoid overwriting TTL on later hits)
                await redis.expire(key, _WINDOW_SECONDS * 2)

            if count > _RATE_LIMIT:
                retry_after = _WINDOW_SECONDS - (int(time.time()) % _WINDOW_SECONDS)
                log.warning(
                    "Rate limit exceeded",
                    ip=client_ip,
                    count=count,
                    path=request.url.path,
                )
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too Many Requests — rate limit exceeded"},
                    headers={"Retry-After": str(retry_after)},
                )
        except Exception as exc:
            # Never let rate-limit failures block legitimate traffic
            log.error("Rate limit Redis error", error=str(exc))

        return await call_next(request)
