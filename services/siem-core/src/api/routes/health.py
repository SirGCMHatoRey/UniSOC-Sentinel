"""
Health and metrics routes.

GET /health   — service liveness check
GET /metrics  — Prometheus metrics (instrumented by prometheus-fastapi-instrumentator)
"""

from __future__ import annotations

import time

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])

# Module-level start time for uptime calculation
_START_TIME = time.monotonic()

_VERSION = "1.0.0"


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime: float  # seconds since startup


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Return a simple liveness response. Always returns 200 if the app is up."""
    return HealthResponse(
        status="ok",
        version=_VERSION,
        uptime=round(time.monotonic() - _START_TIME, 2),
    )
