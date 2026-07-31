"""
Main API router — mounts all sub-routers under their respective prefixes.
"""

from __future__ import annotations

from fastapi import APIRouter

from src.api.routes.alerts import router as alerts_router
from src.api.routes.api_keys import router as api_keys_router
from src.api.routes.auth import router as auth_router
from src.api.routes.dashboard import router as dashboard_router
from src.api.routes.logs import router as logs_router
from src.api.routes.users import router as users_router

# Versioned API prefix
_V1 = "/api/v1"

api_router = APIRouter()

# Auth endpoints
api_router.include_router(auth_router, prefix=_V1)

# Resource endpoints
api_router.include_router(logs_router, prefix=_V1)
api_router.include_router(alerts_router, prefix=_V1)
api_router.include_router(dashboard_router, prefix=_V1)
api_router.include_router(users_router, prefix=_V1)
api_router.include_router(api_keys_router, prefix=_V1)
