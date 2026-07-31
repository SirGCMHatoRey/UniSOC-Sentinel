"""
UniSOC Sentinel SIEM Core — FastAPI application entry point.

Startup order:
  1. Configure structlog
  2. Initialise PostgreSQL (create tables)
  3. Connect to Redis
  4. Connect to OpenSearch (create ILM policy + index template)
  5. Start correlation engine background task
  6. Start Redis→WebSocket bridge background task

Shutdown (reverse):
  1. Cancel correlation engine task
  2. Cancel WebSocket bridge task
  3. Close Redis connection
  4. Close OpenSearch connection
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis

from src.api.middleware.audit import AuditMiddleware
from src.api.middleware.rate_limit import RateLimitMiddleware
from src.api.middleware.security_headers import SecurityHeadersMiddleware
from src.api.router import api_router
from src.api.routes.health import router as health_router
from src.config import settings
from src.correlation.engine import CorrelationEngine
from src.database import AsyncSessionLocal, init_db
from src.metrics import setup_metrics
from src.search.client import create_opensearch_client
from src.search.index_template import setup_opensearch
from src.websocket.manager import ws_manager
from src.websocket.router import redis_to_websocket_bridge
from src.websocket.router import router as ws_router


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _configure_logging(log_level: str) -> None:
    """Configure structlog with JSON renderer at the given log level."""
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

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )
    # Quieten verbose third-party loggers
    for noisy in ("redis", "aiohttp", "asyncpg", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Redis client factory
# ---------------------------------------------------------------------------


async def _create_redis_client(url: str) -> Redis:
    """Create and verify a Redis async client."""
    client = Redis.from_url(
        url,
        encoding="utf-8",
        decode_responses=False,  # keep bytes for pub/sub compatibility
        socket_connect_timeout=5,
        socket_timeout=5,
        health_check_interval=30,
    )
    await client.ping()
    return client


# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage startup and shutdown of all background resources."""
    _configure_logging(settings.log_level)
    log = structlog.get_logger(__name__)

    log.info(
        "siem-core starting",
        version="1.0.0",
        log_level=settings.log_level,
        postgres_host=settings.postgres_host,
        redis_host=settings.redis_host,
        opensearch_url=settings.opensearch_url,
    )

    # ------------------------------------------------------------------
    # 1. PostgreSQL
    # ------------------------------------------------------------------
    log.info("Initialising PostgreSQL connection")
    await init_db(settings.db_url)
    log.info("PostgreSQL ready")

    # Expose the session factory on app.state so middleware can use it
    app.state.db_factory = AsyncSessionLocal

    # ------------------------------------------------------------------
    # 2. Redis
    # ------------------------------------------------------------------
    log.info("Connecting to Redis")
    redis_client = await _create_redis_client(settings.redis_url)
    app.state.redis = redis_client
    log.info("Redis connected")

    # ------------------------------------------------------------------
    # 3. OpenSearch
    # ------------------------------------------------------------------
    log.info("Connecting to OpenSearch")
    opensearch_client = create_opensearch_client(settings)
    app.state.opensearch = opensearch_client
    await setup_opensearch(opensearch_client)
    log.info("OpenSearch ready")

    # ------------------------------------------------------------------
    # 4. Correlation engine
    # ------------------------------------------------------------------
    log.info("Starting correlation engine")
    correlation_engine = CorrelationEngine(
        redis=redis_client,
        db_session_factory=AsyncSessionLocal,
        settings=settings,
    )
    engine_task = asyncio.create_task(correlation_engine.run(), name="correlation_engine")

    # ------------------------------------------------------------------
    # 5. Redis→WebSocket bridge
    # ------------------------------------------------------------------
    log.info("Starting Redis→WebSocket bridge")
    ws_bridge_task = asyncio.create_task(
        redis_to_websocket_bridge(redis_client, ws_manager),
        name="ws_bridge",
    )

    log.info("siem-core startup complete")

    # ------------------------------------------------------------------
    # Yield — application runs here
    # ------------------------------------------------------------------
    yield

    # ------------------------------------------------------------------
    # Shutdown (reverse order)
    # ------------------------------------------------------------------
    log.info("siem-core shutting down")

    engine_task.cancel()
    ws_bridge_task.cancel()

    try:
        await asyncio.gather(engine_task, ws_bridge_task, return_exceptions=True)
    except Exception:
        pass

    try:
        await opensearch_client.close()
    except Exception:
        pass

    try:
        await redis_client.aclose()
    except Exception:
        pass

    log.info("siem-core stopped cleanly")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------


app = FastAPI(
    title="UniSOC Sentinel API",
    description="Central SIEM backend for the UniSOC Sentinel platform.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ------------------------------------------------------------------
# Middleware (applied in reverse registration order by Starlette)
# ------------------------------------------------------------------

# CORS — outermost so preflight requests are handled before auth
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers on all responses
app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting on /api/ endpoints
app.add_middleware(RateLimitMiddleware)

# Audit logging for mutating requests
app.add_middleware(AuditMiddleware)

# ------------------------------------------------------------------
# Prometheus metrics
# ------------------------------------------------------------------
setup_metrics(app)

# ------------------------------------------------------------------
# Routers
# ------------------------------------------------------------------

# Health endpoint (no auth, no rate limit prefix issue)
app.include_router(health_router)

# Versioned API routes
app.include_router(api_router)

# WebSocket live stream
app.include_router(ws_router)
