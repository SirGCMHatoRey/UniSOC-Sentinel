"""
SQLAlchemy async engine and session factory for the siem-core service.
"""

from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


engine = None
AsyncSessionLocal: async_sessionmaker | None = None


async def init_db(database_url: str) -> None:
    """
    Create the async SQLAlchemy engine and session factory, then ensure all
    tables exist (idempotent — safe to call on every startup).

    Args:
        database_url: Full asyncpg SQLAlchemy connection URL.
    """
    global engine, AsyncSessionLocal

    engine = create_async_engine(
        database_url,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_pre_ping=True,
    )
    AsyncSessionLocal = async_sessionmaker(
        engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )

    # Import models so Base.metadata is populated before create_all
    from src.models import (  # noqa: F401
        User, Session, APIKey, Alert, AuditLog,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an AsyncSession and closes it when done.
    """
    if AsyncSessionLocal is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    async with AsyncSessionLocal() as session:
        yield session
