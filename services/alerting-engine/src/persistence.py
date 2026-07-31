"""
PostgreSQL persistence layer for triggered alerts.

Each alert that passes deduplication and throttling is written to the
``alerts`` table so it can be queried via the SIEM API and retained for
audit purposes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# ORM model
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Declarative base for alerting-engine ORM models."""


class Alert(Base):
    """
    ORM representation of a triggered alert row.

    Columns mirror the shared interface contract alert message format so the
    same JSON fields that are published to Redis can be stored directly.
    """

    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id = Column(String(128), nullable=False, index=True)
    rule_name = Column(String(256), nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    event_count = Column(Integer, nullable=False, default=1)
    metadata_ = Column("metadata", JSONB, nullable=True)


# ---------------------------------------------------------------------------
# Persistence class
# ---------------------------------------------------------------------------


class AlertPersistence:
    """
    Writes triggered alerts to the PostgreSQL ``alerts`` table.

    A single shared async engine and session factory are created at
    initialisation time.  The schema (table) is created on first startup
    if it does not already exist.

    Args:
        db_url: Full asyncpg SQLAlchemy connection URL.
    """

    def __init__(self, db_url: str) -> None:
        self._engine = create_async_engine(
            db_url,
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            pool_pre_ping=True,
        )
        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    async def init_schema(self) -> None:
        """
        Create the alerts table if it does not already exist.

        Safe to call on every service startup (idempotent).
        """
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        log.info("Database schema initialised")

    async def save(self, alert: dict) -> None:
        """
        Persist a single alert dict to the database.

        The dict is expected to follow the shared interface contract:
            id, rule_id, rule_name, severity, title, description,
            created_at, event_count, metadata

        Args:
            alert: Alert dict as returned by RuleEvaluator.evaluate().

        Raises:
            sqlalchemy.exc.SQLAlchemyError: On database errors.
        """
        async with self._session_factory() as session:
            row = Alert(
                id=uuid.UUID(alert["id"]),
                rule_id=alert["rule_id"],
                rule_name=alert["rule_name"],
                severity=alert["severity"],
                title=alert["title"],
                description=alert["description"],
                created_at=datetime.fromisoformat(
                    alert["created_at"].replace("Z", "+00:00")
                ),
                event_count=alert.get("event_count", 1),
                metadata_=alert.get("metadata"),
            )
            session.add(row)
            await session.commit()

        log.debug(
            "Alert persisted",
            alert_id=alert["id"],
            rule_id=alert["rule_id"],
        )

    async def close(self) -> None:
        """Dispose of the database connection pool."""
        await self._engine.dispose()
        log.info("Database connection pool closed")
