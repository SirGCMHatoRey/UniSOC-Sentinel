"""
PostgreSQL persistence layer for triggered alerts.

Each alert that passes deduplication and throttling is written to the
``alerts`` table so it can be queried via the SIEM API and retained for
audit purposes.

Schema ownership: siem-core owns the ``alerts`` table — its declarative
model (``services/siem-core/src/models/alert.py``) is the single source of
truth, and only siem-core runs ``create_all`` for it at startup. This module
does NOT declare a competing ORM model or create/alter the table; it
describes, via a plain SQLAlchemy Core ``Table``, only the columns it needs
to write to, and inserts through that. Two independent schema owners
racing on table creation (and silently diverging on columns) was the bug
this design fixes — see issue #6.
"""

from __future__ import annotations

from datetime import datetime

import structlog
from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, Text, insert, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Table reference (write-only — not a schema-owning model)
# ---------------------------------------------------------------------------

# Column names, types, and widths mirror siem-core's Alert model exactly
# (services/siem-core/src/models/alert.py) so an insert here always matches
# whatever siem-core actually created. This is deliberately a Core `Table`,
# not a `DeclarativeBase` subclass — it has no `create_all` capability and
# cannot become a second schema owner.
_metadata = MetaData()

alerts_table = Table(
    "alerts",
    _metadata,
    Column("id", String(36), primary_key=True),
    Column("rule_id", String(64), nullable=False),
    Column("rule_name", String(128), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("title", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("event_count", Integer, nullable=False),
    Column("metadata", JSONB, nullable=True),
)


# ---------------------------------------------------------------------------
# Persistence class
# ---------------------------------------------------------------------------


class AlertPersistence:
    """
    Writes triggered alerts to the PostgreSQL ``alerts`` table.

    A single shared async engine and session factory are created at
    initialisation time. This service does not create or alter the table —
    see the module docstring; ``init_schema`` only verifies connectivity.

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
        Verify the database is reachable.

        Does NOT create or alter the ``alerts`` table — siem-core owns that
        schema. If siem-core hasn't created it yet, inserts will fail (and
        are already caught/logged per-alert by the caller) until it has;
        this service does not race to create it itself.
        """
        async with self._engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        log.info("Database connectivity verified (schema owned by siem-core)")

    async def save(self, alert: dict) -> None:
        """
        Persist a single alert dict to the database.

        The dict is expected to follow the shared interface contract:
            id, rule_id, rule_name, severity, title, description,
            created_at, event_count, metadata

        Args:
            alert: Alert dict as returned by RuleEvaluator.evaluate().

        Raises:
            sqlalchemy.exc.SQLAlchemyError: On database errors (including if
                siem-core has not yet created the alerts table).
        """
        async with self._session_factory() as session:
            await session.execute(
                insert(alerts_table).values(
                    id=alert["id"],
                    rule_id=alert["rule_id"],
                    rule_name=alert["rule_name"],
                    severity=alert["severity"],
                    title=alert["title"],
                    description=alert["description"],
                    created_at=datetime.fromisoformat(
                        alert["created_at"].replace("Z", "+00:00")
                    ),
                    event_count=alert.get("event_count", 1),
                    metadata=alert.get("metadata"),
                )
            )
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
