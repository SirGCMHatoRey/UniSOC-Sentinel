"""SQLAlchemy ORM model for the sessions table (refresh tokens)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # SHA-256 hex digest of the raw refresh token
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # jti (JWT ID) of the access token that was issued alongside this refresh token
    jti: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Relationship (lazy=noload to avoid implicit IO in async context)
    user: Mapped["User"] = relationship(  # noqa: F821
        "User",
        lazy="noload",
        foreign_keys=[user_id],
    )

    def __repr__(self) -> str:
        return f"<Session id={self.id!r} user_id={self.user_id!r} revoked={self.is_revoked}>"
