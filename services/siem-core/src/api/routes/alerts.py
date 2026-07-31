"""
Alert routes — queries PostgreSQL alerts table.

GET   /api/v1/alerts                      — paginated alerts list
GET   /api/v1/alerts/{id}                 — single alert
PATCH /api/v1/alerts/{id}/acknowledge     — acknowledge alert (analyst+)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db, get_current_user, require_role
from src.models.alert import Alert
from src.models.user import User

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class AlertResponse(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str | None
    created_at: datetime
    acknowledged: bool
    acknowledged_by: str | None
    acknowledged_at: datetime | None
    event_count: int
    metadata: dict | None

    model_config = {"from_attributes": True}


class AlertsListResponse(BaseModel):
    total: int
    page: int
    size: int
    items: list[AlertResponse]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=AlertsListResponse)
async def list_alerts(
    severity: str | None = Query(None, description="Filter by severity"),
    acknowledged: bool | None = Query(None, description="Filter by acknowledged state"),
    from_ts: str | None = Query(None, description="Start timestamp ISO8601"),
    to_ts: str | None = Query(None, description="End timestamp ISO8601"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_role("viewer", "analyst", "admin")),
) -> AlertsListResponse:
    """Return paginated alerts from PostgreSQL with optional filters."""
    conditions = []

    if severity is not None:
        conditions.append(Alert.severity == severity)
    if acknowledged is not None:
        conditions.append(Alert.acknowledged.is_(acknowledged))
    if from_ts is not None:
        try:
            dt = datetime.fromisoformat(from_ts.replace("Z", "+00:00"))
            conditions.append(Alert.created_at >= dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid from_ts format")
    if to_ts is not None:
        try:
            dt = datetime.fromisoformat(to_ts.replace("Z", "+00:00"))
            conditions.append(Alert.created_at <= dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid to_ts format")

    where_clause = and_(*conditions) if conditions else True

    # Count total
    from sqlalchemy import func, select as sa_select
    count_result = await db.execute(
        sa_select(func.count()).select_from(Alert).where(where_clause)
    )
    total = count_result.scalar_one()

    # Fetch page
    offset = (page - 1) * size
    result = await db.execute(
        select(Alert)
        .where(where_clause)
        .order_by(Alert.created_at.desc())
        .offset(offset)
        .limit(size)
    )
    alerts = result.scalars().all()

    return AlertsListResponse(
        total=total,
        page=page,
        size=size,
        items=[AlertResponse.model_validate(a) for a in alerts],
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_role("viewer", "analyst", "admin")),
) -> AlertResponse:
    """Return a single alert by ID or 404."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found",
        )
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin")),
) -> AlertResponse:
    """
    Mark an alert as acknowledged.

    Sets acknowledged=true, acknowledged_by=current_user.id,
    acknowledged_at=now(). Requires analyst or admin role.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found",
        )

    if alert.acknowledged:
        # Idempotent — return as-is
        return AlertResponse.model_validate(alert)

    alert.acknowledged = True
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(alert)

    log.info(
        "Alert acknowledged",
        alert_id=alert_id,
        acknowledged_by=current_user.username,
    )
    return AlertResponse.model_validate(alert)
