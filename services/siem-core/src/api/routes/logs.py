"""
Log retrieval routes — queries OpenSearch.

GET /api/v1/logs          — paginated event search
GET /api/v1/logs/{id}     — single event by event.id
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel

from src.api.deps import get_current_user, require_role
from src.models.user import User
from src.search.queries import build_log_query

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/logs", tags=["logs"])


class LogsResponse(BaseModel):
    total: int
    page: int
    size: int
    hits: list[dict]


@router.get("", response_model=LogsResponse)
async def list_logs(
    request: Request,
    q: str | None = Query(None, description="Full-text search query"),
    dataset: str | None = Query(None, description="Filter by event.dataset"),
    severity_min: int | None = Query(None, ge=1, le=10, description="Minimum severity"),
    from_ts: str | None = Query(None, description="Start timestamp ISO8601"),
    to_ts: str | None = Query(None, description="End timestamp ISO8601"),
    source_ip: str | None = Query(None, description="Filter by source.ip"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    size: int = Query(50, ge=1, le=200, description="Results per page"),
    _user: User = Depends(require_role("viewer", "analyst", "admin")),
) -> LogsResponse:
    """
    Search ECS events stored in OpenSearch.

    Supports full-text search, dataset filter, severity threshold,
    time-range filter, source IP filter, and pagination.
    """
    opensearch = request.app.state.opensearch
    query = build_log_query(
        q=q,
        dataset=dataset,
        severity_min=severity_min,
        from_ts=from_ts,
        to_ts=to_ts,
        source_ip=source_ip,
        page=page,
        size=size,
    )

    from datetime import datetime, timedelta, timezone

    index_pattern = _resolve_index_pattern(from_ts, to_ts)

    try:
        response = await opensearch.search(
            index=index_pattern,
            body=query,
            ignore_unavailable=True,
        )
    except Exception as exc:
        log.error("OpenSearch query failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Search backend unavailable",
        )

    hits_raw = response.get("hits", {})
    total_value = hits_raw.get("total", {})
    if isinstance(total_value, dict):
        total = total_value.get("value", 0)
    else:
        total = int(total_value)

    hits = [h.get("_source", {}) for h in hits_raw.get("hits", [])]
    return LogsResponse(total=total, page=page, size=size, hits=hits)


@router.get("/{event_id}", response_model=dict)
async def get_log(
    event_id: str,
    request: Request,
    _user: User = Depends(require_role("viewer", "analyst", "admin")),
) -> dict:
    """Retrieve a single ECS event by its event.id field."""
    opensearch = request.app.state.opensearch

    query = {
        "query": {"term": {"event.id": event_id}},
        "size": 1,
    }

    try:
        response = await opensearch.search(
            index="siem-logs-*",
            body=query,
            ignore_unavailable=True,
        )
    except Exception as exc:
        log.error("OpenSearch get_log failed", event_id=event_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Search backend unavailable",
        )

    hits = response.get("hits", {}).get("hits", [])
    if not hits:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found",
        )

    return hits[0].get("_source", {})


def _resolve_index_pattern(from_ts: str | None, to_ts: str | None) -> str:
    """
    Return an OpenSearch index pattern covering the requested date range.
    Falls back to a wildcard when no time bounds are given.
    """
    from datetime import datetime, timedelta, timezone
    import re

    if from_ts is None and to_ts is None:
        return "siem-logs-*"

    try:
        if from_ts:
            start = datetime.fromisoformat(from_ts.replace("Z", "+00:00"))
        else:
            start = datetime.now(timezone.utc) - timedelta(days=1)

        if to_ts:
            end = datetime.fromisoformat(to_ts.replace("Z", "+00:00"))
        else:
            end = datetime.now(timezone.utc)

        # Build comma-separated index list if range spans multiple days
        indices = set()
        current = start
        while current <= end:
            indices.add(f"siem-logs-{current.strftime('%Y.%m.%d')}")
            current += timedelta(days=1)
        return ",".join(sorted(indices)) if indices else "siem-logs-*"
    except Exception:
        return "siem-logs-*"
