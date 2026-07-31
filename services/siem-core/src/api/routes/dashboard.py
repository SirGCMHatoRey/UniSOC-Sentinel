"""
Dashboard routes — aggregate statistics from OpenSearch + PostgreSQL.

All endpoints accept optional from_ts / to_ts (default: last 24 hours).
All require viewer role or above.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db, require_role
from src.models.alert import Alert
from src.models.user import User
from src.search.queries import (
    build_geo_map_query,
    build_timeseries_query,
    build_top_ips_query,
)

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_VIEWER_DEP = Depends(require_role("viewer", "analyst", "admin"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_ts(ts: str | None, default_offset_hours: int = 0) -> str:
    """
    Parse an ISO8601 timestamp string or return a default datetime string.
    Positive offset_hours = N hours in the past.
    """
    if ts is not None:
        return ts
    dt = datetime.now(timezone.utc) - timedelta(hours=default_offset_hours)
    return dt.isoformat().replace("+00:00", "Z")


async def _opensearch_search(
    opensearch,
    query: dict,
    index: str = "siem-logs-*",
) -> dict:
    """Execute an OpenSearch query, returning empty hits on failure."""
    try:
        return await opensearch.search(
            index=index,
            body=query,
            ignore_unavailable=True,
        )
    except Exception as exc:
        log.error("OpenSearch query failed", error=str(exc))
        return {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/stats")
async def dashboard_stats(
    request: Request,
    from_ts: str | None = Query(None),
    to_ts: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _user: User = _VIEWER_DEP,
) -> dict:
    """
    Return summary counters:
    total_events, total_alerts, blocked_connections,
    auth_failures, active_vpn_sessions, threat_intel_matches.
    """
    _from = _parse_ts(from_ts, default_offset_hours=24)
    _to = _parse_ts(to_ts)
    opensearch = request.app.state.opensearch

    # Total events in time range
    total_events_resp = await _opensearch_search(
        opensearch,
        {
            "query": {"range": {"@timestamp": {"gte": _from, "lte": _to}}},
            "size": 0,
        },
    )
    total_events = (
        total_events_resp.get("hits", {}).get("total", {}).get("value", 0)
    )

    # Blocked connections (firewall deny)
    blocked_resp = await _opensearch_search(
        opensearch,
        {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": _from, "lte": _to}}},
                        {"term": {"event.outcome": "failure"}},
                        {"term": {"event.dataset": "unifi.firewall"}},
                    ]
                }
            },
            "size": 0,
        },
    )
    blocked_connections = (
        blocked_resp.get("hits", {}).get("total", {}).get("value", 0)
    )

    # Auth failures
    auth_fail_resp = await _opensearch_search(
        opensearch,
        {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": _from, "lte": _to}}},
                        {"term": {"event.outcome": "failure"}},
                        {"terms": {"event.category": ["authentication"]}},
                    ]
                }
            },
            "size": 0,
        },
    )
    auth_failures = (
        auth_fail_resp.get("hits", {}).get("total", {}).get("value", 0)
    )

    # Active VPN sessions
    vpn_resp = await _opensearch_search(
        opensearch,
        {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": _from, "lte": _to}}},
                        {"term": {"event.dataset": "unifi.vpn"}},
                        {"term": {"event.type": "start"}},
                    ]
                }
            },
            "size": 0,
        },
    )
    active_vpn_sessions = (
        vpn_resp.get("hits", {}).get("total", {}).get("value", 0)
    )

    # Threat intel matches
    threat_resp = await _opensearch_search(
        opensearch,
        {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": _from, "lte": _to}}},
                        {"term": {"source.threat_intel.matched": True}},
                    ]
                }
            },
            "size": 0,
        },
    )
    threat_intel_matches = (
        threat_resp.get("hits", {}).get("total", {}).get("value", 0)
    )

    # Total alerts from PostgreSQL
    try:
        from_dt = datetime.fromisoformat(_from.replace("Z", "+00:00"))
    except ValueError:
        from_dt = datetime.now(timezone.utc) - timedelta(hours=24)
    alert_count = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.created_at >= from_dt
        )
    )
    total_alerts = alert_count.scalar_one()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "blocked_connections": blocked_connections,
        "auth_failures": auth_failures,
        "active_vpn_sessions": active_vpn_sessions,
        "threat_intel_matches": threat_intel_matches,
    }


@router.get("/top-ips")
async def top_ips(
    request: Request,
    from_ts: str | None = Query(None),
    to_ts: str | None = Query(None),
    _user: User = _VIEWER_DEP,
) -> list[dict]:
    """Return top 10 source IPs by event count with country information."""
    _from = _parse_ts(from_ts, default_offset_hours=24)
    _to = _parse_ts(to_ts)
    opensearch = request.app.state.opensearch

    query = build_top_ips_query(_from, _to)
    response = await _opensearch_search(opensearch, query)

    buckets = (
        response.get("aggregations", {})
        .get("top_ips", {})
        .get("buckets", [])
    )

    results = []
    for bucket in buckets[:10]:
        country = (
            bucket.get("top_country", {})
            .get("hits", {})
            .get("hits", [{}])[0]
            .get("_source", {})
            .get("source", {})
            .get("geo", {})
            .get("country_name", "Unknown")
        )
        results.append(
            {
                "source_ip": bucket.get("key"),
                "event_count": bucket.get("doc_count", 0),
                "country": country,
            }
        )
    return results


@router.get("/firewall-activity")
async def firewall_activity(
    request: Request,
    from_ts: str | None = Query(None),
    to_ts: str | None = Query(None),
    _user: User = _VIEWER_DEP,
) -> list[dict]:
    """Return hourly time-series of firewall allow/deny counts."""
    _from = _parse_ts(from_ts, default_offset_hours=24)
    _to = _parse_ts(to_ts)
    opensearch = request.app.state.opensearch

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": _from, "lte": _to}}},
                    {"term": {"event.dataset": "unifi.firewall"}},
                ]
            }
        },
        "size": 0,
        "aggs": {
            "by_hour": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1h",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": _from, "max": _to},
                },
                "aggs": {
                    "allowed": {
                        "filter": {"term": {"event.outcome": "success"}}
                    },
                    "denied": {
                        "filter": {"term": {"event.outcome": "failure"}}
                    },
                },
            }
        },
    }

    response = await _opensearch_search(opensearch, query)
    buckets = (
        response.get("aggregations", {}).get("by_hour", {}).get("buckets", [])
    )

    return [
        {
            "timestamp": b.get("key_as_string"),
            "allowed": b.get("allowed", {}).get("doc_count", 0),
            "denied": b.get("denied", {}).get("doc_count", 0),
        }
        for b in buckets
    ]


@router.get("/geo-map")
async def geo_map(
    request: Request,
    from_ts: str | None = Query(None),
    to_ts: str | None = Query(None),
    _user: User = _VIEWER_DEP,
) -> list[dict]:
    """Return geo coordinates and event counts for map visualisation."""
    _from = _parse_ts(from_ts, default_offset_hours=24)
    _to = _parse_ts(to_ts)
    opensearch = request.app.state.opensearch

    query = build_geo_map_query(_from, _to)
    response = await _opensearch_search(opensearch, query)

    buckets = (
        response.get("aggregations", {})
        .get("by_country", {})
        .get("buckets", [])
    )

    results = []
    for bucket in buckets:
        top_hits = (
            bucket.get("geo_sample", {})
            .get("hits", {})
            .get("hits", [{}])
        )
        if top_hits:
            geo = (
                top_hits[0]
                .get("_source", {})
                .get("source", {})
                .get("geo", {})
            )
            location = geo.get("location", {})
            results.append(
                {
                    "country": geo.get("country_name", "Unknown"),
                    "country_iso_code": bucket.get("key"),
                    "lat": location.get("lat"),
                    "lon": location.get("lon"),
                    "count": bucket.get("doc_count", 0),
                }
            )
    return results


@router.get("/bandwidth")
async def bandwidth(
    request: Request,
    from_ts: str | None = Query(None),
    to_ts: str | None = Query(None),
    _user: User = _VIEWER_DEP,
) -> list[dict]:
    """Return hourly time-series of network.bytes totals."""
    _from = _parse_ts(from_ts, default_offset_hours=24)
    _to = _parse_ts(to_ts)
    opensearch = request.app.state.opensearch

    query = build_timeseries_query("network.bytes", "1h", _from, _to)
    response = await _opensearch_search(opensearch, query)

    buckets = (
        response.get("aggregations", {}).get("by_time", {}).get("buckets", [])
    )
    return [
        {
            "timestamp": b.get("key_as_string"),
            "bytes": b.get("sum_field", {}).get("value", 0) or 0,
        }
        for b in buckets
    ]


@router.get("/vpn-sessions")
async def vpn_sessions(
    request: Request,
    from_ts: str | None = Query(None),
    to_ts: str | None = Query(None),
    _user: User = _VIEWER_DEP,
) -> list[dict]:
    """Return recent VPN session events from unifi.vpn dataset."""
    _from = _parse_ts(from_ts, default_offset_hours=24)
    _to = _parse_ts(to_ts)
    opensearch = request.app.state.opensearch

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": _from, "lte": _to}}},
                    {"term": {"event.dataset": "unifi.vpn"}},
                ]
            }
        },
        "size": 100,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }

    response = await _opensearch_search(opensearch, query)
    hits = response.get("hits", {}).get("hits", [])
    return [h.get("_source", {}) for h in hits]


@router.get("/wireless-activity")
async def wireless_activity(
    request: Request,
    from_ts: str | None = Query(None),
    to_ts: str | None = Query(None),
    _user: User = _VIEWER_DEP,
) -> list[dict]:
    """Return wireless client association events grouped by SSID."""
    _from = _parse_ts(from_ts, default_offset_hours=24)
    _to = _parse_ts(to_ts)
    opensearch = request.app.state.opensearch

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": _from, "lte": _to}}},
                    {"term": {"event.dataset": "unifi.wireless"}},
                ]
            }
        },
        "size": 0,
        "aggs": {
            "by_ssid": {
                "terms": {"field": "labels.ssid", "size": 20},
                "aggs": {
                    "by_event_type": {
                        "terms": {"field": "event.type", "size": 5}
                    }
                },
            }
        },
    }

    response = await _opensearch_search(opensearch, query)
    buckets = (
        response.get("aggregations", {}).get("by_ssid", {}).get("buckets", [])
    )

    return [
        {
            "ssid": b.get("key"),
            "event_count": b.get("doc_count", 0),
            "by_type": {
                t["key"]: t["doc_count"]
                for t in b.get("by_event_type", {}).get("buckets", [])
            },
        }
        for b in buckets
    ]


@router.get("/threat-intel-matches")
async def threat_intel_matches(
    request: Request,
    from_ts: str | None = Query(None),
    to_ts: str | None = Query(None),
    size: int = Query(50, ge=1, le=200),
    _user: User = _VIEWER_DEP,
) -> list[dict]:
    """Return the most recent events with source.threat_intel.matched=true."""
    _from = _parse_ts(from_ts, default_offset_hours=24)
    _to = _parse_ts(to_ts)
    opensearch = request.app.state.opensearch

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": _from, "lte": _to}}},
                    {"term": {"source.threat_intel.matched": True}},
                ]
            }
        },
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }

    response = await _opensearch_search(opensearch, query)
    hits = response.get("hits", {}).get("hits", [])
    return [h.get("_source", {}) for h in hits]


@router.get("/system-health")
async def system_health(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user: User = _VIEWER_DEP,
) -> dict:
    """
    Return health summary for all backend services:
    opensearch, redis, postgres, pipeline stats.
    """
    opensearch = request.app.state.opensearch
    redis = request.app.state.redis

    # OpenSearch health
    os_status = "unknown"
    os_docs_count = 0
    try:
        health = await opensearch.cluster.health()
        os_status = health.get("status", "unknown")
        count_resp = await opensearch.count(index="siem-logs-*", ignore_unavailable=True)
        os_docs_count = count_resp.get("count", 0)
    except Exception as exc:
        log.warning("OpenSearch health check failed", error=str(exc))
        os_status = "unavailable"

    # Redis health
    redis_connected = False
    redis_memory_used = "unknown"
    try:
        await redis.ping()
        redis_connected = True
        info = await redis.info("memory")
        redis_memory_used = info.get("used_memory_human", "unknown")
    except Exception as exc:
        log.warning("Redis health check failed", error=str(exc))

    # PostgreSQL health
    pg_connected = False
    try:
        await db.execute(select(func.now()))
        pg_connected = True
    except Exception as exc:
        log.warning("PostgreSQL health check failed", error=str(exc))

    # Pipeline events per minute (from Redis sorted set or key)
    events_per_minute = 0
    try:
        epm = await redis.get("metrics:events_per_minute")
        if epm:
            events_per_minute = int(epm)
    except Exception:
        pass

    return {
        "opensearch": {"status": os_status, "docs_count": os_docs_count},
        "redis": {"connected": redis_connected, "memory_used": redis_memory_used},
        "postgres": {"connected": pg_connected},
        "pipeline": {"events_per_minute": events_per_minute},
    }
