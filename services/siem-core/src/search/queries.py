"""
OpenSearch query builder functions.

All builders return plain dicts suitable for passing directly to the
AsyncOpenSearch client's search() / count() methods.
"""

from __future__ import annotations

from typing import Any


def build_log_query(
    q: str | None,
    dataset: str | None,
    severity_min: int | None,
    from_ts: str | None,
    to_ts: str | None,
    source_ip: str | None,
    page: int,
    size: int,
) -> dict[str, Any]:
    """
    Build a paginated ECS log search query.

    Combines full-text search, field filters, and a time range filter.
    Results are sorted by @timestamp descending.
    """
    must: list[dict] = []
    filter_clauses: list[dict] = []

    # Time range
    time_range: dict[str, Any] = {}
    if from_ts:
        time_range["gte"] = from_ts
    if to_ts:
        time_range["lte"] = to_ts
    if time_range:
        filter_clauses.append({"range": {"@timestamp": time_range}})

    # Full-text search
    if q:
        must.append({
            "multi_match": {
                "query": q,
                "fields": ["message", "raw_message", "source.ip", "host.hostname"],
                "type": "best_fields",
            }
        })

    # Dataset filter
    if dataset:
        filter_clauses.append({"term": {"event.dataset": dataset}})

    # Severity minimum
    if severity_min is not None:
        filter_clauses.append({"range": {"event.severity": {"gte": severity_min}}})

    # Source IP filter
    if source_ip:
        filter_clauses.append({"term": {"source.ip": source_ip}})

    bool_query: dict[str, Any] = {}
    if must:
        bool_query["must"] = must
    if filter_clauses:
        bool_query["filter"] = filter_clauses

    query: dict[str, Any] = {
        "query": {"bool": bool_query} if bool_query else {"match_all": {}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "from": (page - 1) * size,
        "size": size,
    }

    return query


def build_top_ips_query(from_ts: str, to_ts: str) -> dict[str, Any]:
    """
    Build an aggregation query returning the top 10 source IPs by event count,
    with a top_hits sub-aggregation to retrieve country info.
    """
    return {
        "query": {
            "range": {"@timestamp": {"gte": from_ts, "lte": to_ts}}
        },
        "size": 0,
        "aggs": {
            "top_ips": {
                "terms": {
                    "field": "source.ip",
                    "size": 10,
                    "order": {"_count": "desc"},
                },
                "aggs": {
                    "top_country": {
                        "top_hits": {
                            "size": 1,
                            "_source": {
                                "includes": [
                                    "source.geo.country_name",
                                    "source.geo.country_iso_code",
                                ]
                            },
                        }
                    }
                },
            }
        },
    }


def build_timeseries_query(
    field: str,
    interval: str,
    from_ts: str,
    to_ts: str,
) -> dict[str, Any]:
    """
    Build a date-histogram aggregation query with an optional sum sub-agg.

    If `field` is not @timestamp, a sum aggregation named "sum_field" is
    added inside each bucket.

    Args:
        field:    The numeric field to sum per bucket (e.g. "network.bytes").
        interval: Calendar interval string (e.g. "1h", "1d").
        from_ts:  Lower bound ISO8601 string.
        to_ts:    Upper bound ISO8601 string.
    """
    aggs: dict[str, Any] = {
        "by_time": {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": interval,
                "min_doc_count": 0,
                "extended_bounds": {"min": from_ts, "max": to_ts},
            }
        }
    }

    if field != "@timestamp":
        aggs["by_time"]["aggs"] = {  # type: ignore[index]
            "sum_field": {"sum": {"field": field}}
        }

    return {
        "query": {
            "range": {"@timestamp": {"gte": from_ts, "lte": to_ts}}
        },
        "size": 0,
        "aggs": aggs,
    }


def build_geo_map_query(from_ts: str, to_ts: str) -> dict[str, Any]:
    """
    Build a query that aggregates source IPs by country and samples geo coordinates.
    """
    return {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": from_ts, "lte": to_ts}}},
                    {"exists": {"field": "source.geo.location"}},
                ]
            }
        },
        "size": 0,
        "aggs": {
            "by_country": {
                "terms": {
                    "field": "source.geo.country_iso_code",
                    "size": 200,
                    "order": {"_count": "desc"},
                },
                "aggs": {
                    "geo_sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": {
                                "includes": [
                                    "source.geo.country_name",
                                    "source.geo.location",
                                ]
                            },
                        }
                    }
                },
            }
        },
    }
