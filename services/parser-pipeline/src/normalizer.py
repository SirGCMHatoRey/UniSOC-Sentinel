"""ECS normalizer — converts ParsedEvent + enrichments into a full ECS dict."""
from __future__ import annotations

import uuid
from typing import Optional

from .parsers.base import ParsedEvent


def to_ecs(
    parsed: ParsedEvent,
    geo: Optional[dict] = None,
    threat: Optional[dict] = None,
    mac_vendor: Optional[str] = None,
) -> dict:
    """
    Build a full ECS-compatible event dict from a ParsedEvent and optional
    enrichment results.

    Parameters
    ----------
    parsed:     The structured event produced by a parser.
    geo:        GeoIP enrichment dict with country/city/location keys, or None.
    threat:     Threat intelligence enrichment dict, or None.
    mac_vendor: Human-readable OUI vendor string, or None.

    Returns
    -------
    dict: ECS event ready for bulk indexing into OpenSearch.
    """
    ts_str = _format_timestamp(parsed.timestamp)

    return {
        "@timestamp": ts_str,
        "event": {
            "id": str(uuid.uuid4()),
            "kind": parsed.event_kind,
            "category": parsed.event_category,
            "type": parsed.event_type,
            "dataset": parsed.dataset,
            "severity": parsed.event_severity,
            "outcome": parsed.event_outcome,
        },
        "source": {
            "ip": parsed.source_ip,
            "port": parsed.source_port,
            "mac": parsed.source_mac,
            "geo": geo or {},
            "threat_intel": threat or {
                "matched": False,
                "feed": None,
                "score": 0,
            },
        },
        "destination": {
            "ip": parsed.dest_ip,
            "port": parsed.dest_port,
        },
        "network": {
            "protocol": parsed.network_protocol,
            "direction": parsed.network_direction,
            "bytes": parsed.network_bytes,
            "packets": parsed.network_packets,
        },
        "host": {
            "hostname": parsed.hostname,
            "ip": [],
        },
        "user": {
            "name": parsed.username,
        },
        "observer": {
            "type": parsed.observer_type,
            "name": "unifi",
            "vendor": "Ubiquiti",
            "hostname": parsed.hostname,
            "mac_vendor": mac_vendor,
        },
        "tags": parsed.tags,
        "labels": parsed.labels,
        "message": parsed.message,
        "raw_message": parsed.raw_message,
    }


def _format_timestamp(ts) -> str:
    """Format a datetime as ISO-8601 with millisecond precision and Z suffix."""
    # Produce "2024-01-01T00:00:00.000Z"
    iso = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")  # has microseconds
    return iso[:-3] + "Z"                        # truncate to milliseconds
