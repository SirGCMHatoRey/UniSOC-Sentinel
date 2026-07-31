"""
OpenSearch ILM policy and index template bootstrap.

Called once during application startup. Idempotent — safe to call on every restart.
"""

from __future__ import annotations

import structlog
from opensearchpy import AsyncOpenSearch

log = structlog.get_logger(__name__)

_ILM_POLICY_NAME = "siem-logs-policy"
_INDEX_TEMPLATE_NAME = "siem-logs-template"
_INDEX_PATTERN = "siem-logs-*"


_ILM_POLICY = {
    "policy": {
        "description": "UniSOC Sentinel log lifecycle: hot 7d → warm 30d → delete 90d",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": {
                    "rollover": {
                        "min_index_age": "7d",
                    }
                },
                "transitions": [{"state_name": "warm", "conditions": {"min_index_age": "7d"}}],
            },
            {
                "name": "warm",
                "actions": {
                    "read_only": {},
                    "shrink": {"num_shards": 1},
                    "forcemerge": {"max_num_segments": 1},
                },
                "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "30d"}}],
            },
            {
                "name": "delete",
                "actions": {"delete": {}},
                "transitions": [],
            },
        ],
        "ism_template": [
            {
                "index_patterns": [_INDEX_PATTERN],
                "priority": 100,
            }
        ],
    }
}


_INDEX_TEMPLATE = {
    "index_patterns": [_INDEX_PATTERN],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "5s",
        },
        "mappings": {
            "dynamic_templates": [
                {
                    "ip_fields": {
                        "path_match": "*.ip",
                        "mapping": {"type": "ip"},
                    }
                },
                {
                    "keyword_fields": {
                        "path_match": "*.keyword",
                        "mapping": {"type": "keyword"},
                    }
                },
            ],
            "properties": {
                # Top-level timestamp
                "@timestamp": {"type": "date"},
                # Event fields
                "event": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "kind": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "dataset": {"type": "keyword"},
                        "severity": {"type": "integer"},
                        "outcome": {"type": "keyword"},
                    }
                },
                # Source fields
                "source": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "integer"},
                        "mac": {"type": "keyword"},
                        "geo": {
                            "properties": {
                                "country_iso_code": {"type": "keyword"},
                                "country_name": {"type": "keyword"},
                                "city_name": {"type": "keyword"},
                                "location": {"type": "geo_point"},
                            }
                        },
                        "threat_intel": {
                            "properties": {
                                "matched": {"type": "boolean"},
                                "feed": {"type": "keyword"},
                                "score": {"type": "integer"},
                            }
                        },
                    }
                },
                # Destination fields
                "destination": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "integer"},
                    }
                },
                # Network fields
                "network": {
                    "properties": {
                        "protocol": {"type": "keyword"},
                        "direction": {"type": "keyword"},
                        "bytes": {"type": "long"},
                        "packets": {"type": "long"},
                    }
                },
                # Host fields
                "host": {
                    "properties": {
                        "hostname": {"type": "keyword"},
                        "ip": {"type": "ip"},
                    }
                },
                # User fields
                "user": {
                    "properties": {
                        "name": {"type": "keyword"},
                    }
                },
                # Observer fields
                "observer": {
                    "properties": {
                        "type": {"type": "keyword"},
                        "name": {"type": "keyword"},
                        "vendor": {"type": "keyword"},
                    }
                },
                # Free-form fields
                "tags": {"type": "keyword"},
                "labels": {"type": "object", "dynamic": True},
                "message": {"type": "text"},
                "raw_message": {"type": "text", "index": False},
            }
        },
    },
}


async def setup_opensearch(client: AsyncOpenSearch) -> None:
    """
    Create the ILM policy and index template if they do not already exist.
    Logs progress but never raises — startup should continue even if OpenSearch
    is temporarily unreachable.
    """
    try:
        await _ensure_ilm_policy(client)
    except Exception as exc:
        log.warning("Failed to create ILM policy — continuing", error=str(exc))

    try:
        await _ensure_index_template(client)
    except Exception as exc:
        log.warning("Failed to create index template — continuing", error=str(exc))


async def _ensure_ilm_policy(client: AsyncOpenSearch) -> None:
    """Create the ISM / ILM policy if it does not exist."""
    try:
        existing = await client.transport.perform_request(
            "GET",
            f"/_plugins/_ism/policies/{_ILM_POLICY_NAME}",
        )
        log.debug("ILM policy already exists", policy=_ILM_POLICY_NAME)
        return
    except Exception:
        pass  # 404 → create it

    await client.transport.perform_request(
        "PUT",
        f"/_plugins/_ism/policies/{_ILM_POLICY_NAME}",
        body=_ILM_POLICY,
    )
    log.info("ILM policy created", policy=_ILM_POLICY_NAME)


async def _ensure_index_template(client: AsyncOpenSearch) -> None:
    """Create the composable index template if it does not exist."""
    exists = await client.indices.exists_index_template(name=_INDEX_TEMPLATE_NAME)
    if exists:
        log.debug("Index template already exists", template=_INDEX_TEMPLATE_NAME)
        return

    await client.indices.put_index_template(
        name=_INDEX_TEMPLATE_NAME,
        body=_INDEX_TEMPLATE,
    )
    log.info("Index template created", template=_INDEX_TEMPLATE_NAME)
