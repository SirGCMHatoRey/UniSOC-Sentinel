"""OpenSearch bulk indexer with ILM policy and ECS-compatible index templates."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from opensearchpy import AsyncOpenSearch, helpers as os_helpers
from opensearchpy.exceptions import RequestError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Index template name and ILM policy name
# ---------------------------------------------------------------------------
_TEMPLATE_NAME = "siem-logs-template"
_ILM_POLICY_NAME = "siem-logs-ilm"
_INDEX_PATTERN = "siem-logs-*"

# ---------------------------------------------------------------------------
# ILM policy: hot 7d, warm 30d, delete 90d
# ---------------------------------------------------------------------------
_ILM_POLICY = {
    "policy": {
        "description": "SIEM logs lifecycle: hot 7d, warm 30d, delete 90d",
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {
                    "rollover": {
                        "max_age": "7d",
                        "max_size": "50gb",
                    },
                    "set_priority": {"priority": 100},
                },
            },
            "warm": {
                "min_age": "7d",
                "actions": {
                    "readonly": {},
                    "set_priority": {"priority": 50},
                },
            },
            "delete": {
                "min_age": "90d",
                "actions": {"delete": {}},
            },
        },
    }
}

# ---------------------------------------------------------------------------
# ECS-compatible index template
# ---------------------------------------------------------------------------
_INDEX_TEMPLATE = {
    "index_patterns": [_INDEX_PATTERN],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 1,
            "index.lifecycle.name": _ILM_POLICY_NAME,
            "index.mapping.total_fields.limit": 2000,
        },
        "mappings": {
            "dynamic_templates": [
                {
                    "strings_as_keyword": {
                        "match_mapping_type": "string",
                        "unmatch": "*_text",
                        "mapping": {"type": "keyword", "ignore_above": 1024},
                    }
                },
                {
                    "long_text_fields": {
                        "match": "*_text",
                        "mapping": {"type": "text"},
                    }
                },
            ],
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "kind": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "dataset": {"type": "keyword"},
                        "severity": {"type": "short"},
                        "outcome": {"type": "keyword"},
                    }
                },
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
                                "score": {"type": "short"},
                            }
                        },
                    }
                },
                "destination": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "integer"},
                    }
                },
                "network": {
                    "properties": {
                        "protocol": {"type": "keyword"},
                        "direction": {"type": "keyword"},
                        "bytes": {"type": "long"},
                        "packets": {"type": "long"},
                    }
                },
                "host": {
                    "properties": {
                        "hostname": {"type": "keyword"},
                        "ip": {"type": "ip"},
                    }
                },
                "user": {
                    "properties": {
                        "name": {"type": "keyword"},
                    }
                },
                "observer": {
                    "properties": {
                        "type": {"type": "keyword"},
                        "name": {"type": "keyword"},
                        "vendor": {"type": "keyword"},
                        "hostname": {"type": "keyword"},
                        "mac_vendor": {"type": "keyword"},
                    }
                },
                "tags": {"type": "keyword"},
                "labels": {"type": "object", "dynamic": True},
                "message": {"type": "text"},
                "raw_message": {"type": "text", "index": False},
            },
        },
    },
    "priority": 100,
    "composed_of": [],
}


def _daily_index(timestamp_str: str) -> str:
    """Compute index name from an @timestamp string, e.g. 'siem-logs-2024.01.01'."""
    try:
        # Handle both "Z" and "+00:00" suffixes
        ts = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
    except (ValueError, AttributeError):
        dt = datetime.now(timezone.utc)
    return f"siem-logs-{dt.strftime('%Y.%m.%d')}"


class OpenSearchIndexer:
    """
    Wraps the async OpenSearch client to:
    - Set up ILM policy and index template on startup.
    - Bulk-index ECS events.
    - Compute daily index names from @timestamp.
    """

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify_certs: bool = False,
    ) -> None:
        self._client = AsyncOpenSearch(
            hosts=[url],
            http_auth=(username, password),
            use_ssl=url.startswith("https"),
            verify_certs=verify_certs,
            ssl_show_warn=False,
            timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )
        self._created_indices: set[str] = set()

    async def initialize(self) -> None:
        """Create ILM policy and index template. Called once on startup."""
        await self._ensure_ilm_policy()
        await self._ensure_index_template()
        logger.info("OpenSearch indexer initialized")

    async def _ensure_ilm_policy(self) -> None:
        try:
            resp = await self._client.transport.perform_request(
                "GET", f"/_plugins/_ism/policies/{_ILM_POLICY_NAME}"
            )
            logger.debug("ILM policy '%s' already exists", _ILM_POLICY_NAME)
        except Exception:
            try:
                await self._client.transport.perform_request(
                    "PUT",
                    f"/_plugins/_ism/policies/{_ILM_POLICY_NAME}",
                    body=_ILM_POLICY,
                )
                logger.info("Created ILM/ISM policy '%s'", _ILM_POLICY_NAME)
            except Exception as exc:
                logger.warning("Could not create ILM policy (may not be supported): %s", exc)

    async def _ensure_index_template(self) -> None:
        try:
            await self._client.indices.put_index_template(
                name=_TEMPLATE_NAME,
                body=_INDEX_TEMPLATE,
            )
            logger.info("Index template '%s' applied", _TEMPLATE_NAME)
        except Exception as exc:
            logger.warning("Could not apply index template: %s", exc)

    async def create_index_if_needed(self, index_name: str) -> None:
        """Create the given index if it does not exist yet (idempotent)."""
        if index_name in self._created_indices:
            return
        try:
            exists = await self._client.indices.exists(index=index_name)
            if not exists:
                await self._client.indices.create(index=index_name)
                logger.info("Created OpenSearch index: %s", index_name)
        except RequestError as exc:
            if "resource_already_exists_exception" in str(exc).lower():
                pass  # race condition — another worker created it
            else:
                logger.warning("Error creating index %s: %s", index_name, exc)
        except Exception as exc:
            logger.warning("Error creating index %s: %s", index_name, exc)
        finally:
            self._created_indices.add(index_name)

    async def bulk_index(self, events: list[dict[str, Any]]) -> tuple[int, int]:
        """
        Bulk-index a list of ECS event dicts.

        Returns (success_count, failed_count).
        """
        if not events:
            return 0, 0

        # Group by daily index; ensure each index exists
        index_names: set[str] = set()
        actions = []
        for event in events:
            index = _daily_index(event.get("@timestamp", ""))
            index_names.add(index)
            actions.append({
                "_index": index,
                "_source": event,
            })

        # Ensure indices exist (creates them if the template didn't auto-create)
        for idx in index_names:
            await self.create_index_if_needed(idx)

        try:
            success, errors = await os_helpers.async_bulk(
                self._client,
                actions,
                raise_on_error=False,
                raise_on_exception=False,
                chunk_size=500,
                max_chunk_bytes=10 * 1024 * 1024,  # 10 MB
            )
            failed = len(errors) if isinstance(errors, list) else 0
            if failed:
                logger.warning("Bulk index had %d failures", failed)
                for err in errors[:5]:
                    logger.debug("Bulk error sample: %s", err)
            return success, failed
        except Exception as exc:
            logger.error("Bulk index request failed: %s", exc)
            return 0, len(events)

    async def close(self) -> None:
        await self._client.close()
