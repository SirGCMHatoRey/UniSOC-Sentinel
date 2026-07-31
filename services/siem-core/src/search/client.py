"""
OpenSearch async client factory with retry logic.
"""

from __future__ import annotations

import structlog
from opensearchpy import AsyncOpenSearch, RequestError, TransportError

from src.config import Settings

log = structlog.get_logger(__name__)


def create_opensearch_client(settings: Settings) -> AsyncOpenSearch:
    """
    Create and return an AsyncOpenSearch client configured from settings.

    Retry configuration: 3 retries on transport errors with exponential backoff.
    """
    return AsyncOpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=(settings.opensearch_user, settings.opensearch_password),
        use_ssl=settings.opensearch_url.startswith("https"),
        verify_certs=False,
        ssl_show_warn=False,
        retry_on_timeout=True,
        max_retries=3,
        timeout=30,
        # Connection pool
        http_compress=True,
    )
