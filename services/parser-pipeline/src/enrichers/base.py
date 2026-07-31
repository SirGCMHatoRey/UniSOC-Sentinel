"""Abstract base class for enrichers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseEnricher(ABC):
    """
    An enricher accepts a value (IP address, MAC, user-agent string, etc.)
    and returns an enrichment dict, or None if enrichment is not available.
    """

    @abstractmethod
    async def enrich(self, value: str) -> Optional[dict[str, Any]]:
        """
        Enrich the given value.

        Parameters
        ----------
        value: The input to enrich (IP, MAC, user-agent string, …).

        Returns
        -------
        dict with enrichment data, or None if unavailable.
        Never raises — return None on any error.
        """
        ...

    async def close(self) -> None:
        """Optional cleanup. Override if the enricher holds resources."""
