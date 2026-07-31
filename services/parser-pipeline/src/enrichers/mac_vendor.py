"""MAC address OUI vendor enricher."""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
from typing import Any, Optional

import aiohttp

from .base import BaseEnricher

logger = logging.getLogger(__name__)

# Minimal built-in OUI table for the most common UniFi/networking vendors.
# Format: first 3 octets uppercase no-separator -> vendor string.
_BUILTIN_OUI: dict[str, str] = {
    # Ubiquiti
    "0418D6": "Ubiquiti Networks",
    "246895": "Ubiquiti Networks",
    "44D9E7": "Ubiquiti Networks",
    "687289": "Ubiquiti Networks",
    "785125": "Ubiquiti Networks",
    "802AA8": "Ubiquiti Networks",
    "DC9FDB": "Ubiquiti Networks",
    "F09FC2": "Ubiquiti Networks",
    # Apple
    "000000": "Xerox",  # placeholder
    "001451": "Apple",
    "0016CB": "Apple",
    "001E52": "Apple",
    "001F5B": "Apple",
    "0021E9": "Apple",
    "0023DF": "Apple",
    "002500": "Apple",
    "0026B9": "Apple",
    "0026BB": "Apple",
    "689C70": "Apple",
    "8C2937": "Apple",
    "A8BE27": "Apple",
    "F0B479": "Apple",
    # Raspberry Pi
    "B827EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    # Intel
    "001B21": "Intel",
    "001CC0": "Intel",
    "0021D8": "Intel",
    # Samsung
    "001632": "Samsung Electronics",
    "0021D1": "Samsung Electronics",
    "002339": "Samsung Electronics",
    # Google / Nest
    "F4F5DB": "Google",
    "64:16:66": "Google",
    "A4:77:33": "Google",
    # Amazon
    "AC:63:BE": "Amazon Technologies",
    "40:B4:CD": "Amazon Technologies",
    # Cisco
    "001120": "Cisco Systems",
    "0012DA": "Cisco Systems",
    "001301": "Cisco Systems",
    # TP-Link
    "64:70:02": "TP-Link Technologies",
    "6C:B0:CE": "TP-Link Technologies",
    "14:CC:20": "TP-Link Technologies",
    # Netgear
    "08:BD:43": "Netgear",
    "9C:D3:6D": "Netgear",
    "C4:04:15": "Netgear",
}

# Remote OUI JSON database URL
_OUI_DB_URL = "https://maclookup.app/downloads/json-database"
_CACHE_LIMIT = 50_000  # cap in-memory cache to avoid unbounded growth


def _normalize_oui(mac: str) -> str:
    """Extract first 3 octets from a MAC and return uppercase no-separator form."""
    clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    return clean[:6]


class MACVendorEnricher(BaseEnricher):
    """
    Looks up MAC vendor by OUI prefix.

    - Ships with a small built-in table for common vendors.
    - Optionally downloads and caches the full IEEE OUI JSON database.
    - All lookups are O(1) dict lookups.
    """

    def __init__(self, download_oui: bool = False) -> None:
        self._oui_table: dict[str, str] = dict(_BUILTIN_OUI)
        self._download_oui = download_oui
        self._cache: dict[str, Optional[str]] = {}  # runtime lookup cache

    async def initialize(self) -> None:
        """Optionally fetch the full OUI database."""
        if self._download_oui:
            try:
                await self._download_oui_db()
            except Exception as exc:
                logger.warning("Could not download OUI database, using built-in table", exc_info=exc)

    async def _download_oui_db(self) -> None:
        """Download the maclookup.app JSON OUI database."""
        logger.info("Downloading OUI database from %s", _OUI_DB_URL)
        loop = asyncio.get_event_loop()

        async with aiohttp.ClientSession() as session:
            async with session.get(_OUI_DB_URL, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"OUI DB download failed: HTTP {resp.status}")
                data = await resp.json(content_type=None)

        def _parse(data: list) -> None:
            table: dict[str, str] = dict(_BUILTIN_OUI)
            for entry in data:
                # maclookup.app format: {"macPrefix": "00:00:00", "vendorName": "..."}
                prefix = entry.get("macPrefix", "")
                vendor = entry.get("vendorName", "")
                if prefix and vendor:
                    oui = _normalize_oui(prefix)
                    if oui:
                        table[oui] = vendor
            self._oui_table = table
            logger.info("OUI database loaded: %d entries", len(table))

        await loop.run_in_executor(None, _parse, data)

    async def enrich(self, mac: str) -> Optional[dict[str, Any]]:
        """Return {"vendor": "..."} for the given MAC address, or None."""
        if not mac:
            return None

        oui = _normalize_oui(mac)
        if not oui:
            return None

        # Runtime cache check
        if oui in self._cache:
            vendor = self._cache[oui]
            return {"vendor": vendor} if vendor else None

        vendor = self._oui_table.get(oui)

        # Evict cache if too large
        if len(self._cache) >= _CACHE_LIMIT:
            # Drop oldest 10% of entries
            keys_to_drop = list(self._cache.keys())[: _CACHE_LIMIT // 10]
            for k in keys_to_drop:
                del self._cache[k]

        self._cache[oui] = vendor
        return {"vendor": vendor} if vendor else None
