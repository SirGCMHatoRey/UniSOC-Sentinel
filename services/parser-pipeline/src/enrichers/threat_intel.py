"""Threat intelligence enricher — IP blocklist matching."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from pathlib import Path
from typing import Any, Optional

from .base import BaseEnricher

logger = logging.getLogger(__name__)

_INTEL_DIR = Path("/data/threat-intel")
_REFRESH_INTERVAL_SECONDS = 6 * 3600  # 6 hours
_COMMENT_RE = re.compile(r"^\s*[#;]")
_CIDR_RE = re.compile(r"^[\d.]+/\d+$")
_IP_RE = re.compile(r"^[\d.]+$")


def _parse_feed_file(path: Path) -> tuple[set[str], list[ipaddress.IPv4Network]]:
    """Parse a blocklist file, returning (plain_ips, cidr_networks)."""
    plain: set[str] = set()
    nets: list[ipaddress.IPv4Network] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return plain, nets

    for line in text.splitlines():
        line = line.strip()
        if not line or _COMMENT_RE.match(line):
            continue
        # Strip inline comments
        line = line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        if _CIDR_RE.match(line):
            try:
                nets.append(ipaddress.IPv4Network(line, strict=False))
            except ValueError:
                pass
        elif _IP_RE.match(line):
            plain.add(line)
    return plain, nets


class ThreatIntelEnricher(BaseEnricher):
    """
    Matches an IP against threat intelligence blocklists loaded from
    /data/threat-intel/*.txt files.

    Each file is named after the feed (e.g., feodo_tracker.txt, spamhaus_drop.txt).
    Lines beginning with # or ; are treated as comments.
    Supports plain IPs and CIDR notation.

    Refreshes the blocklists every 6 hours in a background task.
    """

    def __init__(self, intel_dir: str = str(_INTEL_DIR)) -> None:
        self._intel_dir = Path(intel_dir)
        # feed_name -> (plain_ip_set, cidr_list)
        self._feeds: dict[str, tuple[set[str], list[ipaddress.IPv4Network]]] = {}
        self._all_plain: set[str] = set()
        self._all_cidrs: list[tuple[str, ipaddress.IPv4Network]] = []
        self._refresh_task: Optional[asyncio.Task] = None

    async def initialize(self) -> None:
        """Load blocklists and start the background refresh loop."""
        await self._load_feeds()
        self._refresh_task = asyncio.create_task(self._refresh_loop(), name="threat-intel-refresh")

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(_REFRESH_INTERVAL_SECONDS)
            try:
                await self._load_feeds()
                logger.info("Threat intelligence feeds refreshed")
            except Exception as exc:
                logger.warning("Failed to refresh threat intel feeds", exc_info=exc)

    async def _load_feeds(self) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._do_load_feeds)

    def _do_load_feeds(self) -> None:
        if not self._intel_dir.exists():
            logger.info(
                "Threat intel directory not found — enrichment disabled",
                extra={"path": str(self._intel_dir)},
            )
            return

        feeds: dict[str, tuple[set[str], list[ipaddress.IPv4Network]]] = {}
        all_plain: set[str] = set()
        all_cidrs: list[tuple[str, ipaddress.IPv4Network]] = []

        for feed_file in sorted(self._intel_dir.glob("*.txt")):
            feed_name = feed_file.stem
            plain, nets = _parse_feed_file(feed_file)
            feeds[feed_name] = (plain, nets)
            all_plain |= plain
            for net in nets:
                all_cidrs.append((feed_name, net))

        self._feeds = feeds
        self._all_plain = all_plain
        self._all_cidrs = all_cidrs

        total_ips = len(all_plain)
        total_cidrs = len(all_cidrs)
        logger.info(
            "Threat intel feeds loaded",
            extra={"feeds": len(feeds), "ips": total_ips, "cidrs": total_cidrs},
        )

    async def enrich(self, ip_str: str) -> Optional[dict[str, Any]]:
        """Check if the IP matches any blocklist. Returns match info or not-matched dict."""
        if not ip_str:
            return {"matched": False, "feed": None, "score": 0}

        # O(1) plain lookup first
        if ip_str in self._all_plain:
            feed = self._find_feed_for_ip(ip_str)
            return {"matched": True, "feed": feed, "score": 90}

        # CIDR lookup (linear, but blocklists are typically small)
        try:
            addr = ipaddress.IPv4Address(ip_str)
        except ValueError:
            return {"matched": False, "feed": None, "score": 0}

        for feed_name, net in self._all_cidrs:
            if addr in net:
                return {"matched": True, "feed": feed_name, "score": 85}

        return {"matched": False, "feed": None, "score": 0}

    def _find_feed_for_ip(self, ip_str: str) -> Optional[str]:
        for feed_name, (plain, _) in self._feeds.items():
            if ip_str in plain:
                return feed_name
        return None

    async def close(self) -> None:
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
