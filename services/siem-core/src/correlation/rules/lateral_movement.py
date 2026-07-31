"""
Lateral movement detection rule.

Triggers when an internal (RFC1918) source IP contacts >= 10 distinct
destination IPs within a 60-second window.

Redis data structure:
  Sorted set "corr:lateral:{source_ip}"
  - Members: "dest_ip:timestamp" — score: unix timestamp
  - ZREMRANGEBYSCORE to evict old entries
  - Count distinct dest IPs via a Lua-like approach: store "dest_ip" as member
    with timestamp as score, then count distinct dest IPs with ZRANGE
"""

from __future__ import annotations

import ipaddress
import time
from typing import Any

from redis.asyncio import Redis

from src.correlation.rules.base import BaseCorrelationRule

_WINDOW_SECONDS = 60
_THRESHOLD = 10
_KEY_TTL = 120


def _is_rfc1918(ip: str) -> bool:
    """Return True if the IP address is in RFC1918 (private) space."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class LateralMovementRule(BaseCorrelationRule):
    rule_id = "lateral_movement"
    rule_name = "Lateral Movement Detected"
    severity = "high"

    async def evaluate(self, event: dict[str, Any], redis: Redis) -> dict | None:
        source_ip = event.get("source", {}).get("ip")
        dest_ip = event.get("destination", {}).get("ip")

        if not source_ip or not dest_ip:
            return None

        # Only track internal source IPs
        if not _is_rfc1918(source_ip):
            return None

        key = f"corr:lateral:{source_ip}"
        now = time.time()
        window_start = now - _WINDOW_SECONDS

        # Add dest_ip with current timestamp as score
        # Use dest_ip as the member — ZADD with NX won't duplicate, but we need
        # to update the score for recency tracking.  Use XX=False to allow overwrite.
        await redis.zadd(key, {dest_ip: now})

        # Remove entries older than the window
        await redis.zremrangebyscore(key, "-inf", window_start)

        # Count distinct dest IPs in the window
        distinct_dests = await redis.zcard(key)

        await redis.expire(key, _KEY_TTL)

        if distinct_dests >= _THRESHOLD:
            # Retrieve the distinct destination IPs for metadata
            raw_members = await redis.zrange(key, 0, -1)
            dest_ips = [
                m.decode() if isinstance(m, bytes) else m
                for m in raw_members
            ]
            # Clear to avoid repeated alerts
            await redis.delete(key)

            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "title": f"Lateral Movement: {source_ip}",
                "description": (
                    f"Internal host {source_ip} contacted {distinct_dests} distinct "
                    f"destinations within {_WINDOW_SECONDS} seconds. "
                    f"Possible lateral movement or scanning."
                ),
                "event_count": distinct_dests,
                "metadata": {
                    "source_ip": source_ip,
                    "distinct_destinations": distinct_dests,
                    "destination_ips": dest_ips[:20],  # cap for storage
                    "window_seconds": _WINDOW_SECONDS,
                },
            }

        return None
