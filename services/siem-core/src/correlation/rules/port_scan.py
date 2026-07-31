"""
Port scan detection rule.

Triggers when a single source IP contacts >= 15 distinct destination ports
within a 60-second minute bucket.

Redis data structure:
  Set "corr:ports:{source_ip}:{minute_bucket}"
  - SADD destination port
  - SCARD to count distinct ports
  - EXPIRE 120s (two buckets so we don't lose data at bucket boundary)
"""

from __future__ import annotations

import time
from typing import Any

from redis.asyncio import Redis

from src.correlation.rules.base import BaseCorrelationRule

_THRESHOLD = 15
_KEY_TTL = 120  # 2 minute buckets


class PortScanRule(BaseCorrelationRule):
    rule_id = "port_scan"
    rule_name = "Port Scan Detected"
    severity = "medium"

    async def evaluate(self, event: dict[str, Any], redis: Redis) -> dict | None:
        source_ip = event.get("source", {}).get("ip")
        dest_port = event.get("destination", {}).get("port")

        if not source_ip or dest_port is None:
            return None

        # Use a per-minute bucket so windows reset naturally
        minute_bucket = int(time.time()) // 60
        key = f"corr:ports:{source_ip}:{minute_bucket}"

        await redis.sadd(key, str(dest_port))
        await redis.expire(key, _KEY_TTL)

        distinct_ports = await redis.scard(key)

        if distinct_ports >= _THRESHOLD:
            # Clear the set to suppress repeated alerts for the same burst
            await redis.delete(key)
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "title": f"Port Scan: {source_ip}",
                "description": (
                    f"Source IP {source_ip} contacted {distinct_ports} distinct "
                    f"destination ports within a 60-second window."
                ),
                "event_count": distinct_ports,
                "metadata": {
                    "source_ip": source_ip,
                    "distinct_ports": distinct_ports,
                    "threshold": _THRESHOLD,
                },
            }

        return None
