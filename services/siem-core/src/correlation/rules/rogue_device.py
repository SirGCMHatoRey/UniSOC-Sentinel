"""
Rogue device detection rule.

Triggers when a MAC address is seen for the first time (not in the
persistent "corr:known_macs" Redis set). Alerts once per MAC per 24 hours.

Redis data structures:
  Set  "corr:known_macs"              — persistent set of all observed MACs
  Key  "corr:rogue_alerted:{mac}"     — TTL 86400s, prevents duplicate alerts
"""

from __future__ import annotations

from typing import Any

from redis.asyncio import Redis

from src.correlation.rules.base import BaseCorrelationRule

_ALERT_DEDUP_TTL = 86400  # 24 hours


class RogueDeviceRule(BaseCorrelationRule):
    rule_id = "rogue_device"
    rule_name = "Rogue Device Detected"
    severity = "high"

    async def evaluate(self, event: dict[str, Any], redis: Redis) -> dict | None:
        mac = event.get("source", {}).get("mac")
        if not mac:
            return None

        # Normalise MAC (lowercase, colon-separated)
        mac = mac.lower().replace("-", ":").strip()

        # Check dedup key first (avoid double-alerting)
        dedup_key = f"corr:rogue_alerted:{mac}"
        if await redis.exists(dedup_key):
            # Already alerted for this MAC recently
            # Still add to known set so we don't re-alert after TTL expires
            await redis.sadd("corr:known_macs", mac)
            return None

        is_known = await redis.sismember("corr:known_macs", mac)
        # Add to known set regardless
        await redis.sadd("corr:known_macs", mac)

        if not is_known:
            # First time we've seen this MAC — set dedup key and alert
            await redis.setex(dedup_key, _ALERT_DEDUP_TTL, "1")

            source_ip = event.get("source", {}).get("ip", "unknown")
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "title": f"Rogue Device: {mac}",
                "description": (
                    f"Unknown MAC address {mac} (IP: {source_ip}) observed "
                    f"on the network for the first time."
                ),
                "event_count": 1,
                "metadata": {
                    "mac": mac,
                    "source_ip": source_ip,
                    "dataset": event.get("event", {}).get("dataset"),
                },
            }

        return None
