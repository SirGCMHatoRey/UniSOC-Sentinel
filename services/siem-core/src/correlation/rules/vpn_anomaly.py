"""
VPN geographic anomaly rule.

Triggers when a VPN user logs in from a country that has not been seen
before for that user.

Redis data structure:
  Hash "corr:vpn_geos:{username}"   field=source_ip  value=country_code
  (Persists all known (user, country) combinations)
"""

from __future__ import annotations

from typing import Any

from redis.asyncio import Redis

from src.correlation.rules.base import BaseCorrelationRule


class VPNAnomalyRule(BaseCorrelationRule):
    rule_id = "vpn_anomaly"
    rule_name = "VPN Login from New Geographic Location"
    severity = "medium"

    async def evaluate(self, event: dict[str, Any], redis: Redis) -> dict | None:
        # Only process VPN events
        dataset = event.get("event", {}).get("dataset", "")
        if "vpn" not in dataset.lower():
            return None

        # Must be a login / session start
        event_types = event.get("event", {}).get("type", [])
        if isinstance(event_types, str):
            event_types = [event_types]
        if not any(t in ("start", "allowed", "connection") for t in event_types):
            return None

        username = event.get("user", {}).get("name")
        if not username:
            return None

        source_ip = event.get("source", {}).get("ip", "unknown")
        country_code = (
            event.get("source", {}).get("geo", {}).get("country_iso_code", "")
        )
        country_name = (
            event.get("source", {}).get("geo", {}).get("country_name", country_code or "Unknown")
        )

        if not country_code:
            return None

        key = f"corr:vpn_geos:{username}"

        # Get previously seen countries for this user
        known_geos = await redis.hgetall(key)

        # Decode bytes keys/values
        known_countries = {
            (v.decode() if isinstance(v, bytes) else v)
            for v in known_geos.values()
        }

        # Record this IP → country mapping
        ip_field = source_ip.replace(".", "_")
        await redis.hset(key, ip_field, country_code)

        if country_code not in known_countries and known_countries:
            # New country — but only alert if user has a prior history
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "title": f"VPN Geo-Anomaly: {username} from {country_name}",
                "description": (
                    f"User '{username}' connected via VPN from a new country: "
                    f"{country_name} ({country_code}). "
                    f"Previously seen countries: {', '.join(sorted(known_countries))}."
                ),
                "event_count": 1,
                "metadata": {
                    "username": username,
                    "new_country": country_code,
                    "new_country_name": country_name,
                    "source_ip": source_ip,
                    "known_countries": sorted(known_countries),
                },
            }

        return None
