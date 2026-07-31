"""
Admin abuse / off-hours access rule.

Triggers when a unifi.admin dataset event occurs outside business hours
(before 06:00 UTC or after 22:00 UTC).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from redis.asyncio import Redis

from src.correlation.rules.base import BaseCorrelationRule

_BUSINESS_START_HOUR = 6   # 06:00 UTC inclusive
_BUSINESS_END_HOUR = 22    # 22:00 UTC exclusive


class AdminAbuseRule(BaseCorrelationRule):
    rule_id = "admin_abuse"
    rule_name = "Admin Access Outside Business Hours"
    severity = "medium"

    async def evaluate(self, event: dict[str, Any], redis: Redis) -> dict | None:
        dataset = event.get("event", {}).get("dataset", "")
        if dataset != "unifi.admin":
            return None

        # Parse event timestamp
        ts_str = event.get("@timestamp")
        if ts_str is None:
            return None

        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            hour_utc = ts.astimezone(timezone.utc).hour
        except (ValueError, AttributeError):
            return None

        # Business hours: 06:00 <= hour < 22:00
        if _BUSINESS_START_HOUR <= hour_utc < _BUSINESS_END_HOUR:
            return None

        username = event.get("user", {}).get("name", "unknown")
        source_ip = event.get("source", {}).get("ip", "unknown")
        action = event.get("message", "admin action")

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": f"Off-Hours Admin Access by {username}",
            "description": (
                f"Admin activity detected outside business hours "
                f"({_BUSINESS_START_HOUR:02d}:00–{_BUSINESS_END_HOUR:02d}:00 UTC). "
                f"User: {username}, IP: {source_ip}, Hour: {hour_utc:02d}:xx UTC."
            ),
            "event_count": 1,
            "metadata": {
                "username": username,
                "source_ip": source_ip,
                "hour_utc": hour_utc,
                "timestamp": ts_str,
                "action": action,
                "dataset": dataset,
            },
        }
