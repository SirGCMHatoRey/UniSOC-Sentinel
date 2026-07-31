"""
Brute force detection rule.

Triggers when a single source IP has >= 10 authentication failures in 300 seconds.

Redis data structure:
  Sorted set "corr:auth_fail:{source_ip}"
  - ZADD with the current Unix timestamp as both score and member suffix
  - ZREMRANGEBYSCORE to drop events outside the 300s window
  - ZCARD to count remaining events
  - TTL 600s on the key
"""

from __future__ import annotations

import time
from typing import Any

from redis.asyncio import Redis

from src.correlation.rules.base import BaseCorrelationRule

_WINDOW_SECONDS = 300
_THRESHOLD = 10
_KEY_TTL = 600


class BruteForceRule(BaseCorrelationRule):
    rule_id = "brute_force"
    rule_name = "Brute Force Authentication Attack"
    severity = "high"

    async def evaluate(self, event: dict[str, Any], redis: Redis) -> dict | None:
        # Only interested in authentication failure events
        categories = event.get("event", {}).get("category", [])
        outcome = event.get("event", {}).get("outcome", "")

        if "authentication" not in categories or outcome != "failure":
            return None

        source_ip = event.get("source", {}).get("ip")
        if not source_ip:
            return None

        key = f"corr:auth_fail:{source_ip}"
        now = time.time()
        window_start = now - _WINDOW_SECONDS

        # Add this event (unique member = timestamp:event_id)
        event_id = event.get("event", {}).get("id", str(now))
        member = f"{now}:{event_id}"
        await redis.zadd(key, {member: now})

        # Remove events outside the window
        await redis.zremrangebyscore(key, "-inf", window_start)

        # Count events in window
        count = await redis.zcard(key)

        # Renew TTL
        await redis.expire(key, _KEY_TTL)

        if count >= _THRESHOLD:
            # Clear the window to avoid re-triggering on every subsequent failure
            await redis.delete(key)
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "title": f"Brute Force: {source_ip}",
                "description": (
                    f"Source IP {source_ip} had {count} authentication failures "
                    f"in the last {_WINDOW_SECONDS} seconds."
                ),
                "event_count": count,
                "metadata": {
                    "source_ip": source_ip,
                    "failure_count": count,
                    "window_seconds": _WINDOW_SECONDS,
                },
            }

        return None
