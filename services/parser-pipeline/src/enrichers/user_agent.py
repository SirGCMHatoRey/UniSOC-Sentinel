"""User-agent string enricher."""
from __future__ import annotations

from typing import Any, Optional

from user_agents import parse as ua_parse

from .base import BaseEnricher


class UserAgentEnricher(BaseEnricher):
    """
    Enriches a user-agent string with structured device / browser / OS info.

    Uses the `user-agents` library (wraps ua-parser).
    Only processes strings that look like real user-agent values — skips empty
    or very short strings.
    """

    MIN_LENGTH = 10  # Minimum UA string length to bother parsing

    async def enrich(self, ua_string: str) -> Optional[dict[str, Any]]:
        """
        Parse the user-agent string and return a dict with browser, OS, device, and is_bot.

        Returns None if the string is empty or too short.
        """
        if not ua_string or len(ua_string) < self.MIN_LENGTH:
            return None

        try:
            ua = ua_parse(ua_string)
            return {
                "browser": {
                    "family": ua.browser.family,
                    "version": ".".join(str(v) for v in ua.browser.version if v is not None),
                },
                "os": {
                    "family": ua.os.family,
                    "version": ".".join(str(v) for v in ua.os.version if v is not None),
                },
                "device": {
                    "family": ua.device.family,
                    "brand": ua.device.brand,
                    "model": ua.device.model,
                },
                "is_bot": ua.is_bot,
                "is_mobile": ua.is_mobile,
                "is_tablet": ua.is_tablet,
                "is_pc": ua.is_pc,
            }
        except Exception:
            return None
