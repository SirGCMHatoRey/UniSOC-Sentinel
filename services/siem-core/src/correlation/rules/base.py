"""Abstract base class for all correlation rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from redis.asyncio import Redis


class BaseCorrelationRule(ABC):
    """
    All concrete correlation rules must subclass this and implement evaluate().

    Attributes:
        rule_id:   Unique machine-readable identifier (used as FK in alerts table).
        rule_name: Human-readable display name.
        severity:  One of: critical, high, medium, low, info.
    """

    rule_id: str
    rule_name: str
    severity: str

    @abstractmethod
    async def evaluate(self, event: dict[str, Any], redis: Redis) -> dict | None:
        """
        Evaluate the incoming ECS event against this rule.

        Args:
            event: Parsed ECS event dict.
            redis: Redis async client for stateful sliding-window operations.

        Returns:
            An alert dict if the rule triggered, otherwise None.
            Alert dict fields: rule_id, rule_name, severity, title, description,
                               event_count, metadata.
        """
        ...
