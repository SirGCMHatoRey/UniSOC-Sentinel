"""
Tests for CorrelationEngine's alert notification wiring.

Covers: alerts triggered by correlation rules must reach BOTH the
siem:live_stream channel (dashboard websocket) AND the
siem:alert_notifications channel (email-notifier), sharing the same
alert id, with the notification-channel payload being the bare alert
dict (no {"type": ..., "data": ...} envelope).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.config import Settings
from src.correlation.engine import (
    _LIVE_CHANNEL,
    _NOTIFICATION_CHANNEL,
    CorrelationEngine,
)

SAMPLE_ALERT: dict[str, Any] = {
    "rule_id": "vpn_anomaly",
    "rule_name": "VPN Login from New Geographic Location",
    "severity": "medium",
    "title": "VPN Geo-Anomaly: jdoe from Russia",
    "description": "User 'jdoe' connected via VPN from a new country: Russia (RU).",
    "event_count": 1,
    "metadata": {"username": "jdoe", "new_country": "RU"},
}


class _FakeRule:
    """A stub correlation rule that returns a fixed alert (or None)."""

    rule_id = "vpn_anomaly"
    rule_name = "VPN Login from New Geographic Location"
    severity = "medium"

    def __init__(self, alert: dict[str, Any] | None) -> None:
        self._alert = alert

    async def evaluate(self, event: dict[str, Any], redis: Any) -> dict[str, Any] | None:
        if self._alert is None:
            return None
        # Return a fresh copy each call — mirrors real rules, which build a
        # new dict per invocation rather than mutating a shared template.
        return dict(self._alert)


def _make_engine(fake_redis) -> CorrelationEngine:
    engine = CorrelationEngine(
        redis=fake_redis,
        db_session_factory=None,
        settings=Settings(),
    )
    # Persistence is out of scope for this ticket — stub it so the test
    # doesn't require a real Postgres connection, and so we can inspect
    # exactly what id it was called with.
    engine._persist_alert = AsyncMock()  # type: ignore[method-assign]
    return engine


async def _next_message(pubsub) -> dict:
    """Poll for the next non-subscribe-confirmation pubsub message."""
    for _ in range(50):
        msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1)
        if msg is not None:
            return msg
    raise AssertionError("No message received on pubsub channel")


@pytest.mark.asyncio
async def test_evaluate_publishes_same_id_to_live_stream_and_notifications(fake_redis):
    """
    A triggered rule must publish to both siem:live_stream (wrapped in the
    websocket envelope) and siem:alert_notifications (bare alert dict),
    both carrying the SAME generated alert id.
    """
    engine = _make_engine(fake_redis)
    engine._rules = [_FakeRule(SAMPLE_ALERT)]

    live_pubsub = fake_redis.pubsub()
    notify_pubsub = fake_redis.pubsub()
    await live_pubsub.subscribe(_LIVE_CHANNEL)
    await notify_pubsub.subscribe(_NOTIFICATION_CHANNEL)

    await engine._evaluate({"event": {"dataset": "vpn"}})

    live_msg = await _next_message(live_pubsub)
    notify_msg = await _next_message(notify_pubsub)

    live_payload = json.loads(live_msg["data"])
    notify_payload = json.loads(notify_msg["data"])

    # siem:live_stream keeps the websocket envelope.
    assert live_payload["type"] == "alert"
    live_alert = live_payload["data"]
    assert live_alert["id"]
    assert live_alert["rule_id"] == "vpn_anomaly"

    # siem:alert_notifications is the BARE alert dict — no envelope.
    assert "type" not in notify_payload
    assert "data" not in notify_payload
    assert notify_payload["id"]
    assert notify_payload["rule_id"] == "vpn_anomaly"
    assert notify_payload["rule_name"] == SAMPLE_ALERT["rule_name"]
    assert notify_payload["severity"] == SAMPLE_ALERT["severity"]
    assert notify_payload["title"] == SAMPLE_ALERT["title"]
    assert notify_payload["description"] == SAMPLE_ALERT["description"]
    assert notify_payload["event_count"] == SAMPLE_ALERT["event_count"]
    assert notify_payload["metadata"] == SAMPLE_ALERT["metadata"]
    # created_at must be present so the notification payload matches the
    # shape alerting-engine's publisher always includes (see evaluator.py
    # _build_alert) — correlation rules themselves never set this field.
    assert notify_payload["created_at"]

    # Same id everywhere: live stream, notification channel, and persistence.
    shared_id = notify_payload["id"]
    assert live_alert["id"] == shared_id

    engine._persist_alert.assert_awaited_once()
    persisted_alert = engine._persist_alert.await_args.args[0]
    assert persisted_alert["id"] == shared_id


@pytest.mark.asyncio
async def test_evaluate_does_not_notify_when_no_rule_triggers(fake_redis):
    """No alert fired → no message on either channel, no persistence."""
    engine = _make_engine(fake_redis)
    engine._rules = [_FakeRule(None)]

    notify_pubsub = fake_redis.pubsub()
    await notify_pubsub.subscribe(_NOTIFICATION_CHANNEL)

    await engine._evaluate({"event": {"dataset": "vpn"}})

    msg = await notify_pubsub.get_message(ignore_subscribe_messages=True, timeout=0.2)
    assert msg is None
    engine._persist_alert.assert_not_awaited()


@pytest.mark.asyncio
async def test_notify_alert_swallows_redis_publish_failure(fake_redis):
    """
    A Redis publish failure on the notification path must be caught and
    logged, not raised — matching _publish_alert's existing error handling,
    so a broken notification channel can never crash the engine loop.
    """
    engine = _make_engine(fake_redis)

    async def _broken_publish(*args, **kwargs):
        raise ConnectionError("redis unavailable")

    engine._redis.publish = _broken_publish  # type: ignore[method-assign]

    alert = dict(SAMPLE_ALERT)
    alert["id"] = "fixed-test-id"

    # Must not raise.
    await engine._notify_alert(alert)
