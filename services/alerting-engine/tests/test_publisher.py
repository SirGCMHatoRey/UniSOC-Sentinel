"""
Tests for the alert publisher (services/alerting-engine/src/publisher.py).

Seams under test:
  - AlertPublisher.publish() fans out a single alert dict to two Redis
    pub/sub channels: the existing "siem:alert_notifications" (bare dict,
    unchanged shape/behaviour — regression check) and the new
    "siem:live_stream" (wrapped in the {"type": "alert", "data": {...}}
    envelope used by the correlation engine).
  - Fault isolation: a failure publishing to one channel must not prevent
    the other channel's publish from being attempted/succeeding.
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from src.publisher import ALERT_CHANNEL, LIVE_STREAM_CHANNEL, AlertPublisher


@pytest.fixture
def sample_alert() -> dict:
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "rule_id": "brute-force-detection",
        "rule_name": "Brute Force Detection",
        "severity": "high",
        "title": "Brute force attempt detected",
        "description": "10 failed logins from 203.0.113.5 in 5 minutes",
        "created_at": "2026-08-01T00:00:00Z",
        "event_count": 10,
        "metadata": {"source_ip": "203.0.113.5"},
    }


async def _get_message(pubsub) -> dict:
    """Poll a fakeredis pubsub object until a real (non-subscribe) message arrives."""
    for _ in range(20):
        message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.2)
        if message is not None:
            return message
    raise AssertionError("No message received on pubsub channel")


async def test_publish_sends_unchanged_bare_alert_to_notification_channel(
    fake_redis, sample_alert
) -> None:
    pubsub = fake_redis.pubsub()
    await pubsub.subscribe(ALERT_CHANNEL)

    await AlertPublisher(fake_redis).publish(sample_alert)

    message = await _get_message(pubsub)
    received = json.loads(message["data"])
    assert received == sample_alert


async def test_publish_sends_enveloped_alert_to_live_stream_channel(
    fake_redis, sample_alert
) -> None:
    pubsub = fake_redis.pubsub()
    await pubsub.subscribe(LIVE_STREAM_CHANNEL)

    await AlertPublisher(fake_redis).publish(sample_alert)

    message = await _get_message(pubsub)
    received = json.loads(message["data"])

    assert received["type"] == "alert"
    data = received["data"]
    # All original alert fields are preserved...
    for key, value in sample_alert.items():
        if key == "created_at":
            continue
        assert data[key] == value
    # ...except created_at, which is overwritten with a fresh ISO timestamp.
    assert "created_at" in data
    datetime.fromisoformat(data["created_at"])  # raises if not valid ISO 8601


async def test_publish_sends_to_both_channels_from_a_single_call(
    fake_redis, sample_alert
) -> None:
    notif_pubsub = fake_redis.pubsub()
    live_pubsub = fake_redis.pubsub()
    await notif_pubsub.subscribe(ALERT_CHANNEL)
    await live_pubsub.subscribe(LIVE_STREAM_CHANNEL)

    await AlertPublisher(fake_redis).publish(sample_alert)

    notif_message = await _get_message(notif_pubsub)
    live_message = await _get_message(live_pubsub)

    assert json.loads(notif_message["data"]) == sample_alert
    live_data = json.loads(live_message["data"])
    assert live_data["type"] == "alert"
    assert live_data["data"]["id"] == sample_alert["id"]


async def test_live_stream_failure_does_not_prevent_notification_publish(
    fake_redis, sample_alert, monkeypatch
) -> None:
    """
    If publishing to the live-stream channel raises, the notification
    publish must still be attempted and must still succeed (fault
    isolation — the live-stream publish is the one that is caught/logged
    rather than propagated).
    """
    pubsub = fake_redis.pubsub()
    await pubsub.subscribe(ALERT_CHANNEL)

    original_publish = fake_redis.publish
    call_channels: list[str] = []

    async def flaky_publish(channel, message, *args, **kwargs):
        call_channels.append(channel)
        if channel == LIVE_STREAM_CHANNEL:
            raise ConnectionError("simulated live-stream outage")
        return await original_publish(channel, message, *args, **kwargs)

    monkeypatch.setattr(fake_redis, "publish", flaky_publish)

    # Should not raise, despite the live-stream publish failing.
    await AlertPublisher(fake_redis).publish(sample_alert)

    # Both channels were attempted.
    assert LIVE_STREAM_CHANNEL in call_channels
    assert ALERT_CHANNEL in call_channels

    # The notification publish still succeeded and delivered the message.
    message = await _get_message(pubsub)
    assert json.loads(message["data"]) == sample_alert


async def test_notification_failure_still_attempts_live_stream_publish(
    fake_redis, sample_alert, monkeypatch
) -> None:
    """
    Even though the notification publish is allowed to propagate errors
    (unchanged behaviour), the live-stream publish must still have been
    attempted — it runs first, before the notification publish can fail.
    """
    pubsub = fake_redis.pubsub()
    await pubsub.subscribe(LIVE_STREAM_CHANNEL)

    original_publish = fake_redis.publish
    call_channels: list[str] = []

    async def flaky_publish(channel, message, *args, **kwargs):
        call_channels.append(channel)
        if channel == ALERT_CHANNEL:
            raise ConnectionError("simulated notification outage")
        return await original_publish(channel, message, *args, **kwargs)

    monkeypatch.setattr(fake_redis, "publish", flaky_publish)

    with pytest.raises(ConnectionError):
        await AlertPublisher(fake_redis).publish(sample_alert)

    assert LIVE_STREAM_CHANNEL in call_channels
    assert ALERT_CHANNEL in call_channels

    # The live-stream publish still succeeded and delivered the message.
    message = await _get_message(pubsub)
    live_data = json.loads(message["data"])
    assert live_data["type"] == "alert"
    assert live_data["data"]["id"] == sample_alert["id"]
