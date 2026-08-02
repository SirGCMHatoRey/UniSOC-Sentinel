"""
Tests for RuleEvaluator's condition-matching dispatch
(services/alerting-engine/src/evaluator.py).

Seam under test: RuleEvaluator.evaluate() — the public async entry point.
Dependencies (AlertDeduplicator, AlertThrottler) are real implementations
backed by the fake_redis fixture; Metrics() is a real Prometheus metrics
container.
"""

from __future__ import annotations

import pytest

from src.deduplicator import AlertDeduplicator
from src.evaluator import RuleEvaluator
from src.metrics import Metrics
from src.rules.loader import AlertRule, RuleCondition
from src.throttler import AlertThrottler

# prometheus_client registers metric names in a process-global registry, so
# Metrics() must be constructed exactly once for the whole test session —
# a second instantiation would raise "Duplicated timeseries in
# CollectorRegistry".


@pytest.fixture(scope="session")
def metrics() -> Metrics:
    return Metrics()


def make_rule(
    *,
    rule_id: str,
    operator: str,
    value: object,
    field: str = "network.bytes",
    group_by: str = "source.ip",
    threshold: int = 1,
    window_seconds: int = 60,
) -> AlertRule:
    condition = RuleCondition(
        field=field,
        group_by=group_by,
        threshold=threshold,
        window_seconds=window_seconds,
        value=value,
        operator=operator,
    )
    # NOTE: dedup_key/title/body templates deliberately avoid dotted
    # placeholders like "{source.ip}" — str.format_map treats a "." in a
    # field name as attribute access, not a dict key, and the flattened
    # template context here only stores literal dotted-string keys. That
    # templating behavior is a pre-existing concern in
    # RuleEvaluator._render_template/_build_context, unrelated to the
    # operator-dispatch behavior these tests exercise, so it's avoided
    # rather than worked around here.
    return AlertRule(
        id=rule_id,
        name=f"Test Rule {rule_id}",
        condition=condition,
        severity="medium",
        dedup_key=f"{rule_id}:{{group_key}}",
        dedup_ttl_seconds=60,
        throttle_seconds=60,
        title_template="Test {group_key}",
        body_template="Test body {event_count}",
    )


def make_evaluator(
    rule: AlertRule, fake_redis: object, metrics: Metrics
) -> RuleEvaluator:
    deduplicator = AlertDeduplicator(fake_redis)
    throttler = AlertThrottler(fake_redis)
    return RuleEvaluator(
        rules=[rule],
        redis=fake_redis,
        deduplicator=deduplicator,
        throttler=throttler,
        metrics=metrics,
    )


def make_event(**nested: object) -> dict:
    """Build a nested event dict from dotted kwargs, e.g. network__bytes=5."""
    event: dict = {"source": {"ip": "203.0.113.10"}, "event": {"dataset": ""}}
    for dotted_key, value in nested.items():
        parts = dotted_key.split("__")
        cursor = event
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = value
    return event


# ---------------------------------------------------------------------------
# eq — preserve existing behavior exactly
# ---------------------------------------------------------------------------


async def test_eq_matches_when_field_equals_expected(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="eq_positive", operator="eq", value="failure", field="event.outcome"
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(event__outcome="failure")

    alerts = await evaluator.evaluate(event)

    assert len(alerts) == 1


async def test_eq_rejects_when_field_differs_from_expected(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="eq_negative", operator="eq", value="failure", field="event.outcome"
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(event__outcome="success")

    alerts = await evaluator.evaluate(event)

    assert alerts == []


# ---------------------------------------------------------------------------
# gte — the bandwidth_spike scenario: network.bytes >= threshold
# ---------------------------------------------------------------------------


async def test_gte_fires_when_value_is_at_or_above_threshold(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="gte_positive",
        operator="gte",
        value=1073741824,
        field="network.bytes",
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(network__bytes=1073741824)

    alerts = await evaluator.evaluate(event)

    assert len(alerts) == 1


async def test_gte_does_not_fire_when_value_is_below_threshold(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="gte_negative",
        operator="gte",
        value=1073741824,
        field="network.bytes",
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(network__bytes=1000)

    alerts = await evaluator.evaluate(event)

    assert alerts == []


async def test_gte_non_numeric_field_value_does_not_crash_and_does_not_match(
    fake_redis, metrics
) -> None:
    rule = make_rule(
        rule_id="gte_non_numeric",
        operator="gte",
        value=1073741824,
        field="network.bytes",
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(network__bytes="not-a-number")

    alerts = await evaluator.evaluate(event)

    assert alerts == []


# ---------------------------------------------------------------------------
# ne
# ---------------------------------------------------------------------------


async def test_ne_matches_when_field_differs_from_expected(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="ne_positive", operator="ne", value="failure", field="event.outcome"
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(event__outcome="success")

    alerts = await evaluator.evaluate(event)

    assert len(alerts) == 1


async def test_ne_rejects_when_field_equals_expected(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="ne_negative", operator="ne", value="failure", field="event.outcome"
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(event__outcome="failure")

    alerts = await evaluator.evaluate(event)

    assert alerts == []


# ---------------------------------------------------------------------------
# gt
# ---------------------------------------------------------------------------


async def test_gt_matches_when_value_exceeds_expected(fake_redis, metrics) -> None:
    rule = make_rule(rule_id="gt_positive", operator="gt", value=50, field="event.count")
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(event__count=51)

    alerts = await evaluator.evaluate(event)

    assert len(alerts) == 1


async def test_gt_rejects_when_value_equals_expected(fake_redis, metrics) -> None:
    rule = make_rule(rule_id="gt_negative", operator="gt", value=50, field="event.count")
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(event__count=50)

    alerts = await evaluator.evaluate(event)

    assert alerts == []


# ---------------------------------------------------------------------------
# lt
# ---------------------------------------------------------------------------


async def test_lt_matches_when_value_is_below_expected(fake_redis, metrics) -> None:
    rule = make_rule(rule_id="lt_positive", operator="lt", value=50, field="event.count")
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(event__count=10)

    alerts = await evaluator.evaluate(event)

    assert len(alerts) == 1


async def test_lt_rejects_when_value_equals_expected(fake_redis, metrics) -> None:
    rule = make_rule(rule_id="lt_negative", operator="lt", value=50, field="event.count")
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(event__count=50)

    alerts = await evaluator.evaluate(event)

    assert alerts == []


# ---------------------------------------------------------------------------
# contains
# ---------------------------------------------------------------------------


async def test_contains_matches_when_substring_present(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="contains_positive",
        operator="contains",
        value="powershell",
        field="process.command_line",
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(process__command_line="C:\\Windows\\System32\\powershell.exe -enc AB")

    alerts = await evaluator.evaluate(event)

    assert len(alerts) == 1


async def test_contains_rejects_when_substring_absent(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="contains_negative",
        operator="contains",
        value="powershell",
        field="process.command_line",
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event(process__command_line="/bin/bash -c ls")

    alerts = await evaluator.evaluate(event)

    assert alerts == []


# ---------------------------------------------------------------------------
# regex
# ---------------------------------------------------------------------------


async def test_regex_matches_when_pattern_found(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="regex_positive",
        operator="regex",
        value=r"^10\.0\.\d+\.\d+$",
        field="source.ip",
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event()
    event["source"]["ip"] = "10.0.5.20"

    alerts = await evaluator.evaluate(event)

    assert len(alerts) == 1


async def test_regex_rejects_when_pattern_not_found(fake_redis, metrics) -> None:
    rule = make_rule(
        rule_id="regex_negative",
        operator="regex",
        value=r"^10\.0\.\d+\.\d+$",
        field="source.ip",
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event()
    event["source"]["ip"] = "203.0.113.10"

    alerts = await evaluator.evaluate(event)

    assert alerts == []


async def test_regex_invalid_pattern_does_not_crash_and_does_not_match(
    fake_redis, metrics
) -> None:
    # An unbalanced group is invalid regex syntax (re.error) — a bad pattern
    # in rule config must not crash evaluation for this or any other rule
    # on the same event.
    rule = make_rule(
        rule_id="regex_invalid_pattern",
        operator="regex",
        value=r"(unclosed",
        field="source.ip",
    )
    evaluator = make_evaluator(rule, fake_redis, metrics)
    event = make_event()
    event["source"]["ip"] = "203.0.113.10"

    alerts = await evaluator.evaluate(event)

    assert alerts == []
