"""
Tests for the alert-rule YAML loader (services/alerting-engine/src/rules/loader.py).

Seams under test:
  - RuleCondition construction (dataclass + __post_init__ validation)
  - load_rules() against the real shipped config/alert-rules/alert-rules.yml
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.rules.loader import VALID_OPERATORS, RuleCondition, load_rules

REPO_ROOT = Path(__file__).resolve().parents[3]
REAL_RULES_PATH = REPO_ROOT / "config" / "alert-rules" / "alert-rules.yml"


def _base_kwargs(**overrides: object) -> dict:
    kwargs: dict = {
        "field": "event.outcome",
        "group_by": "source.ip",
        "threshold": 10,
        "window_seconds": 300,
    }
    kwargs.update(overrides)
    return kwargs


def test_operator_defaults_to_eq_when_omitted() -> None:
    condition = RuleCondition(**_base_kwargs())
    assert condition.operator == "eq"


@pytest.mark.parametrize("operator", sorted(VALID_OPERATORS))
def test_each_valid_operator_is_accepted(operator: str) -> None:
    condition = RuleCondition(**_base_kwargs(operator=operator))
    assert condition.operator == operator


def test_invalid_operator_raises_value_error() -> None:
    with pytest.raises(ValueError, match="bogus_operator"):
        RuleCondition(**_base_kwargs(operator="bogus_operator"))


def test_invalid_operator_error_lists_valid_set() -> None:
    with pytest.raises(ValueError) as exc_info:
        RuleCondition(**_base_kwargs(operator="nope"))
    message = str(exc_info.value)
    for valid_op in VALID_OPERATORS:
        assert valid_op in message


def test_load_real_alert_rules_yaml_succeeds_and_yields_seven_rules() -> None:
    assert REAL_RULES_PATH.exists(), f"expected rules file at {REAL_RULES_PATH}"
    rules = load_rules(str(REAL_RULES_PATH))
    assert len(rules) == 7


def test_load_real_alert_rules_bandwidth_spike_uses_gte() -> None:
    rules = load_rules(str(REAL_RULES_PATH))
    by_id = {rule.id: rule for rule in rules}
    assert by_id["bandwidth_spike"].condition.operator == "gte"
    assert str(by_id["bandwidth_spike"].condition.value) == "1073741824"
