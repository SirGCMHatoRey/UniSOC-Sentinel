"""
YAML alert rule loader for the alerting-engine service.

Rules are defined in /config/alert-rules.yml and describe sliding-window
threshold conditions.  Each rule is parsed into typed dataclasses so the
evaluator can work with validated, structured data rather than raw dicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, get_args

import yaml

#: Comparison operator applied between a condition's field value and its
#: configured `value`, per the schema documented in
#: config/alert-rules/alert-rules.yml.
Operator = Literal["eq", "ne", "gt", "gte", "lt", "lte", "contains", "regex"]

#: Valid values for RuleCondition.operator, derived from the Operator type
#: so the two can never drift apart.
VALID_OPERATORS: frozenset[str] = frozenset(get_args(Operator))


@dataclass
class RuleCondition:
    """
    Threshold condition that must be met to trigger an alert.

    Attributes:
        field:          Dot-notation path into the ECS event dict to test.
                        e.g. "event.outcome"
        value:          The value that field must equal.  None means "any value"
                        (i.e. count all events regardless of field content).
        operator:       Comparison operator applied between the field value and
                        `value`.  One of: eq, ne, gt, gte, lt, lte, contains, regex.
                        Defaults to "eq".
        group_by:       Dot-notation path whose value partitions the sliding
                        window counter.  e.g. "source.ip" gives per-IP counts.
        threshold:      Minimum count within the window to fire the rule.
        window_seconds: Width of the sliding time window in seconds.
    """

    field: str
    group_by: str
    threshold: int
    window_seconds: int
    value: str | None = None
    operator: Operator = "eq"

    def __post_init__(self) -> None:
        # yaml.safe_load gives us plain strings, so the Literal type is not
        # enforced until runtime — validate explicitly here so a bad value
        # in config fails loudly at load time instead of silently later.
        if self.operator not in VALID_OPERATORS:
            raise ValueError(
                f"Invalid operator {self.operator!r}; must be one of "
                f"{sorted(VALID_OPERATORS)}"
            )


@dataclass
class AlertRule:
    """
    Complete alert rule loaded from YAML configuration.

    Attributes:
        id:                 Unique machine identifier, used as label in metrics
                            and as part of Redis keys.
        name:               Human-readable rule name shown in alert titles.
        description:        Human-readable explanation of what threat the rule
                            detects. Not used in alert output; documentation only.
        dataset_filter:     List of event.dataset values this rule applies to.
                            An empty list means the rule applies to all datasets.
        condition:          The threshold condition (see RuleCondition).
        severity:           One of critical | high | medium | low | info.
        dedup_key:          Template string rendered with event context to form
                            the Redis deduplication key.
                            e.g. "brute_force:{source.ip}"
        dedup_ttl_seconds:  How long the dedup key lives in Redis (seconds).
        throttle_seconds:   Minimum gap between consecutive alerts for the same
                            rule+group combination (seconds).
        title_template:     str.format_map template for the alert title.
        body_template:      str.format_map template for the alert description.
    """

    id: str
    name: str
    condition: RuleCondition
    severity: str
    dedup_key: str
    dedup_ttl_seconds: int
    throttle_seconds: int
    title_template: str
    body_template: str
    dataset_filter: list[str] = field(default_factory=list)
    description: str = ""


def load_rules(path: str) -> list[AlertRule]:
    """
    Parse alert rules from a YAML file and return a list of AlertRule objects.

    The YAML structure expected at the top level is:
        rules:
          - id: some_rule
            name: Human Name
            dataset_filter: [...]
            condition:
              field: event.outcome
              value: failure
              group_by: source.ip
              threshold: 10
              window_seconds: 300
            severity: high
            dedup_key: "rule:{source.ip}"
            dedup_ttl_seconds: 3600
            throttle_seconds: 900
            title_template: "Alert: {source.ip}"
            body_template: "{event_count} events in window"

    Args:
        path: Filesystem path to the YAML rules file.

    Returns:
        Ordered list of AlertRule instances.

    Raises:
        FileNotFoundError: If the rules file does not exist.
        yaml.YAMLError:    If the file is not valid YAML.
        KeyError:          If a required field is missing from a rule definition.
    """
    rules_path = Path(path)
    with rules_path.open() as fh:
        data = yaml.safe_load(fh)

    rules: list[AlertRule] = []
    for raw in data["rules"]:
        # Pop condition dict before passing remainder to AlertRule
        raw = dict(raw)
        condition_data = raw.pop("condition")
        condition = RuleCondition(**condition_data)
        rules.append(AlertRule(condition=condition, **raw))

    return rules
