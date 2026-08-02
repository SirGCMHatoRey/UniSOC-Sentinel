"""
Cross-engine rule id collision check (issue #5).

correlation-engine (siem-core) and alerting-engine each maintain their own
rule id namespace — siem-core's rules are Python class attributes
(`rule_id = "..."` in services/siem-core/src/correlation/rules/*.py) rather
than a shared config file, so there is no single source to load both sets
from. This test hardcodes the known correlation-engine rule ids and checks
them against the real, loaded alerting-engine YAML ids to confirm the two
namespaces stay disjoint — i.e. no alerting-engine rule id silently shadows
a correlation-engine rule id (or vice versa), which would cause the same
alert id to be emitted by two different detection paths.

If a new rule is added to either engine, this test's failure is the signal
to pick a non-colliding id.
"""

from __future__ import annotations

from pathlib import Path

from src.rules.loader import load_rules

REPO_ROOT = Path(__file__).resolve().parents[3]
REAL_RULES_PATH = REPO_ROOT / "config" / "alert-rules" / "alert-rules.yml"

# rule_id class attributes from services/siem-core/src/correlation/rules/*.py
CORRELATION_ENGINE_RULE_IDS = frozenset(
    {
        "admin_abuse",
        "brute_force",
        "lateral_movement",
        "port_scan",
        "rogue_device",
        "vpn_anomaly",
    }
)


def test_correlation_and_alerting_rule_ids_are_disjoint() -> None:
    alerting_rule_ids = {rule.id for rule in load_rules(str(REAL_RULES_PATH))}

    collisions = CORRELATION_ENGINE_RULE_IDS & alerting_rule_ids
    assert not collisions, (
        "Rule id collision between correlation-engine and alerting-engine: "
        f"{sorted(collisions)}"
    )
