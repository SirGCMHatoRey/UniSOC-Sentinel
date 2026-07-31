"""
Prometheus metrics definitions for the alerting-engine service.

All metrics are instantiated once (module-level singleton pattern via the
Metrics dataclass) so they can be imported and incremented from any module
without passing references around.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from prometheus_client import Counter, Histogram


@dataclass
class Metrics:
    """
    Container for all Prometheus metric objects used by this service.

    Instantiate exactly once in main.py and pass the instance to every
    component that needs to update counters/histograms.
    """

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------

    rules_evaluated_total: Counter = field(
        default_factory=lambda: Counter(
            "alerting_rules_evaluated_total",
            "Total number of rule evaluations performed.",
            ["rule_id"],
        )
    )

    alerts_triggered_total: Counter = field(
        default_factory=lambda: Counter(
            "alerting_alerts_triggered_total",
            "Total number of alerts that crossed the threshold and were not suppressed.",
            ["rule_id", "severity"],
        )
    )

    alerts_deduplicated_total: Counter = field(
        default_factory=lambda: Counter(
            "alerting_alerts_deduplicated_total",
            "Total number of alerts suppressed by the deduplication key.",
            ["rule_id"],
        )
    )

    alerts_throttled_total: Counter = field(
        default_factory=lambda: Counter(
            "alerting_alerts_throttled_total",
            "Total number of alerts suppressed by the per-rule throttle window.",
            ["rule_id"],
        )
    )

    events_consumed_total: Counter = field(
        default_factory=lambda: Counter(
            "alerting_events_consumed_total",
            "Total number of events read from the Redis stream.",
        )
    )

    # ------------------------------------------------------------------
    # Histograms
    # ------------------------------------------------------------------

    rule_evaluation_duration_seconds: Histogram = field(
        default_factory=lambda: Histogram(
            "alerting_rule_evaluation_duration_seconds",
            "Time spent evaluating a single rule against one event.",
            ["rule_id"],
            buckets=(
                0.0001,
                0.0005,
                0.001,
                0.005,
                0.010,
                0.025,
                0.050,
                0.100,
                0.250,
                0.500,
                1.0,
                float("inf"),
            ),
        )
    )
