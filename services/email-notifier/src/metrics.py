"""
Prometheus metrics definitions for the email-notifier service.

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

    emails_sent_total: Counter = field(
        default_factory=lambda: Counter(
            "notifier_emails_sent_total",
            "Total number of alert emails successfully delivered.",
            ["rule_id"],
        )
    )

    email_errors_total: Counter = field(
        default_factory=lambda: Counter(
            "notifier_email_errors_total",
            "Total number of email send failures after all retry attempts.",
        )
    )

    # ------------------------------------------------------------------
    # Histograms
    # ------------------------------------------------------------------

    email_send_duration_seconds: Histogram = field(
        default_factory=lambda: Histogram(
            "notifier_email_send_duration_seconds",
            "End-to-end time to send an email including retries.",
            buckets=(
                0.1,
                0.25,
                0.5,
                1.0,
                2.0,
                5.0,
                10.0,
                30.0,
                60.0,
                float("inf"),
            ),
        )
    )
