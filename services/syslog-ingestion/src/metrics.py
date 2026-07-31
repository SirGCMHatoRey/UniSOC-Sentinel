"""
Prometheus metrics definitions for the syslog-ingestion service.

All metrics are instantiated once (module-level singleton pattern via the
Metrics dataclass) so they can be imported and incremented from any module
without passing references around.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from prometheus_client import Counter, Gauge, Histogram


@dataclass
class Metrics:
    """
    Container for all Prometheus metric objects used by this service.

    Instantiate exactly once in main.py and pass the instance to every
    component that needs to update counters/gauges.
    """

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------

    packets_received_total: Counter = field(
        default_factory=lambda: Counter(
            "syslog_packets_received_total",
            "Total UDP datagrams received by the syslog listener.",
        )
    )

    packets_dropped_total: Counter = field(
        default_factory=lambda: Counter(
            "syslog_packets_dropped_total",
            "Total UDP datagrams dropped because the internal queue was full.",
        )
    )

    packets_processed_total: Counter = field(
        default_factory=lambda: Counter(
            "syslog_packets_processed_total",
            "Total syslog messages successfully published to the Redis stream.",
        )
    )

    redis_publish_errors_total: Counter = field(
        default_factory=lambda: Counter(
            "syslog_redis_publish_errors_total",
            "Total failures while publishing a message to the Redis stream.",
        )
    )

    # ------------------------------------------------------------------
    # Gauges
    # ------------------------------------------------------------------

    queue_size: Gauge = field(
        default_factory=lambda: Gauge(
            "syslog_queue_size",
            "Current number of messages waiting in the internal asyncio queue.",
        )
    )

    # ------------------------------------------------------------------
    # Histograms
    # ------------------------------------------------------------------

    processing_duration_seconds: Histogram = field(
        default_factory=lambda: Histogram(
            "syslog_processing_duration_seconds",
            "End-to-end latency from UDP receipt to successful Redis publish.",
            buckets=(
                0.001,
                0.005,
                0.010,
                0.025,
                0.050,
                0.100,
                0.250,
                0.500,
                1.0,
                2.5,
                5.0,
                float("inf"),
            ),
        )
    )
