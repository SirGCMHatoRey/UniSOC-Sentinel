"""Prometheus metrics for the parser-pipeline service."""
from __future__ import annotations

from prometheus_client import Counter, Histogram, REGISTRY

# ---------------------------------------------------------------------------
# Consumption
# ---------------------------------------------------------------------------
events_consumed_total = Counter(
    "parser_pipeline_events_consumed_total",
    "Total number of events consumed from the Redis stream",
    labelnames=["dataset"],
)

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
events_parsed_total = Counter(
    "parser_pipeline_events_parsed_total",
    "Total number of events processed by the parser stage",
    labelnames=["dataset", "status"],  # status: success | failed
)

parse_duration_seconds = Histogram(
    "parser_pipeline_parse_duration_seconds",
    "Time spent parsing a single log line",
    labelnames=["dataset"],
    buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5),
)

# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------
enrichment_duration_seconds = Histogram(
    "parser_pipeline_enrichment_duration_seconds",
    "Time spent in each enricher",
    labelnames=["enricher"],
    buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5),
)

# ---------------------------------------------------------------------------
# Indexing
# ---------------------------------------------------------------------------
events_indexed_total = Counter(
    "parser_pipeline_events_indexed_total",
    "Total number of events sent to OpenSearch",
    labelnames=["status"],  # status: success | failed
)

batch_size_histogram = Histogram(
    "parser_pipeline_batch_size",
    "Distribution of bulk-index batch sizes",
    buckets=(1, 5, 10, 25, 50, 75, 100, 150, 200),
)

# ---------------------------------------------------------------------------
# Dead letter
# ---------------------------------------------------------------------------
dead_letter_total = Counter(
    "parser_pipeline_dead_letter_total",
    "Total number of unparseable messages moved to dead-letter / discarded",
)
