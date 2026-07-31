"""Redis stream consumer and pipeline worker."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

import redis.asyncio as aioredis

from .config import Settings
from .enrichers.geoip import GeoIPEnricher
from .enrichers.mac_vendor import MACVendorEnricher
from .enrichers.threat_intel import ThreatIntelEnricher
from .indexer import OpenSearchIndexer
from .metrics import (
    batch_size_histogram,
    dead_letter_total,
    enrichment_duration_seconds,
    events_consumed_total,
    events_indexed_total,
    events_parsed_total,
    parse_duration_seconds,
)
from .normalizer import to_ecs
from .parsers.base import BaseParser
from .parsers.registry import ParserRegistry

logger = logging.getLogger(__name__)

_INPUT_STREAM = "siem:raw_logs"
_OUTPUT_STREAM = "siem:parsed_logs"
_CONSUMER_GROUP = "siem-parsers"
_MAX_PARSE_RETRIES = 3  # messages that fail N times are dead-lettered


class PipelineWorker:
    """
    Reads from a Redis consumer group, parses + enriches each message,
    publishes to the output stream, and batches events for OpenSearch indexing.
    """

    def __init__(
        self,
        worker_id: int,
        settings: Settings,
        registry: ParserRegistry,
        geoip: GeoIPEnricher,
        threat_intel: ThreatIntelEnricher,
        mac_vendor: MACVendorEnricher,
        indexer: OpenSearchIndexer,
    ) -> None:
        self._worker_id = worker_id
        self._settings = settings
        self._registry = registry
        self._geoip = geoip
        self._threat_intel = threat_intel
        self._mac_vendor = mac_vendor
        self._indexer = indexer

        self._consumer_name = f"parser-{worker_id}"
        self._batch: list[dict] = []
        self._redis: Optional[aioredis.Redis] = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Connect to Redis, ensure consumer group, and start the processing loop."""
        redis_password = self._settings.get_redis_password()
        self._redis = aioredis.Redis(
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            password=redis_password,
            decode_responses=True,
            socket_connect_timeout=10,
            socket_timeout=15,
            retry_on_timeout=True,
        )

        await self._ensure_consumer_group()
        self._running = True
        logger.info("Worker %d started (consumer: %s)", self._worker_id, self._consumer_name)
        await self._run_loop()

    async def stop(self) -> None:
        """Signal the worker to stop gracefully and flush remaining batch."""
        self._running = False
        # Flush accumulated batch before exit
        if self._batch:
            await self._flush_batch()
        if self._redis:
            await self._redis.aclose()
        logger.info("Worker %d stopped", self._worker_id)

    # ------------------------------------------------------------------
    # Consumer group setup
    # ------------------------------------------------------------------

    async def _ensure_consumer_group(self) -> None:
        """Create the consumer group if it doesn't exist (MKSTREAM, start from $)."""
        try:
            await self._redis.xgroup_create(
                name=_INPUT_STREAM,
                groupname=_CONSUMER_GROUP,
                id="$",           # only process messages arriving after group creation
                mkstream=True,    # create the stream if it doesn't exist
            )
            logger.info("Consumer group '%s' created", _CONSUMER_GROUP)
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                logger.debug("Consumer group '%s' already exists — OK", _CONSUMER_GROUP)
            else:
                raise

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _run_loop(self) -> None:
        while self._running:
            try:
                await self._read_and_process()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Worker %d error in main loop: %s", self._worker_id, exc, exc_info=True)
                await asyncio.sleep(1)  # back off briefly on unexpected errors

        # Drain remaining batch on shutdown
        if self._batch:
            await self._flush_batch()

    async def _read_and_process(self) -> None:
        """
        Perform one XREADGROUP call and process all returned messages.
        Blocks up to 5 seconds if the stream is empty.
        """
        results = await self._redis.xreadgroup(
            groupname=_CONSUMER_GROUP,
            consumername=self._consumer_name,
            streams={_INPUT_STREAM: ">"},
            count=self._settings.batch_size,
            block=5000,  # ms
        )
        if not results:
            return

        for _stream, messages in results:
            for msg_id, fields in messages:
                await self._process_message(msg_id, fields)

        # Flush if batch is full
        if len(self._batch) >= self._settings.batch_size:
            await self._flush_batch()

    # ------------------------------------------------------------------
    # Message processing
    # ------------------------------------------------------------------

    async def _process_message(self, msg_id: str, fields: dict[str, str]) -> None:
        """Parse, enrich, normalize, publish, and queue for indexing one message."""
        raw = fields.get("raw", "")
        source_ip = fields.get("source_ip", "")
        received_at_str = fields.get("received_at", "")

        # Parse received_at
        try:
            received_at = datetime.fromisoformat(
                received_at_str.replace("Z", "+00:00")
            ).astimezone(timezone.utc).replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            received_at = datetime.now(timezone.utc)

        # Extract program/hostname for parser selection (best-effort from raw)
        program, hostname = self._extract_program_hostname(raw)

        # Find parser
        parser = self._registry.find_parser(raw, program, hostname)

        if parser is None:
            # No parser matched — dead letter
            logger.warning(
                "No parser for message",
                extra={
                    "msg_id": msg_id,
                    "source_ip": source_ip,
                    "raw": raw[:200],
                },
            )
            dead_letter_total.inc()
            events_consumed_total.labels(dataset="unrecognized").inc()
            await self._ack(msg_id)
            return

        # Parse
        dataset = _guess_dataset(parser)
        events_consumed_total.labels(dataset=dataset).inc()

        t0 = time.perf_counter()
        try:
            parsed = parser.parse(raw, source_ip, received_at)
        except Exception as exc:
            logger.warning("Parser raised exception for msg %s: %s", msg_id, exc)
            parsed = None

        parse_elapsed = time.perf_counter() - t0
        parse_duration_seconds.labels(dataset=dataset).observe(parse_elapsed)

        if parsed is None:
            logger.warning("Parser returned None for msg %s (raw: %.100s)", msg_id, raw)
            events_parsed_total.labels(dataset=dataset, status="failed").inc()
            dead_letter_total.inc()
            await self._ack(msg_id)
            return

        events_parsed_total.labels(dataset=parsed.dataset, status="success").inc()

        # Enrich
        geo = await self._enrich_geoip(parsed.source_ip)
        threat = await self._enrich_threat(parsed.source_ip)
        mac_vendor_info = await self._enrich_mac(parsed.source_mac)
        mac_vendor_str = mac_vendor_info.get("vendor") if mac_vendor_info else None

        # Normalize → ECS
        ecs_event = to_ecs(parsed, geo=geo, threat=threat, mac_vendor=mac_vendor_str)

        # Publish to output stream
        await self._publish(ecs_event)

        # Accumulate for bulk indexing
        self._batch.append(ecs_event)

        # ACK the input message
        await self._ack(msg_id)

    def _extract_program_hostname(self, raw: str) -> tuple[Optional[str], Optional[str]]:
        """Quick extraction of syslog program and hostname without full parsing."""
        import re
        # RFC 3164 hostname program[pid]: pattern
        m = re.match(
            r"^(?:<\d+>)?(?:\S+ +\S+ +\S+ +)?(?P<host>\S+)\s+(?P<prog>[a-zA-Z0-9_\-]+)(?:\[\d+\])?:",
            raw,
        )
        if m:
            return m.group("prog").lower(), m.group("host")
        return None, None

    # ------------------------------------------------------------------
    # Enrichment helpers
    # ------------------------------------------------------------------

    async def _enrich_geoip(self, ip: Optional[str]) -> Optional[dict]:
        if not ip:
            return None
        t0 = time.perf_counter()
        try:
            result = await self._geoip.enrich(ip)
        except Exception:
            result = None
        enrichment_duration_seconds.labels(enricher="geoip").observe(time.perf_counter() - t0)
        return result

    async def _enrich_threat(self, ip: Optional[str]) -> Optional[dict]:
        if not ip:
            return {"matched": False, "feed": None, "score": 0}
        t0 = time.perf_counter()
        try:
            result = await self._threat_intel.enrich(ip)
        except Exception:
            result = {"matched": False, "feed": None, "score": 0}
        enrichment_duration_seconds.labels(enricher="threat_intel").observe(time.perf_counter() - t0)
        return result

    async def _enrich_mac(self, mac: Optional[str]) -> Optional[dict]:
        if not mac:
            return None
        t0 = time.perf_counter()
        try:
            result = await self._mac_vendor.enrich(mac)
        except Exception:
            result = None
        enrichment_duration_seconds.labels(enricher="mac_vendor").observe(time.perf_counter() - t0)
        return result

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    async def _ack(self, msg_id: str) -> None:
        try:
            await self._redis.xack(_INPUT_STREAM, _CONSUMER_GROUP, msg_id)
        except Exception as exc:
            logger.warning("Failed to XACK message %s: %s", msg_id, exc)

    async def _publish(self, ecs_event: dict) -> None:
        try:
            payload = json.dumps(ecs_event, default=str)
            await self._redis.xadd(_OUTPUT_STREAM, {"event": payload})
        except Exception as exc:
            logger.warning("Failed to publish to %s: %s", _OUTPUT_STREAM, exc)

    # ------------------------------------------------------------------
    # Batch flushing
    # ------------------------------------------------------------------

    async def _flush_batch(self) -> None:
        if not self._batch:
            return

        batch = self._batch
        self._batch = []

        batch_size_histogram.observe(len(batch))

        try:
            success, failed = await self._indexer.bulk_index(batch)
            events_indexed_total.labels(status="success").inc(success)
            if failed:
                events_indexed_total.labels(status="failed").inc(failed)
        except Exception as exc:
            logger.error("Bulk index error: %s", exc)
            events_indexed_total.labels(status="failed").inc(len(batch))


def _guess_dataset(parser: BaseParser) -> str:
    """Infer a dataset label from the parser class name for metrics."""
    name = type(parser).__name__.lower().replace("parser", "")
    return f"unifi.{name}" if name else "unifi.unknown"
