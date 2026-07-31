"""
UDP syslog listener built on asyncio.DatagramProtocol.

The listener never blocks the event loop: if the internal queue is full,
the datagram is silently dropped and the dropped counter is incremented.
This ensures the UDP receive path always returns immediately regardless of
downstream pressure.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Tuple

import structlog

from .config import Settings
from .metrics import Metrics

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class SyslogProtocol(asyncio.DatagramProtocol):
    """
    asyncio DatagramProtocol that receives raw UDP syslog datagrams and
    enqueues them for processing by the worker pool.

    Thread-safety note: asyncio guarantees that datagram_received is called
    sequentially on the event loop thread, so no locking is required for
    queue.put_nowait().
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        metrics: Metrics,
        settings: Settings,
    ) -> None:
        self._queue = queue
        self._metrics = metrics
        self._settings = settings
        self._transport: asyncio.DatagramTransport | None = None

    # ------------------------------------------------------------------
    # DatagramProtocol interface
    # ------------------------------------------------------------------

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport
        local = transport.get_extra_info("sockname", ("?", "?"))
        log.info(
            "UDP socket ready",
            host=local[0],
            port=local[1],
        )

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Called by asyncio for each incoming UDP datagram.

        Processing steps:
        1. Increment received counter.
        2. Extract source IP from addr tuple.
        3. Decode bytes (UTF-8 with latin-1 fallback).
        4. Strip null bytes and surrounding whitespace.
        5. Enqueue without blocking; drop if queue is full.
        """
        self._metrics.packets_received_total.inc()

        source_ip = addr[0] if addr else "unknown"

        try:
            # Attempt UTF-8 first; syslog messages are usually ASCII-safe
            try:
                raw_text = data.decode("utf-8")
            except UnicodeDecodeError:
                raw_text = data.decode("latin-1")

            # Remove embedded null bytes (e.g. from BSD syslog framing)
            raw_text = raw_text.replace("\x00", "").strip()

            if not raw_text:
                log.debug("Received empty datagram after stripping", source_ip=source_ip)
                return

            item = (raw_text, source_ip)

            try:
                self._queue.put_nowait(item)
            except asyncio.QueueFull:
                self._metrics.packets_dropped_total.inc()
                log.warning(
                    "Queue full — dropping datagram",
                    source_ip=source_ip,
                    queue_maxsize=self._queue.maxsize,
                )

        except Exception:  # noqa: BLE001 — never let a bad datagram crash the listener
            log.exception(
                "Unexpected error processing datagram",
                source_ip=source_ip,
                data_length=len(data),
            )

    def error_received(self, exc: Exception) -> None:
        """Called when a send or receive operation raises an OS-level error."""
        log.warning("UDP socket error received", exc=str(exc))

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when the UDP socket is closed."""
        if exc is not None:
            log.warning("UDP connection lost with error", exc=str(exc))
        else:
            log.info("UDP socket closed cleanly")


class UDPListener:
    """
    Manages the lifecycle of the asyncio UDP datagram endpoint.

    Usage::

        listener = UDPListener(queue, metrics, settings)
        await listener.start()
        ...
        await listener.stop()
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        metrics: Metrics,
        settings: Settings,
    ) -> None:
        self._queue = queue
        self._metrics = metrics
        self._settings = settings
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: SyslogProtocol | None = None

    async def start(self) -> None:
        """Bind the UDP socket and begin receiving datagrams."""
        loop = asyncio.get_running_loop()

        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(self._queue, self._metrics, self._settings),
            local_addr=(self._settings.listen_host, self._settings.listen_port),
        )

        log.info(
            "UDP listener started",
            host=self._settings.listen_host,
            port=self._settings.listen_port,
        )

    async def stop(self) -> None:
        """Close the UDP socket, stopping receipt of new datagrams."""
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()
            log.info("UDP listener stopped")
        self._transport = None
        self._protocol = None
