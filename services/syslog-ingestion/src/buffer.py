"""
Worker pool that drains the internal asyncio queue and publishes each
syslog message to Redis via RedisPublisher.

Design goals:
- N concurrent coroutines share the same asyncio.Queue (no lock needed).
- On graceful shutdown, workers finish processing items already in the
  queue before exiting (drain semantics).
- If RedisPublisher.publish() raises after exhausting its own retries,
  the worker logs the failure, updates the error counter, and moves on
  to the next message — it never crashes the worker loop.
"""

from __future__ import annotations

import asyncio
import time
from typing import List

import structlog

from .metrics import Metrics
from .publisher import RedisPublisher

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class WorkerPool:
    """
    Pool of N async worker coroutines that consume (raw_message, source_ip)
    tuples from an asyncio.Queue and publish them to the Redis stream.

    Lifecycle::

        pool = WorkerPool(queue, publisher, metrics, worker_count=4)
        await pool.start()
        ...
        await pool.stop()   # waits for queue to drain
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        publisher: RedisPublisher,
        metrics: Metrics,
        worker_count: int = 4,
    ) -> None:
        self._queue = queue
        self._publisher = publisher
        self._metrics = metrics
        self._worker_count = worker_count
        self._tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Spawn N worker coroutines and return immediately."""
        self._shutdown_event.clear()
        self._tasks = [
            asyncio.create_task(
                self._worker(worker_id=i),
                name=f"syslog-worker-{i}",
            )
            for i in range(self._worker_count)
        ]
        log.info("Worker pool started", worker_count=self._worker_count)

    async def stop(self) -> None:
        """
        Signal workers to stop accepting new items, then wait for the queue
        to drain completely before cancelling the worker tasks.

        The drain timeout is intentionally generous (30 s) to handle bursts
        that arrived just before the shutdown signal.
        """
        log.info(
            "Worker pool shutting down — draining queue",
            remaining=self._queue.qsize(),
        )

        # Signal workers to exit after the queue is empty
        self._shutdown_event.set()

        # Wait for queue to drain (workers call task_done after each item)
        try:
            await asyncio.wait_for(self._queue.join(), timeout=30.0)
            log.info("Queue drained successfully")
        except asyncio.TimeoutError:
            log.warning(
                "Drain timeout reached — some messages may be lost",
                remaining=self._queue.qsize(),
            )

        # Cancel any workers still running (they should be idle by now)
        for task in self._tasks:
            if not task.done():
                task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        self._tasks.clear()
        log.info("Worker pool stopped")

    # ------------------------------------------------------------------
    # Internal worker coroutine
    # ------------------------------------------------------------------

    async def _worker(self, worker_id: int) -> None:
        """
        Main loop for a single worker coroutine.

        The worker blocks on queue.get() and exits when the shutdown event
        is set AND the queue is empty.
        """
        log.debug("Worker started", worker_id=worker_id)

        while True:
            # Check shutdown condition: stop only when the queue is empty
            if self._shutdown_event.is_set() and self._queue.empty():
                log.debug("Worker exiting — shutdown signalled and queue empty", worker_id=worker_id)
                break

            try:
                # Use a short timeout so workers periodically check the
                # shutdown event even when the queue is quiescent.
                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    # No item available; loop back to check shutdown
                    continue

            except asyncio.CancelledError:
                log.debug("Worker cancelled", worker_id=worker_id)
                break

            raw_message, source_ip = item
            t_start = time.monotonic()

            try:
                await self._publisher.publish(raw_message, source_ip)
            except Exception as exc:  # noqa: BLE001
                # publisher already incremented the error counter and logged
                log.error(
                    "Worker discarding message after publish failure",
                    worker_id=worker_id,
                    source_ip=source_ip,
                    error=str(exc),
                )
            finally:
                # Always mark the task done so queue.join() can complete
                self._queue.task_done()

                # Update the queue size gauge and processing duration histogram
                self._metrics.queue_size.set(self._queue.qsize())
                duration = time.monotonic() - t_start
                self._metrics.processing_duration_seconds.observe(duration)

        log.debug("Worker finished", worker_id=worker_id)
