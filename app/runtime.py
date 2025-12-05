#!/usr/bin/env python3
import asyncio
import json
import time
from collections.abc import Awaitable
from typing import Any, Dict

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from const import (
    BASE_DELAY,
    CLAMD_CNX_TIMEOUT,
    CLAMD_HOSTS,
    KAFKA_LOG_RETENTION_MS,
    KAFKA_SERVERS,
    KAFKA_TOPIC,
    KAFKAT_STATS,
    MAX_CONCURRENT_SCANS,
    RETRY,
    S3_ACCESS_KEY,
    S3_BUCKET,
    S3_ENDPOINT,
    S3_SCAN_QUARANTINE,
    S3_SCAN_RESULT,
    S3_SECRET_KEY,
)
from helpers import ClamAVResult, ScanResult, retry
from monitor import Monitor
from mylogging import mylogging
from storage import (
    ClamAVException,
    ClamAVFailedAll,
    S3BucketKeyException,
    S3LockException,
    S3MoveException,
    S3Storage,
)

logger = mylogging.getLogger("scanav")

# Limit max concurrent scans
scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


# ----------------- UTILITIES -----------------
def fire_and_forget(coro: Awaitable[None]):
    """Run an async task in background and log exceptions."""

    async def wrapper():
        try:
            await coro
        except Exception as e:
            logger.error("Background task failed: %s", e)

    asyncio.create_task(wrapper())


# ----------------- WORKER -----------------
@retry(
    exceptions=(S3LockException, S3MoveException, ClamAVFailedAll),
    tries=RETRY,
    delay=BASE_DELAY,
)
async def worker(
    worker_id: str,
    storage: S3Storage,
    monitor: Monitor,
    payload: Dict[str, Any],
    producer: AIOKafkaProducer,
) -> None:
    """Worker that selects the best host adaptively, performs scan, updates stats and moves object."""
    async with scan_semaphore:
        try:
            logger.info(f"[worker-{worker_id}] Start scan.")
            start_time = time.monotonic()

            # Extract object key, bucket and metadata
            try:
                key, bucket, metadata = storage.bucket_key(payload)
            except S3BucketKeyException as e:
                logger.error(f"[worker-{worker_id}] bucket/key not found: {e}")
                return

            metadata = metadata or {}

            attempt = 0
            last_exception = None

            while attempt < RETRY:
                attempt += 1
                host, port, host_key = await monitor.select_best_host()
                await monitor.mark_host_busy(host_key)
                scan_start = time.monotonic()

                try:
                    scan = await storage.scan_s3_object_async(key, bucket, host, port)
                except ClamAVException as e:
                    await monitor.mark_host_done(host_key, elapsed=None, success=False)
                    last_exception = e
                    logger.warning(
                        f"[worker-{worker_id}] ClamAV attempt failed on {host_key}: {e} (attempt {attempt})"
                    )
                    await asyncio.sleep(BASE_DELAY * (2 ** (attempt - 1)))
                    continue
                else:
                    elapsed = time.monotonic() - scan_start
                    await monitor.mark_host_done(
                        host_key, elapsed=elapsed, success=True
                    )
                    break
            else:
                logger.error(
                    f"[worker-{worker_id}] All CLAMD attempts failed for {key}: {last_exception}"
                )
                raise ClamAVFailedAll(last_exception)

            # Move object based on scan result
            target = (
                f"{S3_SCAN_RESULT}/{key}"
                if scan.status == "CLEAN"
                else f"{S3_SCAN_QUARANTINE}/{key}"
            )

            duration = time.monotonic() - start_time
            scan = scan or ClamAVResult()
            result = ScanResult(
                bucet=bucket, worker=worker_id, duration=duration, **scan.model_dump()
            )
            await storage.move_s3_object_async(key, bucket, target, result)
            logger.info(f"[worker-{worker_id}] Scanned {key} → {scan.status}")

        finally:
            await producer.send_and_wait(
                KAFKA_TOPIC, value=result.model_dump_json().encode("utf-8")
            )
            await producer.send_and_wait(
                KAFKAT_STATS,
                value=json.dumps(
                    {**storage.statistics, "monitor": monitor.statistics}
                ).encode("utf-8"),
            )

            # Fire webhook if present
            if (
                metadata
                and (url := metadata.get("X-Amz-Meta-Webhook"))
                and scan is not None
            ):
                fire_and_forget(
                    storage.call_webhook_and_remove(key, url, result.model_dump_json())
                )


# ----------------- CONSUMER -----------------
async def consume_loop(
    producer: AIOKafkaProducer, storage: S3Storage, monitor: Monitor
):
    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,  # type: ignore
        group_id="scanner-group",
        enable_auto_commit=True,
    )
    await consumer.start()
    try:
        async for msg in consumer:
            if not msg.value:
                continue
            payload = json.loads(msg.value.decode("utf-8"))
            logger.debug("Kafka payload: %s", payload)
            if (key := payload.get("Key")) and payload.get(
                "EventName"
            ) == "s3:ObjectCreated:Put":
                # Use key as worker_id
                asyncio.create_task(worker(key, storage, monitor, payload, producer))
    finally:
        await consumer.stop()


# ----------------- CLEANUP TASK -----------------
async def periodic_cleanup_task(storage: S3Storage) -> None:
    """Run cleanup periodically."""
    while True:
        try:
            await storage.cleanup_s3_folder(
                S3_BUCKET, S3_SCAN_QUARANTINE, older_than_ms=KAFKA_LOG_RETENTION_MS
            )
            await storage.cleanup_s3_folder(
                S3_BUCKET, S3_SCAN_RESULT, older_than_ms=KAFKA_LOG_RETENTION_MS
            )
        except Exception as e:
            logger.exception(f"[task-cleanup] Cleanup task error: {e}")
        await asyncio.sleep(KAFKA_LOG_RETENTION_MS / 1000 / 2)


# ----------------- MAIN -----------------
async def main():
    monitor = Monitor(CLAMD_HOSTS)
    storage = S3Storage(
        S3_ENDPOINT,
        S3_ACCESS_KEY,
        S3_SECRET_KEY,
        CLAMD_CNX_TIMEOUT,
    )

    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_SERVERS)  # type: ignore
    await producer.start()

    asyncio.create_task(monitor.reset_host_failures_periodically())
    asyncio.create_task(periodic_cleanup_task(storage))

    consumer_task = asyncio.create_task(consume_loop(producer, storage, monitor))

    try:
        await consumer_task
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
