#!/usr/bin/env python3
import asyncio
import json
import time

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from const import (
    BASE_DELAY,
    CLAMD_CNX_TIMEOUT,
    CLAMD_HOSTS,
    CLAMD_RETRY,
    KAFKA_LOG_RETENTION_MS,
    KAFKA_SERVERS,
    KAFKA_TOPIC,
    REDIS_LOCK_TIMEOUT,
    REDIS_URL,
    S3_ACCESS_KEY,
    S3_BUCKET,
    S3_ENDPOINT,
    S3_SCAN_QUARANTINE,
    S3_SCAN_RESULT,
    S3_SECRET_KEY,
    WORKER_POOL,
)
from helpers import ScanResult, retry_async
from monitor import Monitor
from mylogging import mylogging
from storage import (
    ClamAVException,
    ClamAVFailedAll,
    S3LockException,
    S3MoveException,
    S3Storage,
    S3UnlockException,
)

logger = mylogging.getLogger("scanav")


# ----------------- WORKER -----------------
async def worker(
    name: int,
    queue: asyncio.Queue,
    producer: AIOKafkaProducer,
    storage: S3Storage,
    monitor: Monitor,
) -> None:
    """
    Worker that selects the best host adaptively, performs scan, updates stats and moves object.
    """
    while True:
        payload = await queue.get()
        try:
            # start_timestamp = datetime.now().timestamp()
            bucket = payload["bucket"]
            key = payload["key"]

            logger.info(f"[worker-{name}] Start scan {key}")

            # Acquire lock
            if not await storage.acquire_s3_lock(key, bucket):
                logger.warning(f"[worker-{name}] File locked, skipping {key}")
                queue.task_done()
                continue

            # Scan file using adaptive selection
            attempt = 0
            last_exception = None
            while attempt < CLAMD_RETRY:
                attempt += 1
                # choose best host
                host, port, host_key = await monitor.select_best_host()

                # mark busy
                await monitor.mark_host_busy(host_key)
                scan_start = time.monotonic()
                try:
                    scan = await storage.scan_s3_object_async(key, bucket, host, port)
                except ClamAVException as e:
                    elapsed = time.monotonic() - scan_start
                    # mark done with failure (no elapsed update)
                    await monitor.mark_host_done(host_key, elapsed=None, success=False)
                    logger.warning(
                        f"[worker-{name}] ClamAV attempt failed on {host_key}: {e} (attempt {attempt})"
                    )
                    last_exception = e
                    # small backoff before next attempt
                    await asyncio.sleep(BASE_DELAY * (2 ** (attempt - 1)))
                    continue
                else:
                    elapsed = time.monotonic() - scan_start
                    # success or deterministic error from engine -> mark done success if CLEAN/INFECTED, else success False
                    await monitor.mark_host_done(
                        host_key, elapsed=elapsed, success=True
                    )
                    break  # exit retry loop

            else:
                # exhausted retries
                logger.error(
                    f"[worker-{name}] All CLAMD attempts failed for {key}: {last_exception}"
                )
                raise ClamAVFailedAll(last_exception)

            # move object according to result if scan succeeded (or even on ERROR we may want to move to quarantine)
            target = (
                f"{S3_SCAN_RESULT}/{key}"
                if scan.status == "CLEAN"
                else f"{S3_SCAN_QUARANTINE}/{key}"
            )
            await storage.move_s3_object_async(key, bucket, target, scan)

            logger.info(f"[worker-{name}] Scanned {key} → {scan.status}")

            # release S3 lock
            await storage.release_s3_lock(key, bucket)

        except S3LockException as e:
            logger.error(f"[worker-{name}] Lock error: {e}")

        except S3MoveException as e:
            logger.error(f"[worker-{name}] Move error: {e}")

        except S3UnlockException as e:
            logger.error(f"[worker-{name}] Unlock error: {e}")

        except Exception as e:
            logger.error(f"[worker-{name}] Error: {e}")

        else:
            # Trigger webhooks for this file_id
            metadata = await storage.get_s3_metadata(key=key, bucket=bucket)
            result = ScanResult(
                key=key,
                bucket=bucket,
                status=scan.status,
                virus=scan.virus,
                detail=scan.details,
            )
            if url := metadata.get("Webhook"):
                asyncio.create_task(
                    retry_async(
                        storage.call_webhook_and_remove(key, url, result.model_dump())
                    )
                )

        finally:
            queue.task_done()


# ----------------- CONSUMER -----------------
async def consume_loop(queue: asyncio.Queue):
    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,  # type: ignore
        group_id="scanner-group",
        enable_auto_commit=True,
    )
    await consumer.start()
    try:
        async for msg in consumer:
            if msg.value is None:
                continue
            payload = json.loads(msg.value.decode("utf-8"))
            await queue.put(payload)
    finally:
        await consumer.stop()


# ----------------- CLEANUP TASKS -----------------
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
        # Wait 12 hours before next cleanup
        await asyncio.sleep(KAFKA_LOG_RETENTION_MS / 1000 / 2)


# ----------------- MAIN -----------------
async def main():
    queue = asyncio.Queue(maxsize=WORKER_POOL * 2)
    monitor = Monitor(CLAMD_HOSTS)
    storage = S3Storage(
        S3_ENDPOINT,
        S3_ACCESS_KEY,
        S3_SECRET_KEY,
        REDIS_URL,
        REDIS_LOCK_TIMEOUT,
        CLAMD_CNX_TIMEOUT,
    )

    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_SERVERS)  # type: ignore
    await producer.start()

    asyncio.create_task(monitor.reset_host_failures_periodically())
    asyncio.create_task(periodic_cleanup_task(storage))

    workers = [
        asyncio.create_task(worker(i + 1, queue, producer, storage, monitor))
        for i in range(WORKER_POOL)
    ]

    consumer_task = asyncio.create_task(consume_loop(queue))

    try:
        await consumer_task
    finally:
        for w in workers:
            w.cancel()
        await producer.stop()
        await storage.async_close()


if __name__ == "__main__":
    asyncio.run(main())
