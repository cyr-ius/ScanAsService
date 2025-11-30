#!/usr/bin/env python3
import asyncio
import json
import time
from datetime import datetime

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from const import (
    BASE_DELAY,
    CLAMD_CNX_TIMEOUT,
    CLAMD_HOSTS,
    CLAMD_RETRY,
    KAFKA_INPUT_TOPIC,
    KAFKA_LOG_RETENTION_MS,
    KAFKA_OUTPUT_TOPIC,
    KAFKA_SERVERS,
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
from helpers import ScanResult
from monitor import Monitor
from mylogging import mylogging
from storage import (
    ClamAVException,
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
            start_timestamp = datetime.now().timestamp()
            record_id = payload["id"]
            bucket = payload["bucket"]
            key = payload["key"]
            original_filename = payload.get("original_filename")
            status = "PENDING"
            virus = None
            instance = None
            detail = None
            analyse = None

            logger.info(f"[worker-{name}] Start scan {key}")

            # Acquire lock
            try:
                if not await storage.acquire_s3_lock(bucket, key):
                    logger.warning(f"[worker-{name}] File locked, skipping {key}")
                    queue.task_done()
                    continue
            except S3LockException as e:
                logger.error(f"[worker-{name}] Lock error: {e}")
                status = "ERROR"
                detail = f"lock-error:{e}"

            # Scan file using adaptive selection
            if status != "ERROR":
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
                        scan = await storage.scan_s3_object_async(
                            record_id, bucket, key, host, port
                        )
                    except ClamAVException as e:
                        elapsed = time.monotonic() - scan_start
                        # mark done with failure (no elapsed update)
                        await monitor.mark_host_done(
                            host_key, elapsed=None, success=False
                        )
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
                        if scan.status in ("CLEAN", "INFECTED"):
                            await monitor.mark_host_done(
                                host_key, elapsed=elapsed, success=True
                            )
                        else:
                            # engine returned ERROR -> treat as success (we received a response) but don't count as success for avg maybe?
                            await monitor.mark_host_done(
                                host_key, elapsed=elapsed, success=True
                            )
                        # set results
                        status = scan.status
                        detail = scan.details
                        virus = scan.virus
                        instance = scan.instance
                        analyse = scan.analyse
                        break  # exit retry loop

                else:
                    # exhausted retries
                    logger.error(
                        f"[worker-{name}] All CLAMD attempts failed for {key}: {last_exception}"
                    )
                    status = "ERROR"
                    detail = f"clamd-unreachable:{last_exception}"

                # move object according to result if scan succeeded (or even on ERROR we may want to move to quarantine)
                if status != "PENDING":
                    new_key = (
                        f"{S3_SCAN_RESULT}/{key}"
                        if status == "CLEAN"
                        else f"{S3_SCAN_QUARANTINE}/{key}"
                    )
                    try:
                        await storage.move_s3_object_async(bucket, key, new_key)
                    except S3MoveException as e:
                        logger.error(f"[worker-{name}] Move error: {e}")
                        status = "ERROR"
                        detail = f"move-error:{e}"
                    else:
                        key = new_key
                        logger.info(f"[worker-{name}] Scanned {key} → {status}")

            # release S3 lock
            try:
                await storage.release_s3_lock(bucket, key)
            except S3UnlockException as e:
                logger.error(f"[worker-{name}] Unlock error: {e}")
                status = "ERROR"
                detail = f"unlock-error:{e}"

        except Exception as e:
            logger.error(f"[worker-{name}] Error: {e}")
            status = "ERROR"
            detail = f"worker-error:{e}"

        else:
            # publish result
            result = ScanResult(
                id=record_id,
                bucket=bucket,
                key=key,
                status=status,
                virus=virus,
                analyse=analyse,
                details=detail,
                original_filename=original_filename,
                instance=instance,
                timestamp=datetime.now(),
                duration=round(datetime.now().timestamp() - start_timestamp, 3),
                worker=f"worker-{name}",
            )

            # Trigger webhooks for this file_id
            data = await storage.redis_client.get("scan_webhooks")
            hooks = json.loads(data) if data else {}
            for url in hooks.get(record_id, []):
                asyncio.create_task(
                    storage.call_webhook_and_remove(record_id, url, result.model_dump())
                )

            try:
                await producer.send_and_wait(
                    KAFKA_OUTPUT_TOPIC, result.model_dump_json().encode("utf-8")
                )
            except Exception as e:
                logger.error(f"[{result.worker}][{result.id}] Kafka error: {e}")

        finally:
            queue.task_done()


# ----------------- CONSUMER -----------------
async def consume_loop(queue: asyncio.Queue):
    consumer = AIOKafkaConsumer(
        KAFKA_INPUT_TOPIC,
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
