#!/usr/bin/env python3
"""
Async Kafka -> S3 (Ceph/MinIO) -> ClamAV scanner with a pool of workers.
Extended with:
- S3 workflow: incoming -> processed / quarantine
- Kafka result contains new S3 path
- S3 retention cleanup
"""

import asyncio
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import clamd
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

# --- Config from env ---
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INPUT_TOPIC = os.getenv("INPUT_TOPIC", "files_to_scan")
OUTPUT_TOPIC = os.getenv("OUTPUT_TOPIC", "scan_results")

S3_ENDPOINT = os.getenv("S3_ENDPOINT_URL", "http://minio:9000")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "minioadmin")
S3_SCAN_RESULT = os.getenv("S3_SCAN_RESULT", "processed")
S3_SCAN_QUARANTINE = os.getenv("S3_SCAN_QUARANTINE", "quarantine")

CLAMD_HOST = os.getenv("CLAMD_HOST", "clamav")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))
CLAMD_DSN = {"host": CLAMD_HOST, "port": CLAMD_PORT}

WORKER_POOL = int(os.getenv("WORKER_POOL", "4"))
MAX_THREADS = int(os.getenv("MAX_THREADS", "8"))

RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "7"))

LOGGER = logging.getLogger(__name__)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOGGER.setLevel(LOG_LEVEL)
logging.basicConfig(level=LOG_LEVEL)

# --- Sync S3 client (used inside threadpool) ---
s3_client = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
)


# ---------------------------------------------------------
#    S3 Scanning Worker (blocking, runs in threadpool)
# ---------------------------------------------------------
def scan_s3_object_blocking(bucket: str, key: str) -> dict[str, Any]:
    """Reads an object from S3 and scans it with clamd.instream."""
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        body = obj["Body"]

        clam = clamd.ClamdNetworkSocket(host=CLAMD_DSN["host"], port=CLAMD_DSN["port"])

        class S3StreamWrapper:
            def __init__(self, stream):
                self.stream = stream

            def read(self, size=-1):
                return self.stream.read(size)

        wrapper = S3StreamWrapper(body)
        result = clam.instream(wrapper)

        if not result:
            return {
                "status": "ERROR",
                "virus": None,
                "details": "No response from clamd",
            }

        if "stream" in result:
            state, info = result["stream"]
        else:
            _, res = next(iter(result.items()))
            state, info = res[0], res[1] if len(res) > 1 else None

        if state == "FOUND":
            return {"status": "INFECTED", "virus": info}
        elif state in ("OK", "SCAN_OK"):
            return {"status": "CLEAN", "virus": None}
        else:
            return {"status": "ERROR", "virus": None, "details": str(result)}

    except Exception as e:
        return {"status": "ERROR", "virus": None, "details": str(e)}


# ---------------------------------------------------------
#   S3 move operation (blocking, threadpool safe)
# ---------------------------------------------------------
def move_s3_object(bucket: str, old_key: str, new_key: str):
    """Moves an S3 object by copy+delete."""
    s3_client.copy_object(
        Bucket=bucket, CopySource={"Bucket": bucket, "Key": old_key}, Key=new_key
    )
    s3_client.delete_object(Bucket=bucket, Key=old_key)


# ---------------------------------------------------------
#   Worker
# ---------------------------------------------------------
async def worker(
    name: int,
    queue: asyncio.Queue,
    producer: AIOKafkaProducer,
    executor: ThreadPoolExecutor,
):
    loop = asyncio.get_running_loop()

    while True:
        payload = await queue.get()

        try:
            now = datetime.now(timezone.utc)
            record_id = payload.get("id")
            bucket = payload.get("bucket")
            key = payload.get("key")

            if not (record_id and bucket and key):
                LOGGER.info(
                    f"[worker-{name}] Missing id/bucket/key -> skipping: {payload}"
                )
                continue

            LOGGER.info(
                f"[worker-{name}] Start scan id={record_id} s3://{bucket}/{key}"
            )

            # -------- SCAN ----------
            scan = await loop.run_in_executor(
                executor, scan_s3_object_blocking, bucket, key
            )

            status = scan["status"]

            # -------- MOVE OBJECT IN S3 ----------
            if status == "CLEAN":
                new_key = f"{S3_SCAN_RESULT}/{key}"
            else:
                new_key = f"{S3_SCAN_QUARANTINE}/{key}"

            await loop.run_in_executor(executor, move_s3_object, bucket, key, new_key)
            finish = datetime.now(timezone.utc)

            # -------- SEND RESULT ----------
            result = {
                "id": record_id,
                "bucket": bucket,
                "key": new_key,
                "status": status,
                "virus": scan.get("virus"),
                "details": scan.get("details", ""),
                "duration": str(finish - now),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            await producer.send_and_wait(
                OUTPUT_TOPIC, json.dumps(result).encode("utf-8")
            )

            LOGGER.info(
                f"[worker-{name}] Scanned {key} → {status} → moved to {new_key}"
            )

        except Exception as e:
            LOGGER.info(f"[worker-{name}] Error: {e}")

        finally:
            queue.task_done()


# ---------------------------------------------------------
#   Kafka Consumer
# ---------------------------------------------------------
async def consume_loop(queue: asyncio.Queue):
    consumer = AIOKafkaConsumer(
        INPUT_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        enable_auto_commit=True,
        group_id="clamav-async-scanner-multi",
    )
    await consumer.start()

    try:
        async for msg in consumer:
            try:
                payload = json.loads(msg.value.decode("utf-8"))
            except Exception:
                LOGGER.info("Invalid message received")
                continue

            await queue.put(payload)

    finally:
        await consumer.stop()


# ---------------------------------------------------------
#   S3 Retention Cleanup
# ---------------------------------------------------------
def cleanup_s3_retention(bucket: str, days: int):
    """Deletes objects older than specified days in the given S3 bucket."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    resp = s3_client.list_objects_v2(Bucket=bucket)

    if "Contents" not in resp:
        return

    for obj in resp["Contents"]:
        key = obj["Key"]
        last_modified = obj["LastModified"]

        if last_modified < cutoff:
            LOGGER.info(f"[retention] Deleting {key} last modified on {last_modified}")
            s3_client.delete_object(Bucket=bucket, Key=key)


async def retention_loop(bucket: str, executor: ThreadPoolExecutor):
    """Periodically cleans up old objects in the specified S3 bucket."""
    while True:
        loop = asyncio.get_running_loop()
        LOGGER.info(f"[{bucket}] Running cleanup…")
        await loop.run_in_executor(
            executor, cleanup_s3_retention, bucket, RETENTION_DAYS
        )
        await asyncio.sleep(3600)  # 1h


# ---------------------------------------------------------
#   MAIN
# ---------------------------------------------------------
async def main():
    queue = asyncio.Queue(maxsize=WORKER_POOL * 2)

    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
    await producer.start()

    executor = ThreadPoolExecutor(max_workers=MAX_THREADS)

    workers = [
        asyncio.create_task(worker(i + 1, queue, producer, executor))
        for i in range(WORKER_POOL)
    ]

    consumer_task = asyncio.create_task(consume_loop(queue))

    # Retention task
    retention_task = asyncio.create_task(retention_loop("quarantine", executor))
    processed_task = asyncio.create_task(retention_loop("processed", executor))

    LOGGER.info(
        f"Scanner multi-worker started: WORKER_POOL={WORKER_POOL} MAX_THREADS={MAX_THREADS}"
    )

    try:
        await consumer_task
    finally:
        for w in workers:
            w.cancel()
        retention_task.cancel()
        processed_task.cancel()
        await producer.stop()
        executor.shutdown(wait=True)


if __name__ == "__main__":
    asyncio.run(main())
