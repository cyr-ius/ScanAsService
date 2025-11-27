#!/usr/bin/env python3
import asyncio
import io
import json
import os
from datetime import datetime, timezone
from typing import Any

import clamd
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

# --- Config ---
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "192.168.1.1:9092")
INPUT_TOPIC = os.getenv("INPUT_TOPIC", "files_to_scan")
OUTPUT_TOPIC = os.getenv("OUTPUT_TOPIC", "scan_results")

S3_ENDPOINT = os.getenv("S3_ENDPOINT_URL", "http://minio:9000")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "minioadmin")
S3_SCAN_RESULT = os.getenv("S3_SCAN_RESULT", "processed")
S3_SCAN_QUARANTINE = os.getenv("S3_SCAN_QUARANTINE", "quarantine")

CLAMD_HOST = os.getenv("CLAMD_HOST", "clamav")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))

WORKER_POOL = int(os.getenv("WORKER_POOL", "4"))

# --- aiobotocore session ---
from aiobotocore.session import get_session

session = get_session()


# ---------------------------------------------------------
#   ClamAV client
# ---------------------------------------------------------
def get_clamav_client() -> clamd.ClamdNetworkSocket:
    return clamd.ClamdNetworkSocket(host=CLAMD_HOST, port=CLAMD_PORT)


# ---------------------------------------------------------
#   Async S3 + ClamAV scan
# ---------------------------------------------------------
async def scan_s3_object_async(bucket: str, key: str) -> dict[str, Any]:
    """
    Streams an S3 object asynchronously and scans it with ClamAV using BytesIO.
    """
    try:
        async with session.create_client(
            "s3",
            endpoint_url=S3_ENDPOINT,
            aws_access_key_id=S3_ACCESS_KEY,
            aws_secret_access_key=S3_SECRET_KEY,
        ) as client:
            resp = await client.get_object(Bucket=bucket, Key=key)
            body = resp["Body"]

            chunks = []
            while True:
                chunk = await body.read(1024 * 1024)  # 1 MB
                if not chunk:
                    break
                chunks.append(chunk)

            buffer = io.BytesIO(b"".join(chunks))
            clam = get_clamav_client()
            result = clam.instream(buffer)

            if not result:
                return {
                    "status": "ERROR",
                    "virus": None,
                    "details": "No response from ClamAV",
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
#   Async S3 move
# ---------------------------------------------------------
async def move_s3_object_async(bucket: str, old_key: str, new_key: str):
    async with session.create_client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
    ) as client:
        await client.copy_object(
            Bucket=bucket, CopySource={"Bucket": bucket, "Key": old_key}, Key=new_key
        )
        await client.delete_object(Bucket=bucket, Key=old_key)


# ---------------------------------------------------------
#   Worker
# ---------------------------------------------------------
async def worker(name: int, queue: asyncio.Queue, producer: AIOKafkaProducer):
    while True:
        payload = await queue.get()
        try:
            record_id = payload.get("id")
            bucket = payload.get("bucket")
            key = payload.get("key")

            if not (record_id and bucket and key):
                print(f"[worker-{name}] Missing id/bucket/key -> skipping: {payload}")
                continue

            print(f"[worker-{name}] Start scan id={record_id} s3://{bucket}/{key}")

            # -------- SCAN ----------
            scan = await scan_s3_object_async(bucket, key)
            status = scan["status"]

            # -------- MOVE OBJECT IN S3 ----------
            if status == "CLEAN":
                new_key = f"{S3_SCAN_RESULT}/{key}"
            else:
                new_key = f"{S3_SCAN_QUARANTINE}/{key}"

            await move_s3_object_async(bucket, key, new_key)

            # -------- SEND RESULT ----------
            result = {
                "id": record_id,
                "bucket": bucket,
                "key": new_key,
                "status": status,
                "virus": scan.get("virus"),
                "details": scan.get("details", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            await producer.send_and_wait(
                OUTPUT_TOPIC, json.dumps(result).encode("utf-8")
            )
            print(f"[worker-{name}] Scanned {key} → {status} → moved to {new_key}")

        except Exception as e:
            print(f"[worker-{name}] Error: {e}")
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
    print("Kafka consumer started…")
    try:
        async for msg in consumer:
            try:
                payload = json.loads(msg.value.decode("utf-8"))
            except Exception:
                print("Invalid message received")
                continue

            await queue.put(payload)

    finally:
        await consumer.stop()


# ---------------------------------------------------------
#   Main
# ---------------------------------------------------------
async def main():
    queue = asyncio.Queue(maxsize=WORKER_POOL * 2)
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
    await producer.start()

    workers = [
        asyncio.create_task(worker(i + 1, queue, producer)) for i in range(WORKER_POOL)
    ]
    consumer_task = asyncio.create_task(consume_loop(queue))

    print(f"Scanner multi-worker started: WORKER_POOL={WORKER_POOL} (fully async)")

    try:
        await consumer_task
    finally:
        for w in workers:
            w.cancel()
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
