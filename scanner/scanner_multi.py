#!/usr/bin/env python3
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

# --- Config ---
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

WORKER_POOL = int(os.getenv("WORKER_POOL", "4"))

# --- aiobotocore session ---
from aiobotocore.session import get_session

session = get_session()


# ---------------------------------------------------------
#   Async S3 + ClamAV scan via TCP socket
# ---------------------------------------------------------
async def scan_s3_object_async(bucket: str, key: str) -> dict[str, Any]:
    """
    Streams an S3 object asynchronously to ClamAV via TCP socket.
    Uses the INSTREAM command directly.
    """
    try:
        # Connect to S3
        async with session.create_client(
            "s3",
            endpoint_url=S3_ENDPOINT,
            aws_access_key_id=S3_ACCESS_KEY,
            aws_secret_access_key=S3_SECRET_KEY,
        ) as client:
            resp = await client.get_object(Bucket=bucket, Key=key)
            body = resp["Body"]

            reader, writer = await asyncio.open_connection(CLAMD_HOST, CLAMD_PORT)

            # Send INSTREAM command
            writer.write(b"zINSTREAM\0")  # zINSTREAM is the ClamAV protocol
            await writer.drain()

            # Stream chunks (up to 1 MB each)
            while True:
                chunk = await body.read(1024 * 1024)
                if not chunk:
                    break
                size_bytes = len(chunk).to_bytes(4, byteorder="big")
                writer.write(size_bytes + chunk)
                await writer.drain()

            # Send zero-length chunk to indicate EOF
            writer.write(b"\x00\x00\x00\x00")
            await writer.drain()

            # Read response
            data = await reader.read(1024)
            response = data.decode().strip()

            writer.close()
            await writer.wait_closed()

            # Parse ClamAV response
            if "OK" in response:
                return {"status": "CLEAN", "virus": None}
            elif "FOUND" in response:
                virus = response.split("FOUND")[0].strip()
                return {"status": "INFECTED", "virus": virus}
            else:
                return {"status": "ERROR", "virus": None, "details": response}

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
            scan = await scan_s3_object_async(bucket, key)
            status = scan["status"]

            # -------- MOVE OBJECT IN S3 ----------
            if status == "CLEAN":
                new_key = f"{S3_SCAN_RESULT}/{key}"
            else:
                new_key = f"{S3_SCAN_QUARANTINE}/{key}"

            await move_s3_object_async(bucket, key, new_key)
            finish = datetime.now(timezone.utc)

            # -------- SEND RESULT ----------
            result = {
                "id": record_id,
                "bucket": bucket,
                "key": new_key,
                "status": status,
                "virus": scan.get("virus"),
                "details": scan.get("details", ""),
                "timestamp": finish.isoformat(),
                "duration": str(finish - now),
            }

            await producer.send_and_wait(
                KAFKA_OUTPUT_TOPIC, json.dumps(result).encode("utf-8")
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
        KAFKA_INPUT_TOPIC,
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
