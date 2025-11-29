#!/usr/bin/env python3
import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Optional

from aiobotocore.session import get_session
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from helpers import (
    ClamAVException,
    ClamAVResult,
    S3GetObjectException,
    S3LockException,
    S3MoveException,
    S3UnlockException,
    ScanResult,
    parse_hosts,
)
from redis import asyncio as redis

# ----------------- CONFIG -----------------
KAFKA_SERVER = os.getenv("KAFKA_SERVER", "kafka:9092")
KAFKA_INPUT_TOPIC = os.getenv("KAFKA_INPUT_TOPIC", "files_to_scan")
KAFKA_OUTPUT_TOPIC = os.getenv("KAFKA_OUTPUT_TOPIC", "scan_results")

S3_ENDPOINT = os.getenv("S3_ENDPOINT_URL", "http://minio:9000")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "minioadmin")
S3_BUCKET = os.getenv("S3_BUCKET", "scans")
S3_SCAN_RESULT = os.getenv("S3_SCAN_RESULT", "processed")
S3_SCAN_QUARANTINE = os.getenv("S3_SCAN_QUARANTINE", "quarantine")

CLAMD_HOSTS = parse_hosts(os.getenv("CLAMD_HOSTS", "clamav:3310"))
CLAMD_CNX_TIMEOUT = float(os.getenv("CLAMD_CNX_TIMEOUT", 10))
CLAMD_RETRY = int(os.getenv("CLAMD_RETRY", 3))  # number of retries (different hosts)
BASE_DELAY = float(os.getenv("BASE_DELAY", 0.5))

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
REDIS_LOCK_TIMEOUT = int(os.getenv("REDIS_LOCK_TIMEOUT", 15))

WORKER_POOL = int(os.getenv("WORKER_POOL", 4))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Hybrid scoring params (tweakable)
BUSY_WEIGHT = float(os.getenv("BUSY_WEIGHT", 1.0))
FAILURE_WEIGHT = float(os.getenv("FAILURE_WEIGHT", 5.0))
COOLDOWN_THRESHOLD = int(os.getenv("COOLDOWN_THRESHOLD", 3))  # failures before cooldown
COOLDOWN_SECONDS = float(os.getenv("COOLDOWN_SECONDS", 60))  # cooldown duration
EMA_ALPHA = float(
    os.getenv("EMA_ALPHA", 0.2)
)  # exponential moving average alpha for avg times

session = get_session()
logger = logging.getLogger(__name__)
logging.basicConfig(level=LOG_LEVEL)

# ----------------- GLOBAL STATE FOR ADAPTIVE LB -----------------
# Stats per host key "host:port"
_host_stats: dict[str, dict] = {}
_stats_lock = asyncio.Lock()  # protects _host_stats and round-robin index
_next_clamd_index = 0


# Initialize stats for configured hosts
def _init_host_stats() -> None:
    """Ensure _host_stats has entries for all CLAMD_HOSTS."""
    global _host_stats
    for host, port in CLAMD_HOSTS:
        key = f"{host}:{port}"
        if key not in _host_stats:
            _host_stats[key] = {
                "host": host,
                "port": port,
                "busy": 0,  # number of concurrent scans in progress
                "avg_time": 0.0,  # avg scan time in seconds (EMA)
                "count": 0,  # number of completed scans used in avg
                "failures": 0,  # consecutive failures
                "last_failure": 0.0,  # timestamp of last failure
            }


_init_host_stats()


# -------------------- Mutex S3 via Redis --------------------
async def acquire_s3_lock(
    redis_client, bucket: str, key: str, timeout: int = REDIS_LOCK_TIMEOUT
) -> bool:
    try:
        lock_key = f"lock:{bucket}/{key}"
        return await redis_client.set(lock_key, "1", nx=True, ex=timeout)
    except Exception as e:
        logger.error(f"Error acquiring lock for {bucket}/{key}: {e}")
        raise S3LockException(f"s3-acquire-error:{e}")


async def release_s3_lock(redis_client, bucket: str, key: str) -> None:
    try:
        lock_key = f"lock:{bucket}/{key}"
        await redis_client.delete(lock_key)
    except Exception as e:
        logger.error(f"Error releasing lock for {bucket}/{key}: {e}")
        raise S3UnlockException(f"s3-release-error:{e}")


# ----------------- ClamAV SCAN -----------------
async def scan_s3_object_async(
    record_id: str, bucket: str, key: str, host: str, port: int
) -> ClamAVResult:
    """Scan a single S3 file using a specific CLAMD host via INSTREAM."""

    start_time = time.monotonic()

    # fetch S3 stream (fresh for each attempt)
    async with session.create_client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
    ) as s3_client:
        try:
            resp = await s3_client.get_object(Bucket=bucket, Key=key)  # type: ignore
            body = resp["Body"]
        except Exception as e:
            raise S3GetObjectException(f"s3-get-error:{e}")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=float(CLAMD_CNX_TIMEOUT)
        )

        writer.write(b"zINSTREAM\0")
        await writer.drain()

        async for chunk in body.iter_chunks():
            if not chunk:
                break
            writer.write(len(chunk).to_bytes(4, "big") + chunk)
            await writer.drain()

        writer.write(b"\x00\x00\x00\x00")
        await writer.drain()

        resp_bytes = await asyncio.wait_for(reader.read(4096), timeout=5)
        response = resp_bytes.decode(errors="ignore").strip()

        writer.close()
        await writer.wait_closed()

        elapsed = time.monotonic() - start_time

        # Parse response
        if "OK" in response:
            return ClamAVResult(
                id=record_id,
                status="CLEAN",
                instance=f"{host}:{port}",
                analyse=round(elapsed, 3),
            )

        if "FOUND" in response:
            virus = response.split("FOUND")[0].split(":")[-1].strip()
            return ClamAVResult(
                id=record_id,
                status="INFECTED",
                virus=virus,
                instance=f"{host}:{port}",
                analyse=round(elapsed, 3),
            )

        return ClamAVResult(
            id=record_id, status="ERROR", details=response, instance=f"{host}:{port}"
        )

    except Exception as e:
        raise ClamAVException(f"clamd-scan-error:{e}")


# ----------------- Adaptive load-balancer helpers -----------------
def _host_key(host: str, port: int) -> str:
    """Generate host key string."""
    return f"{host}:{port}"


async def _select_best_host() -> tuple[str, int, str]:
    """
    Select best host according to hybrid score.
    Hosts in cooldown get penalty, but if all are in cooldown fallback to round-robin.
    """
    async with _stats_lock:
        _init_host_stats()

        best_key = None
        best_score = float("inf")
        now = time.time()

        for key, s in _host_stats.items():
            # cooldown penalty
            cooldown_active = (
                s["failures"] >= COOLDOWN_THRESHOLD
                and (now - s["last_failure"]) < COOLDOWN_SECONDS
            )
            penalty = 1e9 if cooldown_active else 0.0

            score = (
                s["busy"] * BUSY_WEIGHT
                + s["avg_time"]
                + s["failures"] * FAILURE_WEIGHT
                + penalty
            )

            if score < best_score:
                best_score = score
                best_key = key

        if best_key is None:
            # fallback round-robin (should rarely happen)
            global _next_clamd_index
            host, port = CLAMD_HOSTS[_next_clamd_index % len(CLAMD_HOSTS)]
            key = _host_key(host, port)
            _next_clamd_index = (_next_clamd_index + 1) % len(CLAMD_HOSTS)
            return host, port, key

        s = _host_stats[best_key]
        return s["host"], s["port"], best_key


async def _mark_host_busy(key: str) -> None:
    """Increment busy counter for host."""
    async with _stats_lock:
        _host_stats[key]["busy"] += 1


async def _mark_host_done(key: str, elapsed: Optional[float], success: bool) -> None:
    """
    Decrement busy, update avg_time (EMA) if elapsed provided, and update failure counters.
    """
    async with _stats_lock:
        s = _host_stats[key]
        # busy decrement, never below 0
        s["busy"] = max(0, s["busy"] - 1)

        now = time.time()
        if success:
            s["failures"] = 0
            s["last_failure"] = 0.0
        else:
            s["failures"] = s.get("failures", 0) + 1
            s["last_failure"] = now

        # update avg_time only on success and if elapsed provided
        if success and elapsed is not None:
            prev = s.get("avg_time", 0.0) or 0.0
            if prev == 0.0:
                s["avg_time"] = elapsed
                s["count"] = 1
            else:
                # exponential moving average
                s["avg_time"] = EMA_ALPHA * elapsed + (1 - EMA_ALPHA) * prev
                s["count"] = s.get("count", 0) + 1


# ----------------- S3 helpers -----------------
async def move_s3_object_async(bucket: str, old_key: str, new_key: str) -> None:
    """Move or copy an object within S3 bucket."""
    async with session.create_client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
    ) as s3_client:
        try:
            await s3_client.copy_object(
                Bucket=bucket,
                CopySource={"Bucket": bucket, "Key": old_key},
                Key=new_key,
            )  # type: ignore
            await s3_client.delete_object(Bucket=bucket, Key=old_key)  # type: ignore
        except Exception as e:
            raise S3MoveException(f"s3-move-error:{e}")


# ----------------- WORKER -----------------
async def worker(
    name: int, queue: asyncio.Queue, producer: AIOKafkaProducer, redis_client
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
                if not await acquire_s3_lock(redis_client, bucket, key):
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
                    host, port, host_key = await _select_best_host()

                    # mark busy
                    await _mark_host_busy(host_key)
                    scan_start = time.monotonic()
                    try:
                        scan = await scan_s3_object_async(
                            record_id, bucket, key, host, port
                        )
                    except ClamAVException as e:
                        elapsed = time.monotonic() - scan_start
                        # mark done with failure (no elapsed update)
                        await _mark_host_done(host_key, elapsed=None, success=False)
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
                            await _mark_host_done(
                                host_key, elapsed=elapsed, success=True
                            )
                        else:
                            # engine returned ERROR -> treat as success (we received a response) but don't count as success for avg maybe?
                            await _mark_host_done(
                                host_key, elapsed=elapsed, success=False
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
                        await move_s3_object_async(bucket, key, new_key)
                    except S3MoveException as e:
                        logger.error(f"[worker-{name}] Move error: {e}")
                        status = "ERROR"
                        detail = f"move-error:{e}"
                    else:
                        key = new_key
                        logger.info(f"[worker-{name}] Scanned {key} → {status}")

            # release S3 lock
            try:
                await release_s3_lock(redis_client, bucket, key)
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
        bootstrap_servers=KAFKA_SERVER,
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


# ----------------- COOLDOWN RESET TASK -----------------
async def reset_host_failures_periodically() -> None:
    """
    Periodically reset failures of hosts whose cooldown has expired.
    Ensures that rebooted ClamAV instances become selectable again.
    """
    while True:
        async with _stats_lock:
            now = time.time()
            for s in _host_stats.values():
                if (
                    s["failures"] >= COOLDOWN_THRESHOLD
                    and (now - s["last_failure"]) > COOLDOWN_SECONDS
                ):
                    logger.info(
                        f"Resetting host {s['host']}:{s['port']} failures after cooldown"
                    )
                    s["failures"] = 0
                    s["last_failure"] = 0.0
        await asyncio.sleep(COOLDOWN_SECONDS / 2)  # check twice per cooldown period


# ----------------- MAIN -----------------
async def main():
    global producer
    queue = asyncio.Queue(maxsize=WORKER_POOL * 2)
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_SERVER)
    await producer.start()

    redis_client = redis.from_url(REDIS_URL)

    asyncio.create_task(reset_host_failures_periodically())

    workers = [
        asyncio.create_task(worker(i + 1, queue, producer, redis_client))
        for i in range(WORKER_POOL)
    ]

    consumer_task = asyncio.create_task(consume_loop(queue))

    try:
        await consumer_task
    finally:
        for w in workers:
            w.cancel()
        await producer.stop()
        await redis_client.aclose()
        await redis_client.connection_pool.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
