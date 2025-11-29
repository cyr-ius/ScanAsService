# main.py
import asyncio
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager

from aiobotocore.session import AioSession, get_session
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from helpers import KafkaMessage, ScanResult, retry_async
from starlette.background import BackgroundTask

# --- Config ---
KAFKA_SERVER = os.getenv("KAFKA_SERVER", "kafka:9092")
KAFKA_INPUT_TOPIC = os.getenv("KAFKA_INPUT_TOPIC", "files_to_scan")
KAFKA_OUTPUT_TOPIC = os.getenv("KAFKA_OUTPUT_TOPIC", "scan_results")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "minioadmin")
S3_BUCKET = os.getenv("S3_BUCKET", "scans")
S3_ENDPOINT = os.getenv("S3_ENDPOINT_URL", "http://minio:9000")
S3_SCAN_RESULT = os.getenv("S3_SCAN_RESULT", "processed")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "minioadmin")

SEARCH_TIMEOUT = float(os.getenv("SEARCH_TIMEOUT", "5"))
VERSION = os.getenv("APP_VERSION", "unknown")

session = get_session()
producer: AIOKafkaProducer
logger = logging.getLogger("api")
logging.basicConfig(level=LOG_LEVEL)


# Create a reusable asynccontextmanager for S3 client to ensure proper close
@asynccontextmanager
async def s3_client_ctx():
    """Async context manager for S3 client."""
    client = await session.create_client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
    ).__aenter__()
    try:
        yield client
    finally:
        try:
            await client.__aexit__(None, None, None)
        except Exception as e:
            logger.debug("Error closing s3 client: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize Kafka producer and Redis client."""
    global producer
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_SERVER, acks="all")
    await producer.start()
    logger.info("Kafka producer started")
    yield
    await producer.stop()
    logger.info("Shutdown complete")


app = FastAPI(title="ScanAV API", lifespan=lifespan, version=VERSION)


@app.post("/upload")
async def upload_file_to_scan(file: UploadFile) -> KafkaMessage:
    """Upload file to S3 and send scan request to Kafka."""
    unique_key = f"{uuid.uuid4()}_{file.filename}"
    data = await file.read()

    try:
        async with s3_client_ctx() as client:
            await client.put_object(Bucket=S3_BUCKET, Key=unique_key, Body=data)  # type: ignore
    except Exception as e:
        logger.error("S3 put_object failed")
        raise HTTPException(status_code=503, detail=f"Storage unavailable: {e}")

    # Send Kafka message with retries
    payload = KafkaMessage(
        id=str(uuid.uuid4()),
        status="PENDING",
        bucket=S3_BUCKET,
        key=unique_key,
        original_filename=file.filename,
    )

    try:
        await producer.send_and_wait(
            KAFKA_INPUT_TOPIC, value=payload.model_dump_json().encode("utf-8")
        )
    except Exception as e:
        logger.error("Kafka send failed (%s)", e)
        raise HTTPException(status_code=503, detail=f"Message broker unavailable: {e}")

    return payload


@app.get("/download/{id}")
async def download_scanned_file(id: str, force: bool = False) -> StreamingResponse:
    """Download scanned file by ID if clean or force is True."""
    result = await fetch_scan_result(id)
    if result.status == "PENDING":
        raise HTTPException(status_code=202, detail="File is pending scan")
    if result.status != "CLEAN" and not force:
        raise HTTPException(status_code=404, detail=result.details)

    filename = getattr(result, "original_filename", "downloaded_file")

    # Use s3_client_ctx
    async def _get() -> AioSession:
        async with s3_client_ctx() as s3_client:
            return await s3_client.get_object(Bucket=S3_BUCKET, Key=result.key)  # type: ignore

    try:
        resp = await retry_async(_get, retries=6, base_delay=0.5)
        body = resp["Body"]
        headers = {"Content-Disposition": f"attachment; filename={filename}"}
        return StreamingResponse(
            body,
            media_type="application/octet-stream",
            headers=headers,
            background=BackgroundTask(body.close),
        )

    except Exception as e:
        logger.error("Download error (%s)", e)
        raise HTTPException(
            status_code=404, detail="File not found or storage unavailable"
        )


@app.get("/result/{id}")
async def scan_status(id: str) -> ScanResult:
    """Fetch scan result by ID."""
    try:
        result = await fetch_scan_result(id)
        return result
    except Exception as e:
        logger.error("Fetch scan result error (%s)", e)
        raise HTTPException(status_code=503, detail=str(e))


async def fetch_scan_result(record_id: str, timeout=SEARCH_TIMEOUT) -> ScanResult:
    """Fetch scan result from Kafka with timeout."""
    consumer = AIOKafkaConsumer(
        KAFKA_OUTPUT_TOPIC,
        bootstrap_servers=KAFKA_SERVER,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        group_id=f"api-tracker-{uuid.uuid4()}",
    )

    # start consumer with retry
    try:
        await consumer.start()
    except Exception as e:
        logger.exception("Kafka consumer start failed")
        raise HTTPException(status_code=503, detail=str(e))

    try:
        deadline = asyncio.get_event_loop().time() + timeout

        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break

            try:
                batch = await consumer.getmany(timeout_ms=int(remaining * 1000))
            except Exception as e:
                logger.warning("Error polling consumer, will retry: %s", e)
                await asyncio.sleep(0.5)
                continue

            for _, messages in batch.items():
                for msg in messages:
                    if msg.value is None:
                        continue
                    payload = json.loads(msg.value.decode())
                    if payload.get("id") == record_id:
                        logger.info(
                            "Found scan result for ID %s (%s)", record_id, payload
                        )
                        return ScanResult(**payload)

        raise HTTPException(status_code=503, detail="Result not ready yet")

    finally:
        await consumer.stop()
