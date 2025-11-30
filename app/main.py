# main.py
import asyncio
import json
import uuid
from contextlib import asynccontextmanager

from aiobotocore.session import AioSession, get_session
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from const import (
    KAFKA_INPUT_TOPIC,
    KAFKA_OUTPUT_TOPIC,
    KAFKA_SERVERS,
    REDIS_URL,
    S3_ACCESS_KEY,
    S3_BUCKET,
    S3_ENDPOINT,
    S3_SECRET_KEY,
    SEARCH_TIMEOUT,
    VERSION,
)
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from helpers import KafkaMessage, ScanResult, retry_async
from mylogging import mylogging
from pydantic import BaseModel, HttpUrl
from redis import asyncio as redis
from starlette.background import BackgroundTask

WEBHOOKS_KEY = "scan_webhooks"

logger = mylogging.getLogger("api")
session = get_session()
producer: AIOKafkaProducer
r = redis.from_url(REDIS_URL)


class WebhookSubscription(BaseModel):
    url: HttpUrl
    file_id: str


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
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_SERVERS, acks="all")  # type: ignore
    await producer.start()
    logger.info("Kafka producer started")
    yield
    await producer.stop()
    logger.info("Shutdown complete")


app = FastAPI(
    title="ScanAV as Service (SAVaS) - API", lifespan=lifespan, version=VERSION
)


@app.post("/upload")
async def upload_file_to_scan(file: UploadFile) -> KafkaMessage:
    """Upload file to S3 and send scan request to Kafka."""
    unique_key = f"{uuid.uuid4()}_{file.filename}"
    data = await file.read()

    try:
        async with s3_client_ctx() as client:  # type: ignore
            await client.put_object(Bucket=S3_BUCKET, Key=unique_key, Body=data)  # type: ignore
    except Exception as e:
        logger.exception("S3 put_object failed")
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
        logger.exception("Kafka send failed (%s)", e)
        raise HTTPException(status_code=503, detail=f"Message broker unavailable: {e}")

    return payload


@app.get("/download/{id}")
async def download_scanned_file(id: str, force: bool = False) -> StreamingResponse:
    """Download scanned file by ID if clean or force is True."""
    result = await scan_status(id)
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
        logger.exception("Download error (%s)", e)
        raise HTTPException(
            status_code=404, detail="File not found or storage unavailable"
        )


@app.get("/result/{id}")
async def scan_status(id: str) -> ScanResult:
    """Fetch scan result by ID."""
    consumer = AIOKafkaConsumer(
        KAFKA_OUTPUT_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,  # type: ignore
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
        deadline = asyncio.get_event_loop().time() + SEARCH_TIMEOUT

        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break

            try:
                batch = await consumer.getmany(timeout_ms=int(remaining * 1000))
            except Exception as e:
                logger.warning("[api] Error polling consumer, will retry: %s", e)
                await asyncio.sleep(0.5)
                continue

            for _, messages in batch.items():
                for msg in messages:
                    if msg.value is None:
                        continue
                    payload = json.loads(msg.value.decode())
                    if payload.get("id") == id:
                        return ScanResult(**payload)

        raise HTTPException(status_code=503, detail="Result not ready yet")

    finally:
        await consumer.stop()


@app.get("/heartbeat", status_code=204)
async def hearbeat():
    """Hearbeat url."""
    pass


@app.get("/monitor")
async def loadbalcenr_monitor():
    """Monitor loadbalancing."""
    keys = await r.keys("monitor")
    mresult = []
    for k in keys:
        v = await r.get(k)
        if v:
            mresult.append(json.loads(v))

    keys = await r.keys("clamav")
    cresult = []
    for k in keys:
        v = await r.get(k)
        if v:
            cresult.append(json.loads(v))

    return {"monitor": mresult, "clamav": cresult}


@app.post("/webhooks/subscribe")
async def subscribe_webhook(sub: WebhookSubscription):
    data = await r.get(WEBHOOKS_KEY)
    hooks = json.loads(data) if data else {}

    hooks.setdefault(sub.file_id, [])
    url_str = str(sub.url)
    if url_str not in hooks[sub.file_id]:
        hooks[sub.file_id].append(url_str)

    await r.set("scan_webhooks", json.dumps(hooks))
    return {"status": "subscribed", "file_id": sub.file_id, "url": url_str}


@app.post("/webhooks/unsubscribe")
async def unsubscribe_webhook(sub: WebhookSubscription):
    data = await r.get(WEBHOOKS_KEY)
    hooks = json.loads(data) if data else {}

    url_str = str(sub.url)
    if sub.file_id in hooks and url_str in hooks[sub.file_id]:
        hooks[sub.file_id].remove(url_str)
        if not hooks[sub.file_id]:
            del hooks[sub.file_id]

    await r.set(WEBHOOKS_KEY, json.dumps(hooks))
    return {"status": "unsubscribed", "file_id": sub.file_id, "url": sub.url}


@app.get("/webhooks/{file_id}")
async def list_webhooks(file_id: str):
    data = await r.get(WEBHOOKS_KEY)
    hooks = json.loads(data) if data else {}
    return {"file_id": file_id, "webhooks": hooks.get(file_id, [])}
