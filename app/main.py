# main.py
import asyncio
import json
from socket import getfqdn
import uuid
from contextlib import asynccontextmanager

from aiobotocore.session import AioSession, get_session
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from const import (
    KAFKA_TOPIC,
    KAFKA_SERVERS,
    REDIS_URL,
    S3_ACCESS_KEY,
    S3_BUCKET,
    S3_ENDPOINT,
    S3_SECRET_KEY,
    VERSION,
    S3_SCAN_RESULT,
    S3_SCAN_QUARANTINE
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
async def upload_file_to_scan(file: UploadFile , url: HttpUrl |None = None ) -> ScanResult:
    """Upload file to S3 and send scan request to Kafka."""
    key = str(uuid.uuid4())
    data = await file.read()
    try:
        async with s3_client_ctx() as client:  # type: ignore
            metadata = {"OriginalFilename":file.filename, "Webhook":url}
            await client.put_object(Bucket=S3_BUCKET, Key=key, Body=data, Metadata=metadata)  # type: ignore
    except Exception as e:
        logger.exception("S3 put_object failed")
        raise HTTPException(status_code=503, detail=f"Storage unavailable: {e}")

    # Send Kafka message with retries
    payload = KafkaMessage(Key=key, bucket=S3_BUCKET)

    try:
        await producer.send_and_wait(
            KAFKA_TOPIC, value=payload.model_dump_json().encode("utf-8")
        )
    except Exception as e:
        logger.exception("Kafka send failed (%s)", e)
        raise HTTPException(status_code=503, detail=f"Message broker unavailable: {e}")

    return ScanResult(key=key, status="PENDING", webhook=url)


@app.get("/download/{id}")
async def download_scanned_file(id: str, force: bool = False) -> StreamingResponse:
    """Download scanned file by ID if clean or force is True."""
    result = await scan_status(id)
    if result.status == "PENDING":
        raise HTTPException(status_code=202, detail="File is pending scan")
    if result.status != "CLEAN" and not force:
        raise HTTPException(status_code=404, detail=result.details)

    # Use s3_client_ctx
    async def _get() -> AioSession:
        async with s3_client_ctx() as s3_client:
            return await s3_client.get_object(Bucket=S3_BUCKET, Key=result.key)  # type: ignore

    try:
        resp = await retry_async(_get, retries=6, base_delay=0.5)
        filename = resp.get("Metadata", {}).get("OriginalFilename","unkown_name")
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

    async with s3_client_ctx() as s3_client:
        for bucket in [S3_BUCKET, S3_SCAN_RESULT, S3_SCAN_QUARANTINE]:
            try:
                obj = await s3_client.get_object_tagging(Bucket=bucket, Key=id) 
                if tags := obj.get("TagSet"):
                    tags = {t["Key"]:t["Value"] for t in tags}
                break
            except Exception as e:
                continue
        if bucket == S3_BUCKET:
            return ScanResult(key=id, status_code=202, detail="File is pending scan")
        if tags.get("status") in ["CLEAN", "INFECTED"]:
            return ScanResult(key=id, bucket=bucket, **tags)
        
        return ScanResult(key=id, status="ERROR", detail="File not found")


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

