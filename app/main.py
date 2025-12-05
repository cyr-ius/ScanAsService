# main.py
import json
import uuid
from contextlib import asynccontextmanager

from aiobotocore.session import get_session
from aiokafka import AIOKafkaConsumer
from aiokafka.structs import TopicPartition
from const import (
    KAFKA_SERVERS,
    KAFKAT_STATS,
    S3_ACCESS_KEY,
    S3_BUCKET,
    S3_ENDPOINT,
    S3_SCAN_QUARANTINE,
    S3_SCAN_RESULT,
    S3_SECRET_KEY,
    VERSION,
)
from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from helpers import ScanResult
from mylogging import mylogging
from pydantic import HttpUrl

CHUNK_SIZE = 64 * 1024

logger = mylogging.getLogger("api")
session = get_session()


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


app = FastAPI(title="ScanAV as Service (SAVaS) - API", version=VERSION)


@app.post("/upload")
async def upload_file_to_scan(
    file: UploadFile, url: HttpUrl | None = None
) -> ScanResult:
    """Upload file to S3 and send scan request to Kafka."""
    key = str(uuid.uuid4())
    data = await file.read()
    if url and len(url) > 128:
        raise HTTPException(
            status_code=503, detail="Webhook url: length exceeded (max: 128)"
        )
    try:
        async with s3_client_ctx() as client:  # type: ignore
            metadata = {"OriginalFilename": file.filename}
            if url is not None:
                metadata = {**metadata, "Webhook": str(url)}
            await client.put_object(
                Bucket=S3_BUCKET, Key=key, Body=data, Metadata=metadata
            )  # type: ignore
    except Exception as e:
        logger.exception("S3 put_object failed")
        raise HTTPException(status_code=503, detail=f"Storage unavailable: {e}")

    return ScanResult(key=key, status="PENDING", webhook=str(url))


@app.get("/download/{id}")
async def download_scanned_file(id: str, force: bool = False) -> StreamingResponse:
    """Download scanned file by ID if clean or force is True."""
    result = await scan_status(id)
    if result.status == "PENDING":
        raise HTTPException(status_code=202, detail="File is pending scan")
    if result.status != "CLEAN" and not force:
        raise HTTPException(status_code=404, detail=f"{result.status}")

    try:
        # Use s3_client_ctx
        async with s3_client_ctx() as s3_client:
            obj_meta = await s3_client.head_object(
                Bucket=S3_BUCKET, Key=f"{result.bucket}/{result.key}"
            )
            filename = obj_meta.get("Metadata", {}).get(
                "originalfilename", "unknown_name"
            )

        headers = {"Content-Disposition": f"attachment; filename={filename}"}
        return StreamingResponse(
            s3_object_stream(S3_BUCKET, f"{result.bucket}/{result.key}"),
            media_type="application/octet-stream",
            headers=headers,
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
        tags = {}
        for bucket in [S3_SCAN_RESULT, S3_SCAN_QUARANTINE]:
            try:
                obj = await s3_client.head_object(
                    Bucket=S3_BUCKET, Key=f"{bucket}/{id}"
                )
                metadata = obj.get("Metadata", {})
                if obj.get("TagCount"):
                    obj_tags = await s3_client.get_object_tagging(
                        Bucket=S3_BUCKET, Key=f"{bucket}/{id}"
                    )
                    tags = {t["Key"]: t["Value"] for t in obj_tags.get("TagSet", [])}
                return ScanResult(
                    key=id,
                    bucket=bucket,
                    orginal_filename=metadata.get("originalfilename"),
                    webhook=metadata.get("webhook"),
                    **tags,
                )
            except Exception:
                continue
        try:
            if await s3_client.head_object(Bucket=S3_BUCKET, Key=id):
                return ScanResult(key=id, bucket=S3_BUCKET, status="PENDING")
        except Exception as e:
            logger.exception("Download error (%s)", e)
            raise HTTPException(
                status_code=404, detail=f"File not found or storage unavailable ({e})"
            )


@app.post("/test/webhook")
async def webhook_s3_events(request: Request):
    data = await request.json()  # Récupère le JSON envoyé
    logger.info("[TEST WEBHHOK] %s", data)


@app.get("/heartbeat", status_code=204)
async def hearbeat():
    """Hearbeat url."""
    pass


@app.get("/monitor")
async def monitor():
    """Monitor loadbalancing."""
    msg = await get_last_message()
    return {"last_message": msg}


async def s3_object_stream(bucket: str, key: str):
    """Stream S3 object."""
    async with s3_client_ctx() as s3_client:  # type: ignore
        resp = await s3_client.get_object(Bucket=bucket, Key=key)  # type: ignore
        body = resp["Body"]
        try:
            async for chunk in body.iter_chunks(CHUNK_SIZE):
                if not chunk:
                    break
                yield chunk
        finally:
            # assure close du body si nécessaire
            try:
                await body.close()
            except Exception:
                pass


async def get_last_message() -> dict | None:
    consumer = AIOKafkaConsumer(
        bootstrap_servers=KAFKA_SERVERS,
        enable_auto_commit=False,  # ne jamais avancer l'offset
        auto_offset_reset="latest",  # démarrer au dernier offset
        group_id=f"api-tracker-{uuid.uuid4()}",
    )
    await consumer.start()

    # récupérer les partitions du topic
    partitions = consumer.partitions_for_topic(KAFKAT_STATS)
    if not partitions:
        await consumer.stop()
        return None

    topic_partitions = [TopicPartition(KAFKAT_STATS, p) for p in partitions]
    consumer.assign(topic_partitions)  # assign manuel

    # chercher le dernier offset et lire le dernier message
    last_messages = []
    for tp in topic_partitions:
        end_offset = await consumer.end_offsets([tp])
        last_offset = end_offset[tp] - 1
        if last_offset >= 0:
            consumer.seek(tp, last_offset)
            msg = await consumer.getone()
            last_messages.append(json.loads(msg.value.decode("utf-8")))

    await consumer.stop()
    return last_messages[-1] if last_messages else None
