"""Class for managment S3 storage."""

import asyncio
import time
from typing import Any

from aiobotocore.session import ClientCreatorContext, get_session
from aiohttp import ClientSession
from const import BASE_DELAY, RETRY
from helpers import ClamAVResult, ScanResult, retry
from mylogging import mylogging

logger = mylogging.getLogger("storage")


class S3Storage:
    def __init__(
        self,
        endpoint,
        key,
        secret,
        clamd_timeout: float,
        region: str | None = None,
    ):
        self.endpoint = endpoint
        self.key = key
        self.secret = secret
        self._clamd_timeout = clamd_timeout
        self._statistics = {"infected": 0, "cleaned": 0, "errors": 0}

    @property
    def statistics(self):
        """Return statis."""
        return self._statistics

    async def _get_s3_client(self) -> ClientCreatorContext:
        session = get_session()
        return session.create_client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.key,
            aws_secret_access_key=self.secret,
        )

    async def move_s3_object_async(
        self, key: str, bucket: str, target: str, result: ScanResult | None = None
    ) -> None:
        """Move or copy an object within S3 bucket."""

        logger.debug("Moving %s/%s to %s", bucket, key, target)
        tagging = f"worker={result.worker}&duration={result.duration}&status={result.status}&virus={result.virus}&analyse={result.analyse}&instance={result.instance}"
        async with await self._get_s3_client() as s3_client:
            try:
                # Get headers and merge with new metada because copy_object
                # lost old metadata on file
                await s3_client.copy_object(
                    Bucket=bucket,
                    Key=target,
                    CopySource={"Bucket": bucket, "Key": key},
                    Tagging=tagging,
                    TaggingDirective="REPLACE",
                )  # type: ignore
                await s3_client.delete_object(Bucket=bucket, Key=key)  # type: ignore
            except Exception as e:
                raise S3MoveException(f"s3-move-error:{e}") from e

    async def cleanup_s3_folder(
        self, bucket: str, prefix: str, older_than_ms: int
    ) -> None:
        """Delete S3 objects in `bucket/prefix` older than `older_than_ms`."""

        cutoff_ts = time.time() - (older_than_ms / 1000)

        async with await self._get_s3_client() as s3_client:
            paginator = s3_client.get_paginator("list_objects_v2")
            async for page in paginator.paginate(Bucket=bucket, Prefix=prefix):  # type: ignore
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    last_modified = obj["LastModified"].timestamp()
                    if last_modified < cutoff_ts:
                        try:
                            await s3_client.delete_object(Bucket=bucket, Key=key)  # type: ignore
                            logger.info(f"Deleted old object {bucket}/{key}")
                        except Exception as e:
                            logger.exception(f"Failed to delete {bucket}/{key}: {e}")

    async def scan_s3_object_async(
        self, key: str, bucket: str, host: str, port: int
    ) -> ClamAVResult:
        """Scan a single S3 file using a specific CLAMD host via INSTREAM."""

        logger.debug("Scanning %s/%s", bucket, key)
        start_time = time.monotonic()

        # fetch S3 stream (fresh for each attempt)
        async with await self._get_s3_client() as s3_client:
            try:
                resp = await s3_client.get_object(Bucket=bucket, Key=key)  # type: ignore
                body = resp["Body"]
            except Exception as e:
                raise S3GetObjectException(f"s3-get-error:{e}") from e

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=float(self._clamd_timeout)
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
                self._statistics["cleaned"] += 1
                return ClamAVResult(
                    key=key,
                    status="CLEAN",
                    instance=f"{host}:{port}",
                    analyse=round(elapsed, 3),
                )

            if "FOUND" in response:
                self._statistics["infected"] += 1
                virus = response.split("FOUND")[0].split(":")[-1].strip()
                return ClamAVResult(
                    key=key,
                    status="INFECTED",
                    virus=virus,
                    instance=f"{host}:{port}",
                    analyse=round(elapsed, 3),
                )

            self._statistics["errors"] += 1
            raise ClamAVScanException(f"clamd-scan-nostatus:{key} - {host}:{port}")

        except Exception as e:
            raise ClamAVException(f"clamd-scan-error:{e}") from e

    @retry(tries=RETRY, delay=BASE_DELAY, logger=logger)
    async def call_webhook_and_remove(self, key: str, url: str, payload: dict):
        async with ClientSession(raise_for_status=True) as session:
            logger.info("Calling webhook %s", key)
            async with session.post(url, json=payload):
                logger.info(f"Webhook {url} successfully called for file {key}")

    def bucket_key(self, kafkat_payload: dict[str, Any]) -> tuple[str, str, str]:
        """Return bucket, key, metadata from payload."""
        if "Records" in kafkat_payload and len(kafkat_payload["Records"]) == 1:
            record = kafkat_payload["Records"][0]
            bucket = record.get("s3", {}).get("bucket", {}).get("name")
            key = record.get("s3", {}).get("object", {}).get("key")
            metadata = record.get("s3", {}).get("object", {}).get("userMetadata")
            if bucket is not None and key is not None and metadata:
                return key, bucket, metadata

        raise S3BucketKeyException("Unable to determine the bucket and key")


class S3StorageException(Exception):
    """Storage exception."""


class S3GetObjectException(S3StorageException):
    """Custom exception for S3 get object errors."""


class S3MoveException(S3StorageException):
    """Custom exception for S3 move errors."""


class S3TaggingException(S3StorageException):
    """Custom exception for S3 move errors."""


class S3LockException(S3StorageException):
    """Custom exception for S3 lock errors."""


class S3UnlockException(S3StorageException):
    """Custom exception for S3 unlock errors."""


class S3MetadataException(S3StorageException):
    """Custom exception for S3 unlock errors."""


class S3BucketKeyException(S3StorageException):
    """Custom exception for S3 unlock errors."""


class ClamAVException(Exception):
    """Custom exception for scan result fetch errors."""


class ClamAVScanException(ClamAVException):
    """Scan Exception"""


class ClamAVFailedAll(ClamAVException):
    """All ClamAV failed."""
