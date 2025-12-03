"""Class for managment S3 storage."""

import asyncio
import json
import time
from typing import  Any
from aiobotocore.session import ClientCreatorContext, get_session
from aiohttp import ClientSession
from helpers import ClamAVResult
from mylogging import mylogging
from redis import asyncio as redis
from redis.asyncio import Redis

logger = mylogging.getLogger("storage")


class S3Storage:
    def __init__(
        self,
        endpoint,
        key,
        secret,
        redis_url: str,
        redis_timeout: int,
        clamd_timeout: float,
        region: str | None = None,
    ):
        self.endpoint = endpoint
        self.key = key
        self.secret = secret
        self.redis_client: Redis = redis.from_url(redis_url)
        self.redis_timeout = redis_timeout
        self._clamd_timeout = clamd_timeout
        self._statistics = {"infected": 0, "cleaned": 0, "errors": 0}

    async def _get_s3_client(self) -> ClientCreatorContext:
        session = get_session()
        return session.create_client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.key,
            aws_secret_access_key=self.secret,
        )

    async def acquire_s3_lock(self, key: str, bucket: str, ) -> bool:
        try:
            lock_key = f"lock:{bucket}/{key}"
            return await self.redis_client.set(
                lock_key, "1", nx=True, ex=self.redis_timeout
            )
        except Exception as e:
            logger.exception(f"Error acquiring lock for {bucket}/{key}: {e}")
            raise S3LockException(f"s3-acquire-error:{e}") from e

    async def release_s3_lock(self, key: str, bucket: str) -> None:
        try:
            lock_key = f"lock:{bucket}/{key}"
            await self.redis_client.delete(lock_key)
        except Exception as e:
            logger.exception(f"Error releasing lock for {bucket}/{key}: {e}")
            raise S3UnlockException(f"s3-release-error:{e}") from e

    async def move_s3_object_async(
        self,key: str, bucket: str,  result: ClamAVResult| None = None
    ) -> None:
        """Move or copy an object within S3 bucket."""

        tagging = "&".join(f"{k}={v}" for k,v in result.items())
        async with await self._get_s3_client() as s3_client:
            try:
                # Get headers and merge with new metada because copy_object
                # lost old metadata on file
                await s3_client.copy_object(
                    Bucket=bucket,
                    Key=key,
                    CopySource={"Bucket": bucket, "Key": key},
                    Tagging=tagging
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
                            await self.acquire_s3_lock(Bucket=bucket, Key=key)
                            await s3_client.delete_object(Bucket=bucket, Key=key)  # type: ignore
                            logger.info(f"Deleted old object {bucket}/{key}")
                        except Exception as e:
                            logger.exception(f"Failed to delete {bucket}/{key}: {e}")
                        finally:
                            await self.release_s3_lock(Bucket=bucket, Key=key)

    async def scan_s3_object_async(
        self, key: str, bucket: str, host: str, port: int
    ) -> ClamAVResult:
        """Scan a single S3 file using a specific CLAMD host via INSTREAM."""

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
                await self.update_monitor_state()
                return ClamAVResult(
                    key=key,
                    status="CLEAN",
                    instance=f"{host}:{port}",
                    analyse=round(elapsed, 3),
                )

            if "FOUND" in response:
                self._statistics["infected"] += 1
                await self.update_monitor_state()
                virus = response.split("FOUND")[0].split(":")[-1].strip()
                return ClamAVResult(
                    key=key,
                    status="INFECTED",
                    virus=virus,
                    instance=f"{host}:{port}",
                    analyse=round(elapsed, 3),
                )

            self._statistics["errors"] += 1
            await self.update_monitor_state()
            raise ClamAVScanException(f"clamd-scan-nostatus:{key} - {host}:{port}")

        except Exception as e:
            raise ClamAVException(f"clamd-scan-error:{e}") from e

    async def set_s3_tags(self, key:str, bucket:str, tags: dict[str,Any]):
        """Set tags"""
        if len(tags) > 10:
            raise S3TaggingException("Tags numbers exceeded")
        
        tagging = "&".join(f"{k}={v}" for k,v in tags.items())
        async with await self._get_s3_client() as s3_client:
            try:
                await s3_client.put_object(Bucket=bucket, Key=key, tagging=tags)  # type: ignore
            except Exception as e:
                raise S3TaggingException(f"s3-tags-error:{e}") from e        

    async def get_s3_metadata(self, key:str, bucket:str) -> dict[str, Any]:
        """Get metadata."""
        async with await self._get_s3_client() as s3_client:       
            try:
                head = await s3_client.head_object(Bucket=bucket, Key=key)  # type: ignore
                return head.get("Metadata", {})
            except Exception as e:
                raise S3MetadataException(f"s3-tags-error:{e}") from e    

    async def call_webhook_and_remove(self, file_id: str, url: str, payload: dict):
        try:
            async with ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        logger.warning(f"Webhook {url} returned status {resp.status}")
                    else:
                        logger.info(
                            f"Webhook {url} successfully called for file {file_id}"
                        )
        except Exception as e:
            logger.error(f"Failed to call webhook {url} for file {file_id}: {e}")
        finally:
            # Remove URL from Redis after calling
            data = await self.redis_client.get("scan_webhooks")
            hooks = json.loads(data) if data else {}
            if file_id in hooks and url in hooks[file_id]:
                hooks[file_id].remove(url)
                if not hooks[file_id]:
                    del hooks[file_id]
                await self.redis_client.set("scan_webhooks", json.dumps(hooks))
                logger.debug(f"Webhook {url} unsubscribed for file {file_id}")

    async def update_monitor_state(self):
        try:
            logger.debug("ClamAV statistics: %s", self._statistics)
            await self.redis_client.set("clamav", json.dumps(self._statistics))
        except Exception as e:
            logger.exception(f"Error to push statistics ({e})")

    async def async_close(self):
        """Close."""
        await self.redis_client.aclose()
        await self.redis_client.connection_pool.disconnect()


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

class ClamAVException(Exception):
    """Custom exception for scan result fetch errors."""

class ClamAVScanException(ClamAVException):
    """Scan Exception"""

class ClamAVFailedAll(ClamAVException):
    """All ClamAV failed."""
