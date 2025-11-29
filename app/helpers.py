"""Helpers for the application."""

import asyncio
import logging
from collections.abc import Callable, Coroutine
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

logger = logging.getLogger(__name__)


def parse_hosts(s: str, port: int = 3310) -> list[tuple[str, int]]:
    """Parse 'host:port,host:port' string from environment variable."""
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            h, p = part.split(":", 1)
            try:
                out.append((h, int(p)))
            except ValueError:
                continue
        else:
            out.append((part, port))
    return out


async def retry_async(
    func: Callable[..., Coroutine[Any, Any, Any]],
    *args,
    retries: int = 5,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
    **kwargs,
):
    """Retry async function with exponential backoff."""
    delay = base_delay
    last_exception: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as error:
            last_exception = error
            logger.warning("Attempt %d failed: %s", attempt, error)
            if attempt == retries:
                break
            await asyncio.sleep(min(delay, max_delay))
            delay *= 2
    if last_exception is not None:
        raise last_exception
    raise RuntimeError("retry_async failed without raising an exception")


class MessageBase(BaseModel):
    id: str
    status: Literal["ERROR", "PENDING", "CLEAN", "INFECTED", "UNREACHABLE"]
    timestamp: datetime = datetime.now()
    details: str | None = None


class KafkaMessage(MessageBase):
    bucket: str
    key: str
    original_filename: str | None = None


class ClamAVResult(MessageBase):
    instance: str | None = None
    virus: str | None = None
    analyse: float | None = None


class ScanResult(ClamAVResult, KafkaMessage, MessageBase):
    duration: float | None = None
    worker: str | None = None


class ScanAVException(Exception):
    """Custom exception for scan errors."""


class S3GetObjectException(ScanAVException):
    """Custom exception for S3 get object errors."""


class S3MoveException(ScanAVException):
    """Custom exception for S3 move errors."""


class S3LockException(ScanAVException):
    """Custom exception for S3 lock errors."""


class S3UnlockException(ScanAVException):
    """Custom exception for S3 unlock errors."""


class KafkaSendException(ScanAVException):
    """Custom exception for Kafka send errors."""


class ClamAVException(ScanAVException):
    """Custom exception for scan result fetch errors."""
