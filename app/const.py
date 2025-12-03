"""Constants."""

import os

from helpers import parse_hosts

KAFKA_SERVERS = os.getenv("KAFKA_SERVERS", "kafka:9092").split(",")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "files_to_scan")
KAFKA_LOG_RETENTION_MS = int(os.getenv("KAFKA_LOG_RETENTION_MS", 86400000))

SEARCH_TIMEOUT = float(os.getenv("SEARCH_TIMEOUT", "5"))
VERSION = os.getenv("APP_VERSION", "unknown")

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
LIB_LOG_LEVEL = os.getenv("LIB_LOG_LEVEL", "WARNING").upper()

# Hybrid scoring params (tweakable)
BUSY_WEIGHT = float(os.getenv("BUSY_WEIGHT", 1.0))
FAILURE_WEIGHT = float(os.getenv("FAILURE_WEIGHT", 5.0))
COOLDOWN_THRESHOLD = int(os.getenv("COOLDOWN_THRESHOLD", 3))  # failures before cooldown
COOLDOWN_SECONDS = float(os.getenv("COOLDOWN_SECONDS", 60))  # cooldown duration
EMA_ALPHA = float(
    os.getenv("EMA_ALPHA", 0.2)
)  # exponential moving average alpha for avg times
