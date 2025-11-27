import asyncio
import json
import logging
import time
import uuid

import boto3
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

MINIO_ENDPOINT = "http://192.168.1.1:9000"
MINIO_ACCESS = "minioadmin"
MINIO_SECRET = "minioadmin"

KAFKA_BOOTSTRAP = "192.168.1.1:9092"
INPUT_TOPIC = "files_to_scan"
OUTPUT_TOPIC = "scan_results"

FINAL_FILE = "demo/fichier_final.txt"

FILE = "demo/test_upload1.com"
FILE = "demo/test_upload.txt"

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


async def send_scan_request(producer, file_id, bucket, key):
    """Envoie un message de scan.request à Kafka."""
    msg = {"id": file_id, "bucket": bucket, "key": key}
    await producer.send_and_wait(INPUT_TOPIC, json.dumps(msg).encode("utf-8"))
    LOGGER.info(f"Message envoyé à Kafka: {msg}")


async def wait_for_result(file_id, timeout=180):
    """Attend le résultat du scan pour le fichier donné."""
    consumer = AIOKafkaConsumer(
        OUTPUT_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        enable_auto_commit=False,
        group_id=f"clamav-{uuid.uuid4()}",
        auto_offset_reset="earliest",
    )
    await consumer.start()

    start = time.time()
    try:
        async for msg in consumer:
            data = json.loads(msg.value.decode("utf-8"))
            if data.get("id") == file_id:
                LOGGER.info(f"Résultat reçu: {data}")
                return data

            if time.time() - start > timeout:
                raise TimeoutError("Aucun résultat reçu dans le délai imparti.")
    finally:
        await consumer.stop()


def upload_to_minio(bucket, key, file_path):
    """Upload un fichier vers MinIO."""
    s3 = boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS,
        aws_secret_access_key=MINIO_SECRET,
    )
    s3.upload_file(file_path, bucket, key)
    LOGGER.info(f"Fichier uploadé → s3://{bucket}/{key}")


def download_from_minio(bucket, key, out_path):
    """Télécharge un fichier depuis MinIO."""
    s3 = boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS,
        aws_secret_access_key=MINIO_SECRET,
    )

    s3.download_file(bucket, key, out_path)
    LOGGER.info(f"Fichier téléchargé → {out_path}")


async def main():
    """Upload un fichier, demande son scan et attend le résultat."""

    for i in range(10):
        bucket = "scans"
        key = FILE
        file_id = str(uuid.uuid4())

        # 1) Upload du fichier
        upload_to_minio(bucket, key, FILE)

        # 2) Création du producer Kafka
        producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
        await producer.start()

        try:
            # 3) Envoi d’un message scan.request
            await send_scan_request(producer, file_id, bucket, key)

        finally:
            await producer.stop()

        # # 4) Attente du résultat
        result = await wait_for_result(file_id)

        # # 5) Si CLEAN → télécharger
        if result.get("status") == "CLEAN":
            LOGGER.info("✅ Le fichier est sain.")
            # Récupère la nouvelle clé S3 car en fonction du scan le fichier peut avoir été déplacé
            key = result.get("key")
            LOGGER.info("Téléchargement du fichier scanné...")
            download_from_minio(bucket, key, FINAL_FILE)
        else:
            LOGGER.warning("⚠️ Le fichier est infecté ou erreur durant le scan.")


if __name__ == "__main__":
    asyncio.run(main())
