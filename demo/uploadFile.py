#!/usr/bin/env python3
import asyncio
import random

import aiohttp

API_URL = "http://192.168.1.1:8000"  # ton API FastAPI
CLEAN_FILE_PATH = "demo/test_upload.txt"  # fichier à uploader
INFECTED_FILE_PATH = "demo/test_upload1.com"  # fichier à uploader
CONCURRENT_UPLOADS = 20  # nombre de dépôts simultanés


async def upload_file(session, path):
    with open(path, "rb") as f:
        files = {"file": f}
        try:
            async with session.post(f"{API_URL}/upload/", data=files) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    print(f"Upload réussi: {result}")
                    record_id = result["id"]
                    await poll_result(session, record_id)
                elif resp.status == 409:
                    print(f"⚠️ Fichier déjà existant: {path}")
                else:
                    print(f"Erreur upload {resp.status}")
        except Exception as e:
            print(f"Exception: {e}")


async def poll_result(session, record_id):
    while True:
        async with session.get(f"{API_URL}/result/{record_id}") as resp:
            data = await resp.json()
            status = data.get("status")
            if resp.status / 100 != 2:
                print(f"Erreur récupération résultat pour {record_id} ({resp.status})")
                return
            if status in ("CLEAN", "INFECTED", "ERROR", "UNREACHABLE"):
                print(f"Résultat pour {record_id}: {data}")
                break
            else:
                print(f"Résultat pour {record_id} non prêt, attente…")
                await asyncio.sleep(2)


async def main():
    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(CONCURRENT_UPLOADS):
            # Choix aléatoire entre clean et infected
            file_path = random.choice([CLEAN_FILE_PATH, INFECTED_FILE_PATH])
            tasks.append(upload_file(session, file_path))
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
