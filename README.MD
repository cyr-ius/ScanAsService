# ScanAsService

Permet de réaliser des scans antivirus de fichiers en mode service.
Le moteur ClamAV sert d'antivirus. Kafka sert de bus de messages pour ordonner les scans et récupérer les résultats. MinIO sert de stockage S3 pour déposer/servir les fichiers scannés.

## Contenu principal du dossier app

- app/main.py : point d'entrée du scanner (consommateur Kafka). Lit les variables d'environnement et démarre la boucle de traitement.
- app/scanner_multi.py : logique pour interroger plusieurs daemons ClamAV (CLAMD_HOSTS) avec round‑robin / retry.
- app/helpers.py : utilitaires (S3, Kafka, parsing, logging).
- app/wait_and_start.sh : script utilitaire pour attendre que des services (Kafka, MinIO, ClamAV...) soient disponibles avant de démarrer le scanner.

## Variables d'environnement importantes

La section suivante documente toutes les variables et options que vous pouvez passer ou ajuster via docker-compose (ou via l'environnement) pour contrôler le comportement des services. Les valeurs indiquées sont des exemples / valeurs par défaut présentes dans docker-compose.yaml fourni.

Remarque : certaines valeurs sont spécifiques à l'image Kafka et à sa configuration — adaptez-les selon votre environnement.

### Variables générales (docker-compose / runtime)

- CLAMD_HOSTS
  - Description : liste de daemons ClamAV (host:port) séparés par des virgules.
  - Exemple : "scanasservice-clamav-1:3310,scanasservice-clamav-2:3310"
- WORKER_POOL
  - Description : nombre de threads / workers dans le scanner.
  - Exemple : 8
- LOG_LEVEL
  - Description : niveau de log (DEBUG, INFO, WARNING, ERROR)
  - Exemple : INFO

### Service scanner (conteneur scanner)

- KAFKA_SERVER
  - Description : adresse bootstrap du broker Kafka.
  - Exemple : kafka:9092
- KAFKA_INPUT_TOPIC
  - Description : topic Kafka d'entrée (messages de fichiers à scanner).
  - Exemple : files_to_scan
- KAFKA_OUTPUT_TOPIC
  - Description : topic Kafka de sortie (résultats de scan).
  - Exemple : scan_results
- S3_ENDPOINT_URL
  - Description : endpoint MinIO / S3 pour stockage des fichiers.
  - Exemple : http://minio:9000
- S3_ACCESS_KEY / S3_SECRET_KEY
  - Description : identifiants pour accéder à MinIO.
  - Exemple : minioadmin / minioadmin
- CLAMD_HOSTS, WORKER_POOL, LOG_LEVEL (déjà listés ci‑dessus)

Conseil : Dans docker-compose vous pouvez aussi changer `ports` et `volumes` pour exposer ou persister des données.

### Service Kafka (variables Kafka importantes)

Ces variables sont définies pour l'image kafka et contrôlent le broker. Modifiez-les si vous avez des besoins réseau/production.

- KAFKA_BROKER_ID
  - Description : identifiant du broker.
  - Exemple : 1
- KAFKA_PROCESS_ROLES
  - Description : rôles du processus (broker,controller...).
  - Exemple : broker,controller
- KAFKA_CONTROLLER_QUORUM_VOTERS
  - Description : configuration du quorum controller (pour Kafka KRaft).
  - Exemple : 1@localhost:9093
- KAFKA_CONTROLLER_LISTENER_NAMES
  - Exemple : CONTROLLER
- KAFKA_LISTENERS
  - Description : sockets d'écoute et ports exposés par Kafka dans le conteneur.
  - Exemple : PLAINTEXT://:29092,PLAINTEXT_HOST://:9092,CONTROLLER://:9093
- KAFKA_LISTENER_SECURITY_PROTOCOL_MAP
  - Exemple : CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
- KAFKA_ADVERTISED_HOSTS / KAFKA_ADVERTISED_LISTENERS
  - Description : valeurs annoncées aux clients externes. Adaptez à votre réseau.
  - Exemple : KAFKA_ADVERTISED_HOSTS=${KAFKA_ADVERTISED_HOSTS:-192.168.1.1}
  - Exemple KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:29092,PLAINTEXT_HOST://${KAFKA_ADVERTISED_HOSTS}:9092
- KAFKA_INTER_BROKER_LISTENER_NAME
  - Exemple : PLAINTEXT
- KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR
  - Exemple : 1
- KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR
  - Exemple : 1
- KAFKA_TRANSACTION_STATE_LOG_MIN_ISR
  - Exemple : 1
- KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS
  - Exemple : 0
- KAFKA_NUM_PARTITIONS
  - Description : nombre de partitions par topic créé automatiquement.
  - Exemple : 4
- KAFKA_AUTO_CREATE_TOPICS_ENABLE
  - Exemple : "true"
- KAFKA_LOG_RETENTION_MS
  - Exemple : 86400000

Notes Kafka :

- En environnement de production, ajustez replication factor, partitions, et listeners selon votre cluster.
- Les healthchecks définis dans docker-compose permettent d'attendre que Kafka soit prêt.

### Service MinIO (variables MinIO)

- MINIO_ROOT_USER / MINIO_ROOT_PASSWORD
  - Description : identifiants administrateur MinIO.
  - Exemple : minioadmin / minioadmin
- S3_ENDPOINT_URL, S3_ACCESS_KEY, S3_SECRET_KEY (utilisés par le scanner pour se connecter)

MinIO options :

- `command: server /data` et `volumes` contrôlent le stockage persistant.
- Le service `minio-init` utilise `mc` pour créer le bucket `scans` ; vous pouvez adapter le nom du bucket ou les scripts d'initialisation.

### Service ClamAV

- CLAMD_HOSTS (décrit plus haut) — adaptez la liste des daemons ClamAV.
- Dans docker-compose l'exemple crée 2 réplicas :
  - deploy.replicas: 2
  - Vous pouvez augmenter ou diminuer le nombre d'instances ClamAV (ou utiliser `docker compose up --scale clamav=N`).

### Exemple d'usage Avancé

- Lancer plusieurs instances du scanner (par ex. pour paraléliser via Kafka consumer group) :
  - docker compose up --scale scanner=3 -d

## Lancer avec Docker Compose

Construire et démarrer les conteneurs :

```bash
docker compose up --build -d
```

Pour exécuter plusieurs instances du scanner (parallélisation via Kafka consumer group) :

```bash
docker compose up --build -d
docker compose up --scale scanner=3 -d
```

Remarques :

- Docker Compose génère des noms de conteneur uniques (project_service_1, project_service_2...). On ne peut pas assigner le même container_name à plusieurs instances.
- Pour un déploiement déclaratif avec réplication (Swarm), utilisez `deploy.replicas` et `docker stack deploy`.

## Lancer le scanner localement (développement)

1. Créer et activer un venv :
   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   pip install -r requirements.txt  # si requirements disponible
   ```
2. Exporter les variables d'environnement requises et lancer :
   ```bash
   export KAFKA_SERVER=kafka:9092
   export CLAMD_HOSTS="clamav1:3310,clamav2:3310"
   # autres variables...
   python3 app/main.py
   ```

## Utilisation de l'API

Le service expose une API HTTP via FastAPI (port mappé 8000 par défaut). La documentation interactive (Swagger UI) et le schéma OpenAPI sont accessibles après démarrage :

- Swagger UI : http://localhost:8000/docs
- OpenAPI JSON : http://localhost:8000/openapi.json

Endpoints exposés (implémentation actuelle)

- POST /upload
  - Description : téléverse un fichier (multipart/form-data) vers le bucket configuré (S3_BUCKET, par défaut `scans`) et publie une demande de scan sur le topic Kafka d'entrée.
  - Form-data :
    - file : le fichier à téléverser
  - Réponse : objet KafkaMessage (JSON) contenant au minimum : id, status, bucket, key, original_filename.
  - Exemple curl :
    curl -X POST "http://localhost:8000/upload" -F "file=@./sample.pdf"
  - Comportement : le fichier est stocké dans S3 sous une clé unique (uuid_filename). Une entrée est publiée sur KAFKA_INPUT_TOPIC pour déclencher le scan par le worker.

- GET /result/{id}
  - Description : récupère le résultat de scan pour l'identifiant fourni.
  - Paramètres :
    - id : identifiant (UUID) renvoyé par l'upload (ou par l'appel qui publie la demande).
  - Réponse : ScanResult (JSON). Exemple de structure :
    {
    "id": "123",
    "bucket": "scans",
    "key": "processed/sample.pdf",
    "status": "PENDING" | "CLEAN" | "INFECTED" | "ERROR",
    "virus": null | "NameOfVirus",
    "details": "",
    "timestamp": "2025-11-29T12:34:56Z",
    "duration": 1.234,
    "worker": "worker-1",
    "original_filename": "sample.pdf",
    "instance": "clamav1:3310",
    "analyse": 0.123
    }
  - Exemple curl :
    curl "http://localhost:8000/result/1234-uuid"

  - Remarque : l'API cherche le résultat sur le topic Kafka de sortie en créant un consumer temporaire. Le délai d'attente est contrôlé par la variable d'environnement SEARCH_TIMEOUT (par défaut 5s). Si le résultat n'est pas encore disponible, l'endpoint peut renvoyer une erreur indiquant que le résultat n'est pas prêt.

- GET /download/{id}
  - Description : télécharge le fichier scanné correspondant à l'id si le statut est CLEAN ou si `force=true`.
  - Paramètres :
    - id : identifiant du scan
    - force (query, optionnel) : true|false (si true, permet de télécharger même si INFECTED)
  - Réponse : StreamingResponse avec le contenu du fichier et header Content-Disposition.
  - Exemple curl (télécharger et sauvegarder localement) :
    curl -L -o sample.pdf "http://localhost:8000/download/1234-uuid?force=true"

Notes opérationnelles

- Ports : l'API est exposée sur le port 8000 du host (docker-compose mappe "8000:8000").
- Topics Kafka : le comportement dépend des variables d'environnement KAFKA_INPUT_TOPIC et KAFKA_OUTPUT_TOPIC.
- Stockage : S3/MiniO est configuré via S3_ENDPOINT_URL, S3_ACCESS_KEY, S3_SECRET_KEY, et S3_BUCKET.
- Timeouts / retry : la recherche de résultat dans /result/{id} utilise un consumer Kafka temporaire avec un timeout (SEARCH_TIMEOUT).

## Multi-ClamAV et scalabilité

But : permettre à plusieurs moteurs ClamAV de traiter la file Kafka en parallèle.

- Fournir la liste de daemons ClamAV via CLAMD_HOSTS.
- Le scanner (scanner_multi.py) itère sur cette liste et retente les connexions en cas d'échec.
- Lancer plusieurs réplicas du service scanner pour paralléliser le traitement : Kafka répartira les messages entre instances du même groupe de consommateurs.

## wait_and_start.sh

Le script `app/wait_and_start.sh` est fourni pour attendre la disponibilité de dépendances avant de lancer le scanner (utile en développement ou comme entrypoint). Exemple d'utilisation dans Dockerfile / docker-compose :

```bash
sh app/wait_and_start.sh kafka:9092 minio:9000 clamav:3310 -- python3 app/main.py
```

(Le script attendra les endpoints donnés puis exécutera la commande passée.)

## Contribuer

Contributions bienvenues. Voir `CONTRIBUTING.md`.

## Licence

MIT — voir fichier LICENSE pour détails.
