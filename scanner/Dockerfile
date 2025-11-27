FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

RUN apt-get update
RUN apt-get install -y build-essential curl netcat-openbsd pkg-config libssl-dev ca-certificates
RUN rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir aiokafka boto3 clamd aiobotocore

# copy scanner code and entrypoint
COPY scanner_multi.py /app/scanner_multi.py
COPY wait_and_start.sh /app/wait_and_start.sh
RUN chmod +x /app/wait_and_start.sh

CMD ["/app/wait_and_start.sh"]
