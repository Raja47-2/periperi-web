# Deliberately weak build for the ECDAT demo. Never use in production.
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

RUN echo "stamp" | openssl dgst -sha1

COPY src /app/src
WORKDIR /app
