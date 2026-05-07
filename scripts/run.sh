#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
if [ -f ".env" ]; then
    echo "Loading environment variables from .env..."
    set -a
    source .env
    set +a
fi

# Check if TLS certificates exist
if [ -f "ca_cert.pem" ] && [ -f "ca_key.pem" ]; then
    echo "TLS certificates found. Starting with HTTPS/WSS support..."
    python3 -m uvicorn app.main:app \
        --host 127.0.0.1 \
        --port 8000 \
        --ssl-keyfile ca_key.pem \
        --ssl-certfile ca_cert.pem \
        --reload
else
    echo "TLS certificates not found. Starting without TLS..."
    python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
fi
