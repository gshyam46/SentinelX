#!/bin/bash
set -e

echo "[entrypoint] Running Alembic migrations..."
cd /app
python -m alembic upgrade head

echo "[entrypoint] Starting SentinelX API..."
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 1
