#!/usr/bin/env sh
set -eu

exec python -m uvicorn app.worker:app --host 0.0.0.0 --port "$PORT"
