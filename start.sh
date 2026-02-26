#!/usr/bin/env bash
set -e

# Load .env if present
if [ -f .env ]; then
  export $(grep -v '^\s*#' .env | xargs) >/dev/null 2>&1 || true
fi

PORT="${PORT:-8000}"

python3 -m uvicorn app.worker:app --host 0.0.0.0 --port "$PORT" --reload --log-level debug
