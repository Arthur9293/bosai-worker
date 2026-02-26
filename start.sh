#!/usr/bin/env bash
set -euo pipefail

: "${PORT:=8000}"
exec python -m uvicorn app.worker:app --host 0.0.0.0 --port "$PORT"
