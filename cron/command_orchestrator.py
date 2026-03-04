# cron_orchestrator.py — BOSAI Cron (robust)
# Goals:
# - Robust HTTP POST with retries + backoff
# - Idempotency key stable per minute (safe for retries / avoids double-run)
# - Optional scheduler auth: x-scheduler-secret (SCHEDULER_SECRET env)
# - Optional run signature: x-run-signature (RUN_SHARED_SECRET env, sha256=...)
# - Clear logs, zero dependencies

import os
import json
import time
import hmac
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone


RUN_URL = os.getenv("BOSAI_RUN_URL", "https://bosai-worker.onrender.com/run").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()

CRON_ORCH_LIMIT = int((os.getenv("CRON_ORCH_LIMIT", "5") or "5").strip())
CRON_TIMEOUT_SECONDS = float((os.getenv("CRON_TIMEOUT_SECONDS", "30") or "30").strip())

CRON_MAX_RETRIES = int((os.getenv("CRON_MAX_RETRIES", "3") or "3").strip())
CRON_BACKOFF_SECONDS = float((os.getenv("CRON_BACKOFF_SECONDS", "2.0") or "2.0").strip())

# Scheduler guard (recommended)
SCHEDULER_SECRET = os.getenv("SCHEDULER_SECRET", "").strip()
ENFORCE_SCHEDULER_SECRET = (os.getenv("ENFORCE_SCHEDULER_SECRET", "1").strip() != "0")

# Optional request signature (matches your worker verify_signature_or_401)
RUN_SHARED_SECRET = os.getenv("RUN_SHARED_SECRET", "").strip()


def _utc_minute_key() -> str:
    # Stable per minute => retries don't create multiple runs
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%MZ")


def _build_payload(idempotency_key: str) -> dict:
    limit = CRON_ORCH_LIMIT
    if limit <= 0:
        limit = 5
    if limit > 50:
        limit = 50

    return {
        "worker": WORKER_NAME,
        "capability": "command_orchestrator",
        "idempotency_key": idempotency_key,
        "input": {"limit": limit},
    }


def _compute_run_signature(raw_body: bytes) -> str:
    # Worker expects: sha256=<hex>
    mac = hmac.new(RUN_SHARED_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def _request_once(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "bosai-cron/1.0",
        "Accept": "application/json",
    }

    # Scheduler auth (your header)
    if SCHEDULER_SECRET:
        headers["x-scheduler-secret"] = SCHEDULER_SECRET

    # Optional run signature (if your worker enforces it)
    if RUN_SHARED_SECRET:
        headers["x-run-signature"] = _compute_run_signature(raw)

    req = urllib.request.Request(
        RUN_URL,
        data=raw,
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=CRON_TIMEOUT_SECONDS) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        status = getattr(resp, "status", None) or resp.getcode()
        if int(status) >= 300:
            raise RuntimeError(f"Non-2xx response: {status} body={body[:1000]}")
        return body


def main() -> None:
    if ENFORCE_SCHEDULER_SECRET and not SCHEDULER_SECRET:
        raise SystemExit("Missing SCHEDULER_SECRET env (ENFORCE_SCHEDULER_SECRET=1).")

    minute_key = _utc_minute_key()
    idem = f"cron-command-orchestrator-{minute_key}"

    payload = _build_payload(idem)

    last_err = None
    for attempt in range(1, CRON_MAX_RETRIES + 1):
        try:
            out = _request_once(payload)
            print(out)
            return
        except urllib.error.HTTPError as e:
            # Read response body for debugging
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            last_err = f"HTTPError {e.code}: {body[:1000]}"
        except urllib.error.URLError as e:
            last_err = f"URLError: {repr(e)}"
        except Exception as e:
            last_err = f"Error: {repr(e)}"

        if attempt < CRON_MAX_RETRIES:
            # Backoff (simple, deterministic)
            sleep_s = CRON_BACKOFF_SECONDS * attempt
            time.sleep(sleep_s)

    raise SystemExit(f"Cron failed after {CRON_MAX_RETRIES} attempts. Last error: {last_err}")


if __name__ == "__main__":
    main()
