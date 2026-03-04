# cron.py — BOSAI Cron (robuste, SAFE) — PATCHED
# - Sends x-scheduler-secret if present
# - Retries with backoff
# - Idempotency stable per minute (prevents spam replays)
# - Explicit scheduler flags in input (SAFE, backward compatible)

import os
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

RUN_URL = os.getenv("BOSAI_RUN_URL", "https://bosai-worker.onrender.com/run").strip()
WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()
LIMIT = int(os.getenv("CRON_ORCH_LIMIT", "5") or "5")

SCHEDULER_SECRET = os.getenv("SCHEDULER_SECRET", "").strip()

TIMEOUT_SECONDS = int(os.getenv("CRON_TIMEOUT_SECONDS", "30") or "30")
RETRIES = int(os.getenv("CRON_RETRIES", "2") or "2")
SLEEP = float(os.getenv("CRON_RETRY_SLEEP_SECONDS", "1.5") or "1.5")


def _post(payload: dict) -> str:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if SCHEDULER_SECRET:
        headers["x-scheduler-secret"] = SCHEDULER_SECRET

    req = urllib.request.Request(RUN_URL, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return resp.read().decode("utf-8")


def main() -> None:
    tick = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M")  # idempotency stable par minute
    idem = f"cron-command-orchestrator-{tick}"

    payload = {
        "worker": WORKER_NAME,
        "capability": "command_orchestrator",
        "idempotency_key": idem,
        "max_commands": LIMIT,
        "input": {
            "limit": LIMIT,
            # SAFE flags (worker can ignore them if not used)
            "scheduler": True,
            "include_unscheduled": True,
        },
    }

    last_err = None
    for attempt in range(RETRIES + 1):
        try:
            body = _post(payload)
            print(body)
            return
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8")
            except Exception:
                err_body = ""
            last_err = f"HTTPError {e.code}: {err_body or str(e)}"
        except Exception as e:
            last_err = repr(e)

        if attempt < RETRIES:
            time.sleep(SLEEP)

    raise SystemExit(f"CRON_FAILED: {last_err}")


if __name__ == "__main__":
    main()
