import os
import json
import urllib.request
import uuid
from datetime import datetime, timezone

RUN_URL = os.getenv("BOSAI_RUN_URL", "https://bosai-worker.onrender.com/run").strip()
SCHEDULER_SECRET = os.getenv("SCHEDULER_SECRET", "").strip()

if not SCHEDULER_SECRET:
    raise RuntimeError("Missing SCHEDULER_SECRET")

now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
idempotency_key = f"cron-command-orchestrator-{now}-{uuid.uuid4().hex[:8]}"

payload = {
    "worker": os.getenv("WORKER_NAME", "bosai-worker-01"),
    "capability": "command_orchestrator",
    "idempotency_key": idempotency_key,
    "max_commands": int(os.getenv("CRON_ORCH_LIMIT", "5")),
    "input": {}
}

data = json.dumps(payload).encode("utf-8")

req = urllib.request.Request(
    RUN_URL,
    data=data,
    headers={
        "Content-Type": "application/json",
        "x-scheduler-secret": SCHEDULER_SECRET,
    },
    method="POST",
)

with urllib.request.urlopen(req, timeout=30) as resp:
    body = resp.read().decode("utf-8")
    print(body)
