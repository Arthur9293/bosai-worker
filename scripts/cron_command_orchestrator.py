import os
import json
import urllib.request

WORKER_URL = os.getenv("WORKER_URL", "https://bosai-worker.onrender.com/run").strip()

payload = {
    "worker": os.getenv("WORKER_NAME", "bosai-worker-01").strip(),
    "capability": "command_orchestrator",
    "idempotency_key": os.getenv("IDEMPOTENCY_KEY", "cron-command-orchestrator").strip(),
    "input": {"limit": int(os.getenv("ORCH_LIMIT", "5"))},
}

data = json.dumps(payload).encode("utf-8")
req = urllib.request.Request(
    WORKER_URL,
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST",
)

with urllib.request.urlopen(req, timeout=30) as resp:
    body = resp.read().decode("utf-8")
    print(body)
