import os
import json
import urllib.request

RUN_URL = os.getenv("BOSAI_RUN_URL", "https://bosai-worker.onrender.com/run").strip()

payload = {
  "worker": os.getenv("WORKER_NAME", "bosai-worker-01"),
  "capability": "command_orchestrator",
  "idempotency_key": "cron-command-orchestrator",
  "input": {"limit": int(os.getenv("CRON_ORCH_LIMIT", "5"))},
}

data = json.dumps(payload).encode("utf-8")
req = urllib.request.Request(
    RUN_URL,
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST",
)

with urllib.request.urlopen(req, timeout=30) as resp:
    body = resp.read().decode("utf-8")
    print(body)
