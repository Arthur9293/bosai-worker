import os
import json
import uuid
import urllib.request
from datetime import datetime, timezone

RUN_URL = os.getenv("BOSAI_RUN_URL", "https://bosai-worker.onrender.com/run").strip()

def main() -> None:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    idem = f"cron-command-orchestrator-{now}-{uuid.uuid4().hex[:8]}"

    payload = {
        "worker": os.getenv("WORKER_NAME", "bosai-worker-01"),
        "capability": "command_orchestrator",
        "idempotency_key": idem,
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

if __name__ == "__main__":
    main()
