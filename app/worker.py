import os
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from datetime import datetime
from app.airtable_client import MakeClient

from app.make_client import MakeClient
from app.airtable_client import AirtableClient
from app.intents import build_registry


load_dotenv()

APP_NAME = "bosai-worker"
WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()

app = FastAPI(title=APP_NAME)


class RunRequest(BaseModel):
    intent: str
    args: Dict[str, Any] = {}
    command_record_id: Optional[str] = None
    idempotency_key: Optional[str] = None


@app.get("/health")
from datetime import datetime
from app.airtable_client import MakeClient


@app.post("/health/tick")
def health_tick():
    make = MakeClient()

    now = datetime.utcnow().isoformat()

    make.create_record(
        table="System_Runs",
        fields={
            "Run_Label": "health_tick",
            "Type": "health",
            "Run_At": now,
            "Capability": "health_tick",
            "Provider": "worker",
            "Status": "OK",
            "Severity": "OK",
            "Summary": "Health tick executed"
        }
    )

    return {"ok": True, "tick": "executed"}
def health() -> Dict[str, Any]:
    return {"ok": True, "worker": WORKER_NAME}


@app.post("/run")
def run(req: RunRequest) -> Dict[str, Any]:
    try:
        make = MakeClient()
        airtable = AirtableClient()
        registry = build_registry(make, airtable)

        if req.intent not in registry:
            raise HTTPException(status_code=400, detail=f"Unknown intent: {req.intent}")

        # Execute
        result = registry[req.intent](req.args or {})

        return {"ok": True, "intent": req.intent, "result": result}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
