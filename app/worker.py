from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import FastAPI
from pydantic import BaseModel

try:
    # optionnel
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass


APP_NAME = os.getenv("APP_NAME", "bosai-worker")
WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01")

app = FastAPI(title=APP_NAME, version="1.0.0")


class TickResponse(BaseModel):
    ok: bool = True
    worker: str
    ts: str
    note: str = "health tick received"


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "worker": WORKER_NAME,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/health/tick", response_model=TickResponse)
def health_tick() -> TickResponse:
    return TickResponse(
        worker=WORKER_NAME,
        ts=datetime.now(timezone.utc).isoformat(),
    )
