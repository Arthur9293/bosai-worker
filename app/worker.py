# app/worker.py
# BOSAI Worker — stable baseline (v2.1.0 style)
# - FastAPI: /health, /health/score, /health/tick, /sla/tick, /run
# - Airtable logging: System_Runs + Logs_Erreurs updates
# - Idempotency + locking + retry (<=3)
# - NO OpenAI usage (no OPENAI env needed)

import os
import json
import time
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


# =========================
# Utils
# =========================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        return int(raw)
    except Exception:
        return default


def env_float(name: str, default: float) -> float:
    raw = os.getenv(name, str(default)).strip()
    try:
        return float(raw)
    except Exception:
        return default


# =========================
# Env / Settings
# =========================

AIRTABLE_API_KEY = env_str("AIRTABLE_API_KEY", "")
AIRTABLE_BASE_ID = env_str("AIRTABLE_BASE_ID", "")

# tables
SYSTEM_RUNS_TABLE_NAME = env_str("SYSTEM_RUNS_TABLE_NAME", "System_Runs")
LOGS_ERRORS_TABLE_NAME = env_str("LOGS_ERRORS_TABLE_NAME", "Logs_Erreurs")

# views (optional)
LOGS_ERRORS_VIEW_NAME = env_str("LOGS_ERRORS_VIEW_NAME", "Active")

# linking field name in System_Runs that links to Commands (optional)
SYSTEM_RUNS_COMMAND_LINK_FIELD = env_str("SYSTEM_RUNS_COMMAND_LINK_FIELD", "Commands")

# app
WORKER_NAME = env_str("WORKER_NAME", "bosai-worker-01")
APP_NAME = env_str("APP_NAME", "bosai-worker")
APP_VERSION = env_str("APP_VERSION", "2.1.0")

PORT = env_int("PORT", 10000)
RUN_MAX_SECONDS = env_float("RUN_MAX_SECONDS", 30.0)
MAX_RETRY = env_int("MAX_RETRY", 3)

# SLA related fields (names in Logs_Erreurs)
LE_FIELD_SLA_STATUS = env_str("LE_FIELD_SLA_STATUS", "SLA_Status")
LE_FIELD_LAST_SLA_CHECK = env_str("LE_FIELD_LAST_SLA_CHECK", "Last_SLA_Check")
LE_FIELD_LINKED_RUN = env_str("LE_FIELD_LINKED_RUN", "Linked_Run")

# Run record fields in System_Runs (names in System_Runs)
SR_FIELD_STATUS = env_str("SR_FIELD_STATUS", "Status")
SR_FIELD_STARTED_AT = env_str("SR_FIELD_STARTED_AT", "Started_At")
SR_FIELD_FINISHED_AT = env_str("SR_FIELD_FINISHED_AT", "Finished_At")
SR_FIELD_WORKER = env_str("SR_FIELD_WORKER", "Worker")
SR_FIELD_APP = env_str("SR_FIELD_APP", "App")
SR_FIELD_VERSION = env_str("SR_FIELD_VERSION", "Version")
SR_FIELD_CAPABILITY = env_str("SR_FIELD_CAPABILITY", "Capability")
SR_FIELD_IDEMPOTENCY_KEY = env_str("SR_FIELD_IDEMPOTENCY_KEY", "Idempotency_Key")
SR_FIELD_REQUEST = env_str("SR_FIELD_REQUEST", "Request_JSON")
SR_FIELD_RESULT = env_str("SR_FIELD_RESULT", "Result_JSON")
SR_FIELD_ERROR = env_str("SR_FIELD_ERROR", "Error")
SR_FIELD_RETRY_COUNT = env_str("SR_FIELD_RETRY_COUNT", "Retry_Count")
SR_FIELD_LOCK_KEY = env_str("SR_FIELD_LOCK_KEY", "Lock_Key")

# Status values (must match Airtable Single Select EXACTLY if you use single select)
STATUS_QUEUED = env_str("STATUS_QUEUED", "Queued")
STATUS_RUNNING = env_str("STATUS_RUNNING", "Running")
STATUS_DONE = env_str("STATUS_DONE", "Done")
STATUS_ERROR = env_str("STATUS_ERROR", "Error")
STATUS_BLOCKED = env_str("STATUS_BLOCKED", "Blocked")
STATUS_UNSUPPORTED = env_str("STATUS_UNSUPPORTED", "Unsupported")


# =========================
# Airtable Client
# =========================

class AirtableClient:
    def __init__(self, api_key: str, base_id: str, timeout: float = 20.0):
        self.api_key = api_key
        self.base_id = base_id
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _url(self, table_name: str) -> str:
        return f"https://api.airtable.com/v0/{self.base_id}/{table_name}"

    def _check_ready(self):
        if not self.api_key or not self.base_id:
            raise HTTPException(
                status_code=500,
                detail="Airtable is not configured: AIRTABLE_API_KEY and/or AIRTABLE_BASE_ID missing.",
            )

    def create_record(self, table_name: str, fields: Dict[str, Any]) -> str:
        self._check_ready()
        r = requests.post(
            self._url(table_name),
            headers=self._headers(),
            json={"fields": fields},
            timeout=self.timeout,
        )
        if r.status_code >= 300:
            raise HTTPException(status_code=500, detail=f"Airtable create_record failed: {r.status_code} {r.text}")
        data = r.json()
        return data["id"]

    def update_record(self, table_name: str, record_id: str, fields: Dict[str, Any]) -> None:
        self._check_ready()
        r = requests.patch(
            f"{self._url(table_name)}/{record_id}",
            headers=self._headers(),
            json={"fields": fields},
            timeout=self.timeout,
        )
        if r.status_code >= 300:
            raise HTTPException(status_code=500, detail=f"Airtable update_record failed: {r.status_code} {r.text}")

    def get_record(self, table_name: str, record_id: str) -> Dict[str, Any]:
        self._check_ready()
        r = requests.get(
            f"{self._url(table_name)}/{record_id}",
            headers=self._headers(),
            timeout=self.timeout,
        )
        if r.status_code >= 300:
            raise HTTPException(status_code=500, detail=f"Airtable get_record failed: {r.status_code} {r.text}")
        return r.json()

    def search_records(
        self,
        table_name: str,
        formula: Optional[str] = None,
        view: Optional[str] = None,
        max_records: int = 50,
        fields: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        self._check_ready()
        params: Dict[str, Any] = {"pageSize": max_records}
        if formula:
            params["filterByFormula"] = formula
        if view:
            params["view"] = view
        if fields:
            # Airtable expects repeated "fields[]" parameters
            for i, f in enumerate(fields):
                params[f"fields[{i}]"] = f

        r = requests.get(self._url(table_name), headers=self._headers(), params=params, timeout=self.timeout)
        if r.status_code >= 300:
            raise HTTPException(status_code=500, detail=f"Airtable search_records failed: {r.status_code} {r.text}")
        return r.json().get("records", [])


# =========================
# API Models
# =========================

class RunRequest(BaseModel):
    worker: str = Field(default=WORKER_NAME)
    capability: str = Field(..., description="Capability name (e.g. health_tick, sla_tick)")
    idempotency_key: Optional[str] = Field(default=None, description="Idempotency key for dedup")
    command_record_id: Optional[str] = Field(default=None, description="Optional Airtable Commands record id")
    args: Dict[str, Any] = Field(default_factory=dict, description="Optional extra args")
    input: Dict[str, Any] = Field(default_factory=dict, description="Capability input payload")


class RunResponse(BaseModel):
    ok: bool
    status: str
    run_id: Optional[str] = None
    worker: str
    capability: str
    idempotency_key: Optional[str] = None
    detail: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


class TickRequest(BaseModel):
    worker: str = Field(default=WORKER_NAME)
    idempotency_key: Optional[str] = None
    input: Dict[str, Any] = Field(default_factory=dict)


# =========================
# Core Engine
# =========================

def compute_lock_key(capability: str, idempotency_key: Optional[str], payload: Dict[str, Any]) -> str:
    # Deterministic lock over (capability + idempotency_key + payload)
    base = {
        "capability": capability,
        "idempotency_key": idempotency_key,
        "payload": payload,
    }
    return sha256_hex(stable_json(base))


def make_run_fields(req: RunRequest, status: str, lock_key: str) -> Dict[str, Any]:
    fields: Dict[str, Any] = {
        SR_FIELD_STATUS: status,
        SR_FIELD_WORKER: WORKER_NAME,
        SR_FIELD_APP: APP_NAME,
        SR_FIELD_VERSION: APP_VERSION,
        SR_FIELD_CAPABILITY: req.capability,
        SR_FIELD_IDEMPOTENCY_KEY: req.idempotency_key or "",
        SR_FIELD_LOCK_KEY: lock_key,
        SR_FIELD_REQUEST: stable_json(req.model_dump()),
        SR_FIELD_RETRY_COUNT: 0,
        SR_FIELD_STARTED_AT: utc_now_iso(),
    }
    # Optional link to Commands
    if req.command_record_id:
        fields[SYSTEM_RUNS_COMMAND_LINK_FIELD] = [req.command_record_id]
    return fields


def update_run_start(at: AirtableClient, run_id: str) -> None:
    at.update_record(
        SYSTEM_RUNS_TABLE_NAME,
        run_id,
        {
            SR_FIELD_STATUS: STATUS_RUNNING,
            SR_FIELD_STARTED_AT: utc_now_iso(),
        },
    )


def update_run_finish(at: AirtableClient, run_id: str, status: str, result: Optional[Dict[str, Any]] = None, error: str = "") -> None:
    fields: Dict[str, Any] = {
        SR_FIELD_STATUS: status,
        SR_FIELD_FINISHED_AT: utc_now_iso(),
    }
    if result is not None:
        fields[SR_FIELD_RESULT] = stable_json(result)
    if error:
        fields[SR_FIELD_ERROR] = error[:5000]
    at.update_record(SYSTEM_RUNS_TABLE_NAME, run_id, fields)


def find_existing_run_by_lock(at: AirtableClient, lock_key: str) -> Optional[Dict[str, Any]]:
    # Search System_Runs where Lock_Key equals lock_key and Status in (Running, Done)
    # Airtable formula: AND({Lock_Key}="...", OR({Status}="Running",{Status}="Done"))
    formula = f'AND({{{SR_FIELD_LOCK_KEY}}}="{lock_key}", OR({{{SR_FIELD_STATUS}}}="{STATUS_RUNNING}", {{{SR_FIELD_STATUS}}}="{STATUS_DONE}"))'
    recs = at.search_records(SYSTEM_RUNS_TABLE_NAME, formula=formula, max_records=1)
    return recs[0] if recs else None


# =========================
# Capabilities
# =========================

def capability_health_tick(req: RunRequest) -> Dict[str, Any]:
    # Pure function result
    return {
        "ok": True,
        "worker": WORKER_NAME,
        "app": APP_NAME,
        "version": APP_VERSION,
        "ts": utc_now_iso(),
        "input": req.input,
    }


def capability_sla_tick(at: AirtableClient, run_id: str, req: RunRequest) -> Dict[str, Any]:
    """
    SLA Machine V1 (minimal):
    - reads Logs_Erreurs view LOGS_ERRORS_VIEW_NAME (Active)
    - updates fields:
        - SLA_Status = "OK" (or value you decide later)
        - Last_SLA_Check = now
        - Linked_Run = [run_id]  (link field recommended; if it's text, Airtable will reject)
    IMPORTANT: If Linked_Run is NOT a linked-record field, comment out that line.
    """
    now = utc_now_iso()
    records = at.search_records(
        LOGS_ERRORS_TABLE_NAME,
        view=LOGS_ERRORS_VIEW_NAME or None,
        max_records=25,
    )

    updated = 0
    errors: List[str] = []

    for r in records:
        rid = r.get("id")
        if not rid:
            continue
        try:
            fields: Dict[str, Any] = {
                LE_FIELD_SLA_STATUS: "OK",          # must match your single select options if single select
                LE_FIELD_LAST_SLA_CHECK: now,
            }

            # If Linked_Run is a linked-record field to System_Runs, keep it:
            # fields[LE_FIELD_LINKED_RUN] = [run_id]
            #
            # If it's a text field, use:
            # fields[LE_FIELD_LINKED_RUN] = run_id

            fields[LE_FIELD_LINKED_RUN] = [run_id]

            at.update_record(LOGS_ERRORS_TABLE_NAME, rid, fields)
            updated += 1
        except Exception as e:
            errors.append(f"{rid}: {str(e)}")

    return {
        "ok": True,
        "ts": now,
        "checked": len(records),
        "updated": updated,
        "errors": errors[:10],
    }


# =========================
# FastAPI App
# =========================

app = FastAPI(title=APP_NAME, version=APP_VERSION)


@app.get("/health")
def health():
    return {"ok": True, "worker": WORKER_NAME, "ts": utc_now_iso()}


@app.get("/health/score")
def health_score():
    # Minimal score; later you can compute from System_Runs / SLA
    return {
        "ok": True,
        "worker": WORKER_NAME,
        "ts": utc_now_iso(),
        "score": 100,
        "signals": {
            "airtable_configured": bool(AIRTABLE_API_KEY and AIRTABLE_BASE_ID),
            "run_max_seconds": RUN_MAX_SECONDS,
            "max_retry": MAX_RETRY,
        },
    }


@app.post("/health/tick")
def health_tick(req: TickRequest):
    # This endpoint exists mainly for manual probing; it doesn't need Airtable.
    rr = RunRequest(
        worker=req.worker,
        capability="health_tick",
        idempotency_key=req.idempotency_key,
        input=req.input,
    )
    result = capability_health_tick(rr)
    return {"ok": True, "result": result}


@app.post("/sla/tick")
def sla_tick(req: TickRequest):
    # SLA tick uses Airtable; will error if not configured.
    at = AirtableClient(AIRTABLE_API_KEY, AIRTABLE_BASE_ID)
    rr = RunRequest(
        worker=req.worker,
        capability="sla_tick",
        idempotency_key=req.idempotency_key,
        input=req.input,
    )

    lock_key = compute_lock_key(rr.capability, rr.idempotency_key, rr.model_dump())
    existing = find_existing_run_by_lock(at, lock_key)
    if existing:
        return {"ok": True, "deduped": True, "existing_run_id": existing.get("id")}

    run_id = at.create_record(SYSTEM_RUNS_TABLE_NAME, make_run_fields(rr, STATUS_QUEUED, lock_key))
    update_run_start(at, run_id)

    try:
        result = capability_sla_tick(at, run_id, rr)
        update_run_finish(at, run_id, STATUS_DONE, result=result)
        return {"ok": True, "run_id": run_id, "result": result}
    except Exception as e:
        update_run_finish(at, run_id, STATUS_ERROR, error=str(e))
        raise


@app.post("/run", response_model=RunResponse)
def run(req: RunRequest):
    # Validate worker target (optional)
    if req.worker and req.worker != WORKER_NAME:
        # Not fatal; but helps you route in multi-worker later
        pass

    at = AirtableClient(AIRTABLE_API_KEY, AIRTABLE_BASE_ID)

    # Lock / idempotency
    lock_key = compute_lock_key(req.capability, req.idempotency_key, req.model_dump())
    existing = find_existing_run_by_lock(at, lock_key)
    if existing:
        return RunResponse(
            ok=True,
            status=existing.get("fields", {}).get(SR_FIELD_STATUS, STATUS_DONE),
            run_id=existing.get("id"),
            worker=WORKER_NAME,
            capability=req.capability,
            idempotency_key=req.idempotency_key,
            detail="deduped_by_lock_key",
        )

    # Create run
    run_id = at.create_record(SYSTEM_RUNS_TABLE_NAME, make_run_fields(req, STATUS_QUEUED, lock_key))
    update_run_start(at, run_id)

    start = time.time()
    try:
        # Dispatch
        if req.capability == "health_tick":
            result = capability_health_tick(req)
            update_run_finish(at, run_id, STATUS_DONE, result=result)
            return RunResponse(
                ok=True,
                status=STATUS_DONE,
                run_id=run_id,
                worker=WORKER_NAME,
                capability=req.capability,
                idempotency_key=req.idempotency_key,
                result=result,
            )

        if req.capability == "sla_tick":
            result = capability_sla_tick(at, run_id, req)
            update_run_finish(at, run_id, STATUS_DONE, result=result)
            return RunResponse(
                ok=True,
                status=STATUS_DONE,
                run_id=run_id,
                worker=WORKER_NAME,
                capability=req.capability,
                idempotency_key=req.idempotency_key,
                result=result,
            )

        # Unsupported capability
        result = {"ok": False, "reason": "unsupported_capability", "capability": req.capability}
        update_run_finish(at, run_id, STATUS_UNSUPPORTED, result=result)
        return RunResponse(
            ok=False,
            status=STATUS_UNSUPPORTED,
            run_id=run_id,
            worker=WORKER_NAME,
            capability=req.capability,
            idempotency_key=req.idempotency_key,
            detail="unsupported_capability",
            result=result,
        )

    except HTTPException as e:
        # Already structured
        update_run_finish(at, run_id, STATUS_ERROR, error=str(e.detail))
        raise
    except Exception as e:
        update_run_finish(at, run_id, STATUS_ERROR, error=str(e))
        raise
    finally:
        elapsed = time.time() - start
        if elapsed > RUN_MAX_SECONDS:
            # Not raising here; just informational. You can later enforce hard timeout.
            pass


# =========================
# Local entry (optional)
# =========================

# Render usually runs via "uvicorn app.worker:app --host 0.0.0.0 --port $PORT"
# Keeping this for local run: python3 app/worker.py
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.worker:app", host="0.0.0.0", port=PORT, reload=False)
