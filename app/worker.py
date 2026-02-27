import os
import json
import time
import uuid
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple

import requests
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, ConfigDict
from pydantic.aliases import AliasChoices


# ============================================================
# Env / settings
# ============================================================

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()

SYSTEM_RUNS_TABLE_NAME = os.getenv("SYSTEM_RUNS_TABLE_NAME", "System_Runs").strip()
LOGS_ERRORS_TABLE_NAME = os.getenv("LOGS_ERRORS_TABLE_NAME", "Logs_Erreurs").strip()
LOGS_ERRORS_VIEW_NAME = os.getenv("LOGS_ERRORS_VIEW_NAME", "Active").strip()

COMMANDS_TABLE_NAME = os.getenv("COMMANDS_TABLE_NAME", "Commands").strip()
COMMANDS_VIEW_NAME = os.getenv("COMMANDS_VIEW_NAME", "Queue").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()
APP_NAME = os.getenv("APP_NAME", "bosai-worker").strip()
APP_VERSION = os.getenv("APP_VERSION", "2.3.0").strip()

RUN_MAX_SECONDS = float(os.getenv("RUN_MAX_SECONDS", "30").strip() or "30")
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "20").strip() or "20")

# Signature HMAC (optionnelle). Si vide => pas de vérif signature.
RUN_SHARED_SECRET = os.getenv("RUN_SHARED_SECRET", "").strip()

# SLA thresholds (minutes)
SLA_WARNING_THRESHOLD_MIN = float(os.getenv("SLA_WARNING_THRESHOLD_MIN", "60").strip() or "60")

# Allowlist fields (Logs_Erreurs) — DOIT matcher Airtable exactement
LOGS_ERRORS_FIELDS_ALLOWED = set(
    [s.strip() for s in os.getenv(
        "LOGS_ERRORS_FIELDS_ALLOWED",
        "SLA_Status,Last_SLA_Check,Linked_Run"
    ).split(",")]
)

# SLA status options — DOIVENT matcher exactement les options Airtable (casse incluse)
SLA_STATUS_OK = os.getenv("SLA_STATUS_OK", "OK").strip()
SLA_STATUS_WARNING = os.getenv("SLA_STATUS_WARNING", "Warning").strip()
SLA_STATUS_BREACHED = os.getenv("SLA_STATUS_BREACHED", "Breached").strip()
SLA_STATUS_ESCALATED = os.getenv("SLA_STATUS_ESCALATED", "Escalated").strip()

# HTTP_EXEC allowlist (simple, optionnel)
HTTP_EXEC_ALLOWLIST = [s.strip() for s in os.getenv("HTTP_EXEC_ALLOWLIST", "").split(",") if s.strip()]


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# ============================================================
# Models
# ============================================================

class RunRequest(BaseModel):
    # Forbid extra keys by default (anti-chaos)
    model_config = ConfigDict(extra="forbid")

    worker: str = Field(default=WORKER_NAME)

    # Canon: capability (Airtable aussi)
    # Alias acceptés: capacity (legacy)
    capability: str = Field(
        ...,
        validation_alias=AliasChoices("capability", "capacity"),
        description="Capability name (canonical: capability).",
    )

    # Canon: idempotency_key
    idempotency_key: str = Field(
        ...,
        validation_alias=AliasChoices("idempotency_key", "idempotencyKey"),
    )

    priority: int = 1

    # Canon: input
    # Alias: inputs (legacy)
    input: Dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("input", "inputs"),
    )

    dry_run: bool = False

    # Optional knobs (used by command orchestrator)
    view: Optional[str] = None
    max_commands: int = 0
    command_id: Optional[str] = None


class RunResponse(BaseModel):
    ok: bool
    worker: str
    capability: str
    idempotency_key: str
    run_id: str
    airtable_record_id: Optional[str] = None
    result: Dict[str, Any] = Field(default_factory=dict)


# ============================================================
# Utilities
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _require_airtable() -> None:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise HTTPException(status_code=500, detail="Airtable env not configured (AIRTABLE_API_KEY / AIRTABLE_BASE_ID).")

def _airtable_url(table_name: str) -> str:
    return f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{table_name}"

def _airtable_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }

def airtable_create(table_name: str, fields: Dict[str, Any]) -> str:
    _require_airtable()
    r = requests.post(
        _airtable_url(table_name),
        headers=_airtable_headers(),
        json={"fields": fields},
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    if r.status_code >= 300:
        raise HTTPException(status_code=500, detail=f"Airtable create failed: {r.status_code} {r.text}")
    return r.json()["id"]

def airtable_update(table_name: str, record_id: str, fields: Dict[str, Any]) -> None:
    _require_airtable()
    r = requests.patch(
        f"{_airtable_url(table_name)}/{record_id}",
        headers=_airtable_headers(),
        json={"fields": fields},
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    if r.status_code >= 300:
        raise HTTPException(status_code=500, detail=f"Airtable update failed: {r.status_code} {r.text}")

def airtable_find_first(table_name: str, formula: str, max_records: int = 1) -> Optional[Dict[str, Any]]:
    _require_airtable()
    r = requests.get(
        _airtable_url(table_name),
        headers=_airtable_headers(),
        params={"filterByFormula": formula, "maxRecords": str(max_records)},
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    if r.status_code >= 300:
        raise HTTPException(status_code=500, detail=f"Airtable search failed: {r.status_code} {r.text}")
    records = r.json().get("records", [])
    return records[0] if records else None

def airtable_list_view(table_name: str, view_name: str, max_records: int = 100) -> List[Dict[str, Any]]:
    _require_airtable()
    r = requests.get(
        _airtable_url(table_name),
        headers=_airtable_headers(),
        params={"view": view_name, "maxRecords": str(max_records)},
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    if r.status_code >= 300:
        raise HTTPException(status_code=500, detail=f"Airtable view list failed: {r.status_code} {r.text}")
    return r.json().get("records", [])

def verify_signature_or_401(raw_body: bytes, signature_header: Optional[str]) -> None:
    if not RUN_SHARED_SECRET:
        return  # signature not enforced

    if not signature_header or not signature_header.startswith("sha256="):
        raise HTTPException(status_code=401, detail="Missing or invalid x-run-signature (expected sha256=...)")

    their_hex = signature_header.split("=", 1)[1].strip()
    ours = hmac.new(RUN_SHARED_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(their_hex, ours):
        raise HTTPException(status_code=401, detail="Invalid x-run-signature")


# ============================================================
# System_Runs helpers
# ============================================================

def create_system_run(req: RunRequest) -> str:
    fields = {
        "Run_ID": str(uuid.uuid4()),
        "Worker": req.worker,
        # Canon field name everywhere: capability
        "Capability": req.capability,
        "Idempotency_Key": req.idempotency_key,
        "Status": "Running",
        "Started_At": utc_now_iso(),
        "Priority": req.priority,
        "Dry_Run": bool(req.dry_run),
        "Input_JSON": json.dumps(req.input, ensure_ascii=False),
        "App_Name": APP_NAME,
        "App_Version": APP_VERSION,
    }
    return airtable_create(SYSTEM_RUNS_TABLE_NAME, fields)

def finish_system_run(record_id: str, status: str, result_obj: Dict[str, Any]) -> None:
    fields = {
        "Status": status,
        "Finished_At": utc_now_iso(),
        "Result_JSON": json.dumps(result_obj, ensure_ascii=False),
    }
    airtable_update(SYSTEM_RUNS_TABLE_NAME, record_id, fields)

def fail_system_run(record_id: str, error_message: str, meta: Optional[Dict[str, Any]] = None) -> None:
    payload = {"error": error_message}
    if meta:
        payload["meta"] = meta
    fields = {
        "Status": "Error",
        "Finished_At": utc_now_iso(),
        "Result_JSON": json.dumps(payload, ensure_ascii=False),
    }
    airtable_update(SYSTEM_RUNS_TABLE_NAME, record_id, fields)

def idempotency_lookup(req: RunRequest) -> Optional[Dict[str, Any]]:
    # If a previous run exists for this key+capability+worker AND is Done/Error,
    # return it. (Deterministic behavior)
    formula = (
        f"AND("
        f"{{Worker}}='{req.worker}',"
        f"{{Capability}}='{req.capability}',"
        f"{{Idempotency_Key}}='{req.idempotency_key}',"
        f"OR({{Status}}='Done',{{Status}}='Error')"
        f")"
    )
    return airtable_find_first(SYSTEM_RUNS_TABLE_NAME, formula=formula, max_records=1)


# ============================================================
# Capabilities
# ============================================================

def capability_health_tick(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    # Minimal: just proves Airtable write works + returns probe
    return {"ok": True, "probe": "airtable_ok", "ts": utc_now_iso()}

def _parse_float(val: Any) -> Optional[float]:
    if val is None:
        return None
    try:
        if isinstance(val, (int, float)):
            return float(val)
        s = str(val).strip().replace(",", ".")
        return float(s)
    except Exception:
        return None

def _sla_status_for_remaining(remaining_min: float) -> str:
    if remaining_min <= 0:
        return SLA_STATUS_BREACHED
    if remaining_min <= SLA_WARNING_THRESHOLD_MIN:
        return SLA_STATUS_WARNING
    return SLA_STATUS_OK

def capability_sla_machine(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    # Reads Logs_Erreurs view "Active", updates SLA_Status/Last_SLA_Check/Linked_Run
    records = airtable_list_view(LOGS_ERRORS_TABLE_NAME, LOGS_ERRORS_VIEW_NAME, max_records=200)

    updated = 0
    skipped = 0
    errors: List[str] = []

    for rec in records:
        rid = rec.get("id")
        fields = rec.get("fields", {})

        remaining = _parse_float(fields.get("SLA_Remaining_Minutes"))
        if remaining is None:
            skipped += 1
            continue

        current_status = str(fields.get("SLA_Status", "")).strip()
        # If already escalated, keep it
        if current_status == SLA_STATUS_ESCALATED:
            skipped += 1
            continue

        new_status = _sla_status_for_remaining(remaining)

        update_fields: Dict[str, Any] = {}

        if "SLA_Status" in LOGS_ERRORS_FIELDS_ALLOWED:
            update_fields["SLA_Status"] = new_status
        if "Last_SLA_Check" in LOGS_ERRORS_FIELDS_ALLOWED:
            update_fields["Last_SLA_Check"] = utc_now_iso()
        if "Linked_Run" in LOGS_ERRORS_FIELDS_ALLOWED:
            # Linked record expects array of record IDs
            update_fields["Linked_Run"] = [run_record_id]

        if not update_fields:
            skipped += 1
            continue

        try:
            airtable_update(LOGS_ERRORS_TABLE_NAME, rid, update_fields)
            updated += 1
        except HTTPException as e:
            errors.append(f"{rid}: {e.detail}")

    return {
        "ok": True,
        "updated": updated,
        "skipped": skipped,
        "errors_count": len(errors),
        "errors": errors[:10],
    }

def _is_url_allowed(url: str) -> bool:
    if not HTTP_EXEC_ALLOWLIST:
        return False
    return any(url.startswith(prefix) for prefix in HTTP_EXEC_ALLOWLIST)

def capability_http_exec(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    url = str(req.input.get("url", "")).strip()
    method = str(req.input.get("method", "GET")).strip().upper()
    headers = req.input.get("headers") or {}
    body = req.input.get("body")

    if not url or not _is_url_allowed(url):
        raise HTTPException(status_code=400, detail="HTTP_EXEC url not allowed (check HTTP_EXEC_ALLOWLIST).")

    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        raise HTTPException(status_code=400, detail="HTTP_EXEC invalid method.")

    r = requests.request(method, url, headers=headers, json=body, timeout=HTTP_TIMEOUT_SECONDS)
    return {
        "ok": True,
        "status_code": r.status_code,
        "text": r.text[:2000],
    }

def capability_command_orchestrator(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    # Minimal orchestrator: just scans the view and returns count.
    # (No write-back here to avoid chaos unless you want it.)
    max_cmds = int(req.max_commands or 0)
    if max_cmds <= 0:
        max_cmds = 5

    cmds = airtable_list_view(COMMANDS_TABLE_NAME, COMMANDS_VIEW_NAME, max_records=max_cmds)
    return {
        "ok": True,
        "scanned": len(cmds),
        "executed": 0,
        "succeeded": 0,
        "failed": 0,
        "blocked": 0,
        "unsupported": 0,
        "commands_record_ids": [c.get("id") for c in cmds],
    }


CAPABILITIES = {
    "health_tick": capability_health_tick,
    "sla_machine": capability_sla_machine,
    "http_exec": capability_http_exec,
    "command_orchestrator": capability_command_orchestrator,
}


# ============================================================
# Routes
# ============================================================

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "app": APP_NAME,
        "version": APP_VERSION,
        "worker": WORKER_NAME,
        "ts": utc_now_iso(),
    }

@app.get("/health/score")
def health_score() -> Dict[str, Any]:
    # Simple deterministic score (expand later if needed)
    score = 100
    issues = []
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        score -= 50
        issues.append("airtable_env_missing")
    if RUN_SHARED_SECRET:
        issues.append("signature_enforced")
    return {"ok": True, "score": max(0, score), "issues": issues, "ts": utc_now_iso()}

@app.post("/run", response_model=RunResponse)
async def run(request: Request) -> RunResponse:
    started = time.time()
    raw = await request.body()
    verify_signature_or_401(raw, request.headers.get("x-run-signature"))

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    # Parse with pydantic (anti-chaos)
    req = RunRequest.model_validate(payload)

    # Strict timebox
    if (time.time() - started) > RUN_MAX_SECONDS:
        raise HTTPException(status_code=408, detail="Request timed out before start.")

    # Idempotency: if already done/error, return existing result deterministically
    existing = idempotency_lookup(req)
    if existing:
        fields = existing.get("fields", {})
        existing_result = {}
        try:
            existing_result = json.loads(fields.get("Result_JSON", "{}") or "{}")
        except Exception:
            existing_result = {"note": "Result_JSON unreadable"}
        return RunResponse(
            ok=True,
            worker=req.worker,
            capability=req.capability,
            idempotency_key=req.idempotency_key,
            run_id=str(fields.get("Run_ID", "")) or "unknown",
            airtable_record_id=existing.get("id"),
            result={"idempotent_replay": True, "previous": existing_result},
        )

    # Create System_Runs record
    run_record_id = create_system_run(req)

    try:
        fn = CAPABILITIES.get(req.capability)
        if not fn:
            finish_system_run(run_record_id, "Unsupported", {"ok": False, "error": "unsupported_capability"})
            raise HTTPException(status_code=400, detail=f"Unsupported capability: {req.capability}")

        if req.dry_run:
            result_obj = {"ok": True, "dry_run": True, "would_execute": req.capability}
            finish_system_run(run_record_id, "Done", result_obj)
            return RunResponse(
                ok=True,
                worker=req.worker,
                capability=req.capability,
                idempotency_key=req.idempotency_key,
                run_id=run_record_id,
                airtable_record_id=run_record_id,
                result=result_obj,
            )

        result_obj = fn(req, run_record_id)
        finish_system_run(run_record_id, "Done", result_obj)

        return RunResponse(
            ok=True,
            worker=req.worker,
            capability=req.capability,
            idempotency_key=req.idempotency_key,
            run_id=run_record_id,
            airtable_record_id=run_record_id,
            result=result_obj,
        )

    except HTTPException as e:
        fail_system_run(run_record_id, str(e.detail))
        raise
    except Exception as e:
        fail_system_run(run_record_id, repr(e))
        raise HTTPException(status_code=500, detail="Internal error.")
