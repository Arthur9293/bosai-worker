# app/worker.py — BOSAI Worker (v2.3.5)
# SAFE from v2.3.4 baseline:
# - Keeps GET /, HEAD /, /health, /health/score, POST /run behavior
# - Status_select schema for System_Runs
# - Idempotency lookup: Idempotency_Key + Status_select only
# - Commands Orchestrator V1 unchanged
# NEW (No-Chaos): Lock TTL Cleanup for stale Running runs (Status_select='Running' too old)

import os
import json
import time
import uuid
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

import requests
from fastapi import FastAPI, HTTPException, Request, Response
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
APP_VERSION = os.getenv("APP_VERSION", "2.3.5").strip()  # bump safe (lock TTL cleanup)

RUN_MAX_SECONDS = float(os.getenv("RUN_MAX_SECONDS", "30").strip() or "30")
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "20").strip() or "20")

# No-Chaos: stale "Running" lock TTL cleanup (seconds)
RUN_LOCK_TTL_SECONDS = int(os.getenv("RUN_LOCK_TTL_SECONDS", "600").strip() or "600")

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
    command_id: Optional[str] = None  # (reserved; not used in V1)


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

# convenience wrapper (name makes intent explicit)
def airtable_update_fields(table_name: str, record_id: str, fields: Dict[str, Any]) -> None:
    airtable_update(table_name, record_id, fields)

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

def _json_load_maybe(val: Any) -> Dict[str, Any]:
    """
    Accepts:
      - dict -> returned as-is
      - JSON string -> parsed
      - None/"" -> {}
    """
    if val is None:
        return {}
    if isinstance(val, dict):
        return val
    try:
        s = str(val).strip()
        if not s:
            return {}
        return json.loads(s)
    except Exception:
        return {}

def verify_signature_or_401(raw_body: bytes, signature_header: Optional[str]) -> None:
    if not RUN_SHARED_SECRET:
        return  # signature not enforced

    if not signature_header or not signature_header.startswith("sha256="):
        raise HTTPException(status_code=401, detail="Missing or invalid x-run-signature (expected sha256=...)")

    their_hex = signature_header.split("=", 1)[1].strip()
    ours = hmac.new(RUN_SHARED_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(their_hex, ours):
        raise HTTPException(status_code=401, detail="Invalid x-run-signature")


def cleanup_stale_runs() -> Dict[str, Any]:
    """
    No-Chaos Lock TTL Cleanup (SAFE):
    - Finds System_Runs stuck in Status_select='Running' with Started_At older than TTL
    - Marks them as Status_select='Error' with Result_JSON={"error":"lock_ttl_expired"}
    - Never blocks /run; returns noop report on schema/formula issues
    """
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        return {"ok": True, "noop": True, "reason": "airtable_env_missing"}

    ttl = int(RUN_LOCK_TTL_SECONDS or 600)

    formula = (
        "AND("
        "{Status_select}='Running',"
        f"DATETIME_DIFF(NOW(), {{Started_At}}, 'seconds') > {ttl}"
        ")"
    )

    try:
        r = requests.get(
            _airtable_url(SYSTEM_RUNS_TABLE_NAME),
            headers=_airtable_headers(),
            params={"filterByFormula": formula, "maxRecords": "10"},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        if r.status_code >= 300:
            if "INVALID_FILTER_BY_FORMULA" in r.text:
                return {"ok": True, "noop": True, "reason": "invalid_filter_formula"}
            return {"ok": False, "error": f"airtable_list_failed:{r.status_code}"}

        records = r.json().get("records", []) or []
        cleaned = 0

        for rec in records:
            rid = rec.get("id")
            if not rid:
                continue
            try:
                airtable_update_fields(SYSTEM_RUNS_TABLE_NAME, rid, {
                    "Status_select": "Error",
                    "Finished_At": utc_now_iso(),
                    "Result_JSON": json.dumps({"error": "lock_ttl_expired"}, ensure_ascii=False),
                })
                cleaned += 1
            except Exception:
                continue

        return {"ok": True, "ttl_seconds": ttl, "found": len(records), "cleaned": cleaned}

    except Exception as e:
        return {"ok": True, "noop": True, "reason": "exception", "detail": repr(e)}


# ============================================================
# System_Runs helpers (Status_select schema)
# ============================================================

def create_system_run(req: RunRequest) -> str:
    fields = {
        "Run_ID": str(uuid.uuid4()),
        "Worker": req.worker,
        "Capability": req.capability,
        "Idempotency_Key": req.idempotency_key,
        "Status_select": "Running",
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
        "Status_select": status,
        "Finished_At": utc_now_iso(),
        "Result_JSON": json.dumps(result_obj, ensure_ascii=False),
    }
    airtable_update(SYSTEM_RUNS_TABLE_NAME, record_id, fields)

def fail_system_run(record_id: str, error_message: str, meta: Optional[Dict[str, Any]] = None) -> None:
    payload = {"error": error_message}
    if meta:
        payload["meta"] = meta
    fields = {
        "Status_select": "Error",
        "Finished_At": utc_now_iso(),
        "Result_JSON": json.dumps(payload, ensure_ascii=False),
    }
    airtable_update(SYSTEM_RUNS_TABLE_NAME, record_id, fields)

def idempotency_lookup(req: RunRequest) -> Optional[Dict[str, Any]]:
    # SAFE: do not depend on {Worker}/{Capability} field names.
    # Idempotency_Key must be unique across the system.
    formula = (
        f"AND("
        f"{{Idempotency_Key}}='{req.idempotency_key}',"
        f"OR({{Status_select}}='Done',{{Status_select}}='Error')"
        f")"
    )
    try:
        return airtable_find_first(SYSTEM_RUNS_TABLE_NAME, formula=formula, max_records=1)
    except HTTPException as e:
        # Anti-chaos: if formula mismatches schema, do not crash the worker.
        if "INVALID_FILTER_BY_FORMULA" in str(e.detail):
            return None
        raise


# ============================================================
# Capabilities
# ============================================================

def capability_health_tick(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
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
    """
    Commands Orchestrator V1 (SAFE):
    - Lists Commands records from a view (default: COMMANDS_VIEW_NAME)
    - Only executes records whose Status_select is "Queued" (or empty)
    - Writes back Status_select: Running -> Done/Error/Unsupported
    - Uses per-command Idempotency_Key if present, else derives stable key from record id + capability
    - Expects Airtable fields in Commands table (exact names):
        Status_select, Capability, Input_JSON, Result_JSON, Error_Message, Idempotency_Key, Linked_Run
    """
    max_cmds = int(req.max_commands or 0) or 5
    view = (req.view or COMMANDS_VIEW_NAME or "Queue").strip()

    cmds = airtable_list_view(COMMANDS_TABLE_NAME, view, max_records=max_cmds)

    executed = 0
    succeeded = 0
    failed = 0
    blocked = 0
    unsupported = 0

    processed_ids: List[str] = []
    errors: List[str] = []

    for c in cmds:
        cid = c.get("id")
        fields = c.get("fields", {}) or {}
        if not cid:
            continue

        processed_ids.append(cid)

        status = str(fields.get("Status_select", "")).strip()
        if status and status not in ("Queued", "QUEUE", "Queue"):
            blocked += 1
            continue

        capability = str(fields.get("Capability", "")).strip()
        if not capability:
            failed += 1
            try:
                airtable_update_fields(COMMANDS_TABLE_NAME, cid, {
                    "Status_select": "Error",
                    "Error_Message": "Missing Capability",
                    "Linked_Run": [run_record_id],
                })
            except Exception:
                pass
            continue

        fn = CAPABILITIES.get(capability)
        if not fn:
            unsupported += 1
            try:
                airtable_update_fields(COMMANDS_TABLE_NAME, cid, {
                    "Status_select": "Unsupported",
                    "Error_Message": f"Unsupported capability: {capability}",
                    "Linked_Run": [run_record_id],
                })
            except Exception:
                pass
            continue

        idem = str(fields.get("Idempotency_Key", "")).strip()
        if not idem:
            idem = f"cmd:{cid}:{capability}"

        cmd_input = _json_load_maybe(fields.get("Input_JSON"))

        # Mark Running (if Airtable refuses => do not execute)
        try:
            airtable_update_fields(COMMANDS_TABLE_NAME, cid, {
                "Status_select": "Running",
                "Idempotency_Key": idem,
                "Linked_Run": [run_record_id],
                "Error_Message": "",
            })
        except Exception:
            blocked += 1
            continue

        executed += 1

        try:
            cmd_req = RunRequest.model_validate({
                "worker": req.worker,
                "capability": capability,
                "idempotency_key": idem,
                "input": cmd_input,
                "priority": req.priority,
                "dry_run": bool(req.dry_run),
            })

            result_obj = fn(cmd_req, run_record_id)

            airtable_update_fields(COMMANDS_TABLE_NAME, cid, {
                "Status_select": "Done",
                "Result_JSON": json.dumps(result_obj, ensure_ascii=False),
                "Linked_Run": [run_record_id],
            })
            succeeded += 1

        except HTTPException as e:
            msg = str(e.detail)
            failed += 1
            try:
                airtable_update_fields(COMMANDS_TABLE_NAME, cid, {
                    "Status_select": "Error",
                    "Error_Message": msg,
                    "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                    "Linked_Run": [run_record_id],
                })
            except Exception:
                pass
            errors.append(f"{cid}: {msg}")

        except Exception as e:
            msg = repr(e)
            failed += 1
            try:
                airtable_update_fields(COMMANDS_TABLE_NAME, cid, {
                    "Status_select": "Error",
                    "Error_Message": msg,
                    "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                    "Linked_Run": [run_record_id],
                })
            except Exception:
                pass
            errors.append(f"{cid}: {msg}")

    return {
        "ok": True,
        "view": view,
        "scanned": len(cmds),
        "executed": executed,
        "succeeded": succeeded,
        "failed": failed,
        "blocked": blocked,
        "unsupported": unsupported,
        "commands_record_ids": processed_ids,
        "errors_count": len(errors),
        "errors": errors[:10],
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

@app.get("/")
def root() -> Dict[str, Any]:
    # Render health pings "/" (GET/HEAD). This prevents 404/405 in logs.
    return {"ok": True, "service": APP_NAME, "version": APP_VERSION}

@app.head("/")
def root_head() -> Response:
    # Render health ping uses HEAD /
    return Response(status_code=200)

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

    req = RunRequest.model_validate(payload)

    # No-Chaos: cleanup stale running locks (must never block /run)
    cleanup_stale_runs()

    if (time.time() - started) > RUN_MAX_SECONDS:
        raise HTTPException(status_code=408, detail="Request timed out before start.")

    existing = idempotency_lookup(req)
    if existing:
        fields = existing.get("fields", {})
        existing_result: Dict[str, Any] = {}
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
