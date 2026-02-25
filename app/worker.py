import os
import json
import time
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple, Union

import requests
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from fastapi import Response 

# ============================================================
# Version / Identity
# ============================================================

WORKER_VERSION = "2.2.1"
DEFAULT_WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()
DEFAULT_APP_NAME = os.getenv("APP_NAME", "bosai-worker").strip()
DEFAULT_ENV = os.getenv("APP_ENV", "local").strip()

# NOTE: IMPORTANT — no Is_bad field, no Is_bad logic. Ever.

# ============================================================
# Airtable config (ENV)
# ============================================================

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()

SYSTEM_RUNS_TABLE = os.getenv("SYSTEM_RUNS_TABLE", "System_Runs").strip()
LOGS_ERRORS_TABLE = os.getenv("LOGS_ERRORS_TABLE", "Logs_Erreurs").strip()
COMMANDS_TABLE = os.getenv("COMMANDS_TABLE", "Commands").strip()

# Views
LOGS_ERRORS_VIEW_DEFAULT = os.getenv("LOGS_ERRORS_VIEW_DEFAULT", "Active").strip()
COMMANDS_VIEW_DEFAULT = os.getenv("COMMANDS_VIEW_DEFAULT", "Grid view").strip()

# Optional signature secret for /run endpoint (recommended later)
RUN_SHARED_SECRET = os.getenv("RUN_SHARED_SECRET", "").strip()

AIRTABLE_API_URL = "https://api.airtable.com/v0"

# ============================================================
# Airtable field names (System_Runs) — must match Airtable exactly
# (Defaults align with your screenshots)
# ============================================================

SR_RUN_ID = os.getenv("SR_RUN_ID", "Run_ID").strip()
SR_WORKER_NAME = os.getenv("SR_WORKER_NAME", "Worker_Name").strip()
SR_APP = os.getenv("SR_APP", "App").strip()
SR_VERSION = os.getenv("SR_VERSION", "Version").strip()
SR_CAPABILITY = os.getenv("SR_CAPABILITY", "Capability").strip()
SR_PRIORITY = os.getenv("SR_PRIORITY", "Priority").strip()
SR_IDEMPOTENCY_KEY = os.getenv("SR_IDEMPOTENCY_KEY", "Idempotency_Key").strip()
SR_STATUS = os.getenv("SR_STATUS", "Status_select").strip()
SR_STARTED_AT = os.getenv("SR_STARTED_AT", "Last_Started_At").strip()
SR_FINISHED_AT = os.getenv("SR_FINISHED_AT", "Finished_At").strip()
SR_DURATION_MS = os.getenv("SR_DURATION_MS", "Duration_ms").strip()
SR_PAYLOAD_JSON = os.getenv("SR_PAYLOAD_JSON", "Payload_JSON").strip()
SR_RESULT_JSON = os.getenv("SR_RESULT_JSON", "Result_JSON").strip()
SR_ERROR_MESSAGE = os.getenv("SR_ERROR_MESSAGE", "Error_Message").strip()  # optional; ok if missing

# IMPORTANT: only use statuses that exist in your Airtable options
SR_STATUS_RUNNING = os.getenv("SR_STATUS_RUNNING", "Running").strip()
SR_STATUS_DONE = os.getenv("SR_STATUS_DONE", "Done").strip()
SR_STATUS_ERROR = os.getenv("SR_STATUS_ERROR", "Error").strip()
SR_STATUS_BLOCKED = os.getenv("SR_STATUS_BLOCKED", "Blocked").strip()
SR_STATUS_CANCELED = os.getenv("SR_STATUS_CANCELED", "canceled").strip()

# ============================================================
# Airtable field names (Commands) — must match Airtable exactly
# ============================================================

CMD_STATUS = os.getenv("CMD_STATUS", "Status_select").strip()
CMD_CAPABILITY = os.getenv("CMD_CAPABILITY", "Capability").strip()
CMD_PRIORITY = os.getenv("CMD_PRIORITY", "Priority").strip()
CMD_PAYLOAD_JSON = os.getenv("CMD_PAYLOAD_JSON", "Payload_JSON").strip()
CMD_IDEMPOTENCY_KEY = os.getenv("CMD_IDEMPOTENCY_KEY", "Idempotency_Key").strip()

# Optional (skip writes if not present)
CMD_COMMAND_ID_TEXT = os.getenv("CMD_COMMAND_ID_TEXT", "Command_ID").strip()
CMD_RETRY_COUNT = os.getenv("CMD_RETRY_COUNT", "Retry_Count").strip()
CMD_LAST_ERROR = os.getenv("CMD_LAST_ERROR", "Last_Error").strip()
CMD_RESULT_JSON = os.getenv("CMD_RESULT_JSON", "Result_JSON").strip()
CMD_STARTED_AT = os.getenv("CMD_STARTED_AT", "Started_At").strip()
CMD_FINISHED_AT = os.getenv("CMD_FINISHED_AT", "Finished_At").strip()
CMD_DURATION_MS = os.getenv("CMD_DURATION_MS", "Duration_ms").strip()

# Locking fields (optional but recommended)
CMD_IS_LOCKED = os.getenv("CMD_IS_LOCKED", "Is_Locked").strip()
CMD_LOCKED_AT = os.getenv("CMD_LOCKED_AT", "Locked_At").strip()
CMD_LOCKED_BY = os.getenv("CMD_LOCKED_BY", "Locked_By").strip()
CMD_LINKED_RUN = os.getenv("CMD_LINKED_RUN", "Linked_Run").strip()

# ============================================================
# Logs_Erreurs SLA fields — must match Airtable exactly
# ============================================================

LE_SLA_STATUS = os.getenv("LE_SLA_STATUS", "SLA_Status").strip()
LE_LAST_SLA_CHECK = os.getenv("LE_LAST_SLA_CHECK", "Last_SLA_Check").strip()
LE_LINKED_RUN = os.getenv("LE_LINKED_RUN", "Linked_Run").strip()

# Remaining minutes field used by SLA machine
LE_SLA_REMAINING_MINUTES = os.getenv("LE_SLA_REMAINING_MINUTES", "SLA_Remaining_Minutes").strip()

# Allowed SLA statuses (must exist in Airtable if you enforce them)
SLA_OK = os.getenv("SLA_OK", "OK").strip()
SLA_WARNING = os.getenv("SLA_WARNING", "Warning").strip()
SLA_BREACHED = os.getenv("SLA_BREACHED", "Breached").strip()
SLA_ESCALATED = os.getenv("SLA_ESCALATED", "Escalated").strip()
SLA_ALLOWED = {SLA_OK, SLA_WARNING, SLA_BREACHED, SLA_ESCALATED}

# Optional: allowlist to prevent accidental writes (comma-separated)
LOGS_ERRORS_FIELDS_ALLOWED = set(
    x.strip()
    for x in os.getenv("LOGS_ERRORS_FIELDS_ALLOWED", "").split(",")
    if x.strip()
)

# ============================================================
# Orchestrator / retry
# ============================================================

MAX_RETRY = int(os.getenv("MAX_RETRY", "3").strip() or "3")
LOCK_TTL_SECONDS = int(os.getenv("LOCK_TTL_SECONDS", "900").strip() or "900")
DEFAULT_WARNING_THRESHOLD_MINUTES = int(os.getenv("DEFAULT_WARNING_THRESHOLD_MINUTES", "15").strip() or "15")
ORCH_MAX_COMMANDS = int(os.getenv("ORCH_MAX_COMMANDS", "10").strip() or "10")

ORCH_QUEUE_STATUS = os.getenv("ORCH_QUEUE_STATUS", "Queued").strip()
ORCH_RUNNING_STATUS = os.getenv("ORCH_RUNNING_STATUS", "Running").strip()
ORCH_DONE_STATUS = os.getenv("ORCH_DONE_STATUS", "Done").strip()
ORCH_ERROR_STATUS = os.getenv("ORCH_ERROR_STATUS", "Error").strip()
ORCH_BLOCKED_STATUS = os.getenv("ORCH_BLOCKED_STATUS", "Blocked").strip()

# ============================================================
# Airtable HTTP helpers
# ============================================================

def _require_airtable() -> None:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise HTTPException(
            status_code=500,
            detail="Missing AIRTABLE_API_KEY or AIRTABLE_BASE_ID in environment",
        )

def _airtable_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }

def _airtable_table_url(table_name: str) -> str:
    return f"{AIRTABLE_API_URL}/{AIRTABLE_BASE_ID}/{table_name}"

def airtable_create_record(table: str, fields: Dict[str, Any]) -> str:
    _require_airtable()
    url = _airtable_table_url(table)
    resp = requests.post(url, headers=_airtable_headers(), json={"fields": fields}, timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"Airtable create failed ({table}): {resp.status_code} {resp.text}")
    return resp.json()["id"]

def airtable_update_record(table: str, record_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    _require_airtable()
    url = f"{_airtable_table_url(table)}/{record_id}"
    resp = requests.patch(url, headers=_airtable_headers(), json={"fields": fields}, timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"Airtable update failed ({table}/{record_id}): {resp.status_code} {resp.text}")
    return resp.json()

def airtable_list_records(
    table: str,
    view: Optional[str] = None,
    max_records: int = 100,
    filter_by_formula: Optional[str] = None,
    fields: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    _require_airtable()
    url = _airtable_table_url(table)
    params: Dict[str, Any] = {"pageSize": max_records}
    if view:
        params["view"] = view
    if filter_by_formula:
        params["filterByFormula"] = filter_by_formula
    if fields:
        # Airtable expects repeated fields[] query params
        params["fields[]"] = fields

    resp = requests.get(url, headers=_airtable_headers(), params=params, timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"Airtable list failed ({table}): {resp.status_code} {resp.text}")
    return resp.json().get("records", [])

# ============================================================
# Generic helpers
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def json_dumps_safe(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)

def compute_idempotency_key(payload: Dict[str, Any]) -> str:
    raw = json_dumps_safe(payload).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def verify_signature_if_needed(request: Request, body: bytes) -> None:
    if not RUN_SHARED_SECRET:
        return
    sig = request.headers.get("x-run-signature", "").strip()
    if not sig:
        raise HTTPException(status_code=401, detail="Missing x-run-signature")
    expected = hmac.new(RUN_SHARED_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")

def filter_allowed_fields(patch: Dict[str, Any], allowed: set) -> Dict[str, Any]:
    if not allowed:
        return patch
    return {k: v for k, v in patch.items() if k in allowed}

def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default
        return int(v)
    except Exception:
        return default

def _safe_json_loads(s: Any) -> Dict[str, Any]:
    if s is None:
        return {}
    if isinstance(s, dict):
        return s
    if isinstance(s, str):
        st = s.strip()
        if not st:
            return {}
        try:
            return json.loads(st)
        except Exception:
            return {}
    return {}

def _set_if(fields: Dict[str, Any], name: str, value: Any) -> None:
    if not name:
        return
    fields[name] = value

# ============================================================
# Request models (support BOTH schemas)
# ============================================================

class RunRequestNew(BaseModel):
    command_id: Optional[str] = Field(default=None)
    capability: str
    priority: int = Field(default=1, ge=0, le=10)
    idempotency_key: Optional[str] = Field(default=None)
    dry_run: bool = Field(default=False)
    payload: Dict[str, Any] = Field(default_factory=dict)

class RunRequestLegacy(BaseModel):
    worker: Optional[str] = Field(default=DEFAULT_WORKER_NAME)
    capability: str
    idempotency_key: Optional[str] = Field(default=None)
    input: Dict[str, Any] = Field(default_factory=dict)

class RunResponse(BaseModel):
    ok: bool
    worker: str
    capability: str
    priority: int
    idempotency_key: str
    run_id: str
    airtable_record_id: str
    result: Dict[str, Any]

# ============================================================
# FastAPI app
# ============================================================

app = FastAPI(title="BOSAI Worker", version=WORKER_VERSION)
@app.get("/")
def root():
    return {"ok": True, "service": "bosai-worker", "version": WORKER_VERSION}

@app.head("/")
def root_head():
    return Response(status_code=200)

@app.get("/health")
def health():
    return {
        "ok": True,
        "worker": DEFAULT_WORKER_NAME,
        "app": DEFAULT_APP_NAME,
        "version": WORKER_VERSION,
        "env": DEFAULT_ENV,
        "time_utc": utc_now_iso(),
    }

@app.get("/health")
def health():
    return {
        "ok": True,
        "worker": DEFAULT_WORKER_NAME,
        "app": DEFAULT_APP_NAME,
        "version": WORKER_VERSION,
        "env": DEFAULT_ENV,
        "time_utc": utc_now_iso(),
    }

@app.get("/health/score")
def health_score():
    return {"ok": True, "score": 100, "version": WORKER_VERSION, "time_utc": utc_now_iso()}

# ============================================================
# Capabilities
# ============================================================

def health_tick_execute() -> Dict[str, Any]:
    """
    Probe Airtable access in the safest way:
    - list 1 record from System_Runs
    - NO filterByFormula
    """
    _require_airtable()
    _ = airtable_list_records(SYSTEM_RUNS_TABLE, max_records=1)
    return {"ok": True, "probe": "airtable_ok"}

def sla_machine_execute(
    payload: Dict[str, Any],
    run_id: str,
    dry_run: bool,
    system_runs_record_id: Optional[str] = None,
) -> Dict[str, Any]:
    view = (payload.get("view") or LOGS_ERRORS_VIEW_DEFAULT).strip()
    warning_threshold_minutes = int(payload.get("warning_threshold_minutes") or DEFAULT_WARNING_THRESHOLD_MINUTES)
    field_remaining = (payload.get("field_sla_remaining_minutes") or LE_SLA_REMAINING_MINUTES).strip()
    max_records = int(payload.get("max_records") or 100)

    records = airtable_list_records(
        LOGS_ERRORS_TABLE,
        view=view,
        max_records=max_records,
        fields=[field_remaining, LE_SLA_STATUS, LE_LAST_SLA_CHECK, LE_LINKED_RUN],
    )

    updated = 0
    scanned = 0
    skipped_no_remaining = 0
    now_iso = utc_now_iso()

    for r in records:
        scanned += 1
        rid = r.get("id")
        fields = r.get("fields", {}) or {}

        remaining = fields.get(field_remaining, None)
        if remaining is None:
            skipped_no_remaining += 1
            continue

        try:
            remaining_val = float(remaining)
        except Exception:
            skipped_no_remaining += 1
            continue

        if remaining_val < 0:
            sla_status = SLA_BREACHED
        elif remaining_val <= warning_threshold_minutes:
            sla_status = SLA_WARNING
        else:
            sla_status = SLA_OK

        # If your Airtable doesn't have these options, it will 422.
        # Keep it strict because you asked for "ticks prêts" -> schema must match.
        if sla_status not in SLA_ALLOWED:
            raise RuntimeError(f"SLA_Status option missing in Airtable: {sla_status}")

        patch: Dict[str, Any] = {
            LE_SLA_STATUS: sla_status,
            LE_LAST_SLA_CHECK: now_iso,
        }

        # Proper linked record
        if system_runs_record_id:
            patch[LE_LINKED_RUN] = [system_runs_record_id]

        patch = filter_allowed_fields(patch, LOGS_ERRORS_FIELDS_ALLOWED)

        if dry_run:
            continue

        airtable_update_record(LOGS_ERRORS_TABLE, rid, patch)
        updated += 1

    return {
        "scanned": scanned,
        "updated": updated,
        "skipped_no_remaining": skipped_no_remaining,
        "dry_run": dry_run,
        "view": view,
        "warning_threshold_minutes": warning_threshold_minutes,
        "field_sla_remaining_minutes": field_remaining,
        "system_runs_record_id": system_runs_record_id,
        "run_id": run_id,
    }

def _list_commands_best_effort(view: str, max_commands: int) -> List[Dict[str, Any]]:
    """
    Try filterByFormula first; if Airtable returns 422 (invalid formula / field mismatch),
    fallback to listing without formula and filter in Python.
    """
    fields_to_get = [
        CMD_STATUS, CMD_CAPABILITY, CMD_PRIORITY, CMD_PAYLOAD_JSON, CMD_IDEMPOTENCY_KEY,
        CMD_COMMAND_ID_TEXT, CMD_RETRY_COUNT, CMD_LAST_ERROR, CMD_RESULT_JSON,
        CMD_STARTED_AT, CMD_FINISHED_AT, CMD_DURATION_MS,
        CMD_IS_LOCKED, CMD_LOCKED_AT, CMD_LOCKED_BY, CMD_LINKED_RUN,
    ]
    # keep only non-empty unique
    fields_to_get = list(dict.fromkeys([f for f in fields_to_get if f]))

    formula = f'{{{CMD_STATUS}}}="{ORCH_QUEUE_STATUS}"'
    try:
        return airtable_list_records(
            COMMANDS_TABLE,
            view=view,
            max_records=max_commands,
            filter_by_formula=formula,
            fields=fields_to_get,
        )
    except Exception:
        # Fallback: no formula
        recs = airtable_list_records(
            COMMANDS_TABLE,
            view=view,
            max_records=max_commands,
            fields=fields_to_get,
        )
        out: List[Dict[str, Any]] = []
        for r in recs:
            st = (r.get("fields", {}) or {}).get(CMD_STATUS)
            if st == ORCH_QUEUE_STATUS:
                out.append(r)
        return out

def command_orchestrator_execute(
    run_id: str,
    payload: Dict[str, Any],
    dry_run: bool,
    system_runs_record_id: Optional[str] = None,
) -> Dict[str, Any]:
    view = (payload.get("view") or COMMANDS_VIEW_DEFAULT).strip()
    max_commands = int(payload.get("max_commands") or ORCH_MAX_COMMANDS)

    records = _list_commands_best_effort(view=view, max_commands=max_commands)

    scanned = len(records)
    executed = 0
    succeeded = 0
    failed = 0
    blocked = 0
    unsupported = 0

    per_command: List[Dict[str, Any]] = []

    for r in records:
        cmd_record_id = r.get("id", "")
        f = r.get("fields", {}) or {}

        capability = (f.get(CMD_CAPABILITY) or "").strip()
        priority = _safe_int(f.get(CMD_PRIORITY), default=1)
        cmd_payload = _safe_json_loads(f.get(CMD_PAYLOAD_JSON))
        cmd_id = (f.get(CMD_COMMAND_ID_TEXT) if CMD_COMMAND_ID_TEXT else None) or cmd_record_id

        started_at = utc_now_iso()
        t0 = time.time()

        # Lock patch
        lock_patch: Dict[str, Any] = {CMD_STATUS: ORCH_RUNNING_STATUS}
        _set_if(lock_patch, CMD_IS_LOCKED, True)
        _set_if(lock_patch, CMD_LOCKED_AT, started_at)
        _set_if(lock_patch, CMD_LOCKED_BY, DEFAULT_WORKER_NAME)
        _set_if(lock_patch, CMD_LINKED_RUN, run_id)
        _set_if(lock_patch, CMD_STARTED_AT, started_at)

        if not dry_run:
            airtable_update_record(COMMANDS_TABLE, cmd_record_id, lock_patch)

        cmd_result: Dict[str, Any] = {}
        cmd_status = ORCH_DONE_STATUS

        try:
            if capability in ("sla_machine", "sla_tick"):
                cmd_result = sla_machine_execute(
                    cmd_payload,
                    run_id=run_id,
                    dry_run=dry_run,
                    system_runs_record_id=system_runs_record_id,
                )
                cmd_status = ORCH_DONE_STATUS
                succeeded += 1
            elif capability in ("health_tick",):
                cmd_result = health_tick_execute()
                cmd_status = ORCH_DONE_STATUS
                succeeded += 1
            else:
                cmd_result = {"reason": "unsupported_capability", "capability": capability}
                cmd_status = ORCH_BLOCKED_STATUS  # avoid needing "Unsupported" option
                unsupported += 1
        except Exception as e:
            cmd_result = {"error": str(e)}
            cmd_status = ORCH_ERROR_STATUS
            failed += 1

        duration_ms = int((time.time() - t0) * 1000)
        finished_at = utc_now_iso()

        retry_count = _safe_int(f.get(CMD_RETRY_COUNT), default=0)
        if cmd_status == ORCH_ERROR_STATUS:
            retry_count += 1
            if retry_count >= MAX_RETRY:
                cmd_status = ORCH_BLOCKED_STATUS
                blocked += 1

        final_patch: Dict[str, Any] = {CMD_STATUS: cmd_status}
        _set_if(final_patch, CMD_FINISHED_AT, finished_at)
        _set_if(final_patch, CMD_DURATION_MS, duration_ms)
        _set_if(final_patch, CMD_RETRY_COUNT, retry_count)
        _set_if(final_patch, CMD_RESULT_JSON, json_dumps_safe(cmd_result))
        _set_if(final_patch, CMD_LAST_ERROR, cmd_result.get("error") if isinstance(cmd_result, dict) else None)
        _set_if(final_patch, CMD_LINKED_RUN, run_id)

        if not dry_run:
            airtable_update_record(COMMANDS_TABLE, cmd_record_id, final_patch)

        executed += 1
        per_command.append(
            {
                "command_record_id": cmd_record_id,
                "command_id": cmd_id,
                "capability": capability,
                "priority": priority,
                "final_status": cmd_status,
                "duration_ms": duration_ms,
            }
        )

    return {
        "view": view,
        "dry_run": dry_run,
        "scanned": scanned,
        "executed": executed,
        "succeeded": succeeded,
        "failed": failed,
        "blocked": blocked,
        "unsupported": unsupported,
        "items": per_command,
        "system_runs_record_id": system_runs_record_id,
        "run_id": run_id,
    }

# ===========================================================
# /run endpoint
# ============================================================

@app.post("/run", response_model=RunResponse)
async def run(req: Request):
    body = await req.body()
    verify_signature_if_needed(req, body)

    try:
        payload_in = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Accept BOTH schemas
    if "payload" in payload_in or "dry_run" in payload_in or "priority" in payload_in:
        run_req_new = RunRequestNew(**payload_in)
        capability = run_req_new.capability
        priority = run_req_new.priority
        dry_run = run_req_new.dry_run
        command_id = run_req_new.command_id
        payload = run_req_new.payload or {}
        idem_in = (run_req_new.idempotency_key or "").strip()
        worker_name = DEFAULT_WORKER_NAME
    else:
        run_req_legacy = RunRequestLegacy(**payload_in)
        capability = run_req_legacy.capability
        priority = 1
        dry_run = False
        command_id = None
        payload = run_req_legacy.input or {}
        idem_in = (run_req_legacy.idempotency_key or "").strip()
        worker_name = (run_req_legacy.worker or DEFAULT_WORKER_NAME).strip()

    # Accept alias: lock_key -> idempotency_key
    lock_key_alias = (payload.get("lock_key") or payload.get("Lock_key") or "").strip() if isinstance(payload, dict) else ""
    idem = idem_in or lock_key_alias

    effective_payload = {
        "command_id": command_id,
        "capability": capability,
        "priority": priority,
        "payload": payload,
        "dry_run": dry_run,
    }
    if not idem:
        idem = compute_idempotency_key(effective_payload)

    run_id = f"run_{secrets.token_hex(8)}"
    started_at = utc_now_iso()

    sr_fields: Dict[str, Any] = {
        SR_RUN_ID: run_id,
        SR_WORKER_NAME: worker_name,
        SR_APP: DEFAULT_APP_NAME,
        SR_VERSION: WORKER_VERSION,
        SR_CAPABILITY: capability,
        SR_PRIORITY: priority,
        SR_IDEMPOTENCY_KEY: idem,
        SR_STATUS: SR_STATUS_RUNNING,
        SR_STARTED_AT: started_at,
        SR_PAYLOAD_JSON: json_dumps_safe(effective_payload),
    }

    t0 = time.time()
    airtable_record_id = ""
    final_status = SR_STATUS_DONE
    result: Dict[str, Any] = {}

    try:
        airtable_record_id = airtable_create_record(SYSTEM_RUNS_TABLE, sr_fields)

        # Dispatch capabilities
        if capability in ("health_tick",):
            result = health_tick_execute()
            final_status = SR_STATUS_DONE

        elif capability in ("sla_machine", "sla_tick"):
            result = sla_machine_execute(
                payload,
                run_id=run_id,
                dry_run=dry_run,
                system_runs_record_id=airtable_record_id,
            )
            final_status = SR_STATUS_DONE

        elif capability in ("command_orchestrator",):
            result = command_orchestrator_execute(
                run_id=run_id,
                payload=payload,
                dry_run=dry_run,
                system_runs_record_id=airtable_record_id,
            )
            final_status = SR_STATUS_DONE

        else:
            # Avoid "Unsupported" status (may not exist in your options)
            result = {"reason": "unsupported_capability", "capability": capability}
            final_status = SR_STATUS_BLOCKED

    except Exception as e:
        result = {"error": str(e)}
        final_status = SR_STATUS_ERROR

    duration_ms = int((time.time() - t0) * 1000)
    finished_at = utc_now_iso()

    # Update System_Runs record
    if airtable_record_id:
        patch = {
            SR_FINISHED_AT: finished_at,
            SR_DURATION_MS: duration_ms,
            SR_STATUS: final_status,
            SR_RESULT_JSON: json_dumps_safe(result),
        }
        # Optional error message field (safe best-effort)
        if SR_ERROR_MESSAGE:
            if isinstance(result, dict) and result.get("error"):
                patch[SR_ERROR_MESSAGE] = str(result.get("error"))

        try:
            airtable_update_record(SYSTEM_RUNS_TABLE, airtable_record_id, patch)
        except Exception as e:
            # If update fails, we still respond (but mark as error)
            final_status = SR_STATUS_ERROR
            result = {"error": "Airtable update failed", "detail": str(e), "previous_result": result}

    ok = final_status == SR_STATUS_DONE
    return RunResponse(
        ok=ok,
        worker=worker_name,
        capability=capability,
        priority=priority,
        idempotency_key=idem,
        run_id=run_id,
        airtable_record_id=airtable_record_id or "",
        result=result,
    )
