# app/worker.py — BOSAI Worker (v2.5.0)
# SAFE PATCH over v2.4.10 baseline:
# - Adds Command Lock_Token + Lock_Expires_At (best-effort, non-breaking if fields absent)
# - Adds Retry/Dead (DLQ) state machine (best-effort)
# - Scheduler selection supports Queued due + Retry due + stale locks (formula best-effort; fallback to view)
# - Releases locks on Done/Error/Retry/Dead (best-effort)
# - Keeps auth OR (scheduler secret OR HMAC) unchanged
# - No change to payload schema, endpoints, SLA, ToolCatalog behavior

import os
import json
import time
import uuid
import hmac
import hashlib
import traceback
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, List, Tuple

import requests
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.capabilities.http_exec import capability_http_exec as capability_http_exec_impl

# ============================================================
# Env / settings
# ============================================================

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()

SYSTEM_RUNS_TABLE_NAME = os.getenv("SYSTEM_RUNS_TABLE_NAME", "System_Runs").strip()
COMMANDS_TABLE_NAME = os.getenv("COMMANDS_TABLE_NAME", "Commands").strip()
LOGS_ERRORS_TABLE_NAME = os.getenv("LOGS_ERRORS_TABLE_NAME", "Logs_Erreurs").strip()
STATE_TABLE_NAME = os.getenv("STATE_TABLE_NAME", "State").strip()
TOOLCATALOG_TABLE_NAME = os.getenv("TOOLCATALOG_TABLE_NAME", "ToolCatalog").strip()

LOGS_ERRORS_VIEW_NAME = os.getenv("LOGS_ERRORS_VIEW_NAME", "Active").strip()
COMMANDS_VIEW_NAME = os.getenv("COMMANDS_VIEW_NAME", "Queue").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()
APP_NAME = os.getenv("APP_NAME", "bosai-worker").strip()
APP_VERSION = os.getenv("APP_VERSION", "2.5.0").strip()

RUN_MAX_SECONDS = float((os.getenv("RUN_MAX_SECONDS", "30") or "30").strip())
HTTP_TIMEOUT_SECONDS = float((os.getenv("HTTP_TIMEOUT_SECONDS", "20") or "20").strip())
RUN_LOCK_TTL_SECONDS = int((os.getenv("RUN_LOCK_TTL_SECONDS", "600") or "600").strip())

# Commands lock TTL (minutes) — SAFE default 10
COMMAND_LOCK_TTL_MIN = int((os.getenv("COMMAND_LOCK_TTL_MIN", "10") or "10").strip())

RUN_SHARED_SECRET = os.getenv("RUN_SHARED_SECRET", "").strip()
SCHEDULER_SECRET = os.getenv("SCHEDULER_SECRET", "").strip()

SLA_WARNING_THRESHOLD_MIN = float((os.getenv("SLA_WARNING_THRESHOLD_MIN", "60") or "60").strip())

LOGS_ERRORS_FIELDS_ALLOWED = set(
    [
        s.strip()
        for s in os.getenv(
            "LOGS_ERRORS_FIELDS_ALLOWED",
            "SLA_Status,Last_SLA_Check,Linked_Run",
        ).split(",")
        if s.strip()
    ]
)

SLA_STATUS_OK = os.getenv("SLA_STATUS_OK", "OK").strip()
SLA_STATUS_WARNING = os.getenv("SLA_STATUS_WARNING", "Warning").strip()
SLA_STATUS_BREACHED = os.getenv("SLA_STATUS_BREACHED", "Breached").strip()
SLA_STATUS_ESCALATED = os.getenv("SLA_STATUS_ESCALATED", "Escalated").strip()

STATE_LOCK_ACTIVE = os.getenv("STATE_LOCK_ACTIVE", "Active").strip()
STATE_LOCK_RELEASED = os.getenv("STATE_LOCK_RELEASED", "Released").strip()
STATE_LOCK_EXPIRED = os.getenv("STATE_LOCK_EXPIRED", "Expired").strip()

HTTP_EXEC_ALLOWLIST_RAW = os.getenv("HTTP_EXEC_ALLOWLIST", "").strip()
HTTP_EXEC_TARGETS_JSON = os.getenv("HTTP_EXEC_TARGETS_JSON", "").strip()
TOOLCATALOG_ENFORCE_HTTP_EXEC = (os.getenv("TOOLCATALOG_ENFORCE_HTTP_EXEC", "1").strip() != "0")

# ============================================================
# FastAPI
# ============================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION)
_HTTP_SESSION = requests.Session()


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    print("UNHANDLED_EXCEPTION:", repr(exc))
    print(tb)
    return JSONResponse(status_code=500, content={"detail": "Internal error", "error": repr(exc)})


# ============================================================
# Pydantic models (COMPAT)
# ============================================================

class RunRequest(BaseModel):
    worker: str = Field(default=WORKER_NAME)
    capability: str
    idempotency_key: str
    priority: int = 1
    input: Dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    view: Optional[str] = None
    max_commands: int = 0

    class Config:
        extra = "forbid"

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "RunRequest":
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Invalid JSON body.")

        p = dict(payload)

        if "capability" not in p and "capacity" in p:
            p["capability"] = p.get("capacity")
        p.pop("capacity", None)

        if "idempotency_key" not in p and "idempotencyKey" in p:
            p["idempotency_key"] = p.get("idempotencyKey")
        p.pop("idempotencyKey", None)

        if "input" not in p and "inputs" in p:
            p["input"] = p.get("inputs")
        p.pop("inputs", None)

        if "worker" not in p or not str(p.get("worker") or "").strip():
            p["worker"] = WORKER_NAME

        try:
            mv = getattr(cls, "model_validate", None)
            if callable(mv):
                return mv(p)  # type: ignore
        except Exception:
            pass

        return cls.parse_obj(p)


class RunResponse(BaseModel):
    ok: bool
    worker: str
    capability: str
    idempotency_key: str
    run_id: str
    airtable_record_id: Optional[str] = None
    result: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "forbid"


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
    return {"Authorization": f"Bearer {AIRTABLE_API_KEY}", "Content-Type": "application/json"}


def airtable_create(table_name: str, fields: Dict[str, Any]) -> str:
    _require_airtable()
    r = _HTTP_SESSION.post(
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
    r = _HTTP_SESSION.patch(
        f"{_airtable_url(table_name)}/{record_id}",
        headers=_airtable_headers(),
        json={"fields": fields},
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    if r.status_code >= 300:
        raise HTTPException(status_code=500, detail=f"Airtable update failed: {r.status_code} {r.text}")


def airtable_find_first(table_name: str, formula: str, max_records: int = 1) -> Optional[Dict[str, Any]]:
    _require_airtable()
    r = _HTTP_SESSION.get(
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
    r = _HTTP_SESSION.get(
        _airtable_url(table_name),
        headers=_airtable_headers(),
        params={"view": view_name, "maxRecords": str(max_records)},
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    if r.status_code >= 300:
        raise HTTPException(status_code=500, detail=f"Airtable view list failed: {r.status_code} {r.text}")
    return r.json().get("records", [])


# NEW (SAFE): filtered list + sort (+ optional view)
def airtable_list_filtered(
    table_name: str,
    formula: str,
    view_name: Optional[str] = None,
    sort: Optional[List[Dict[str, str]]] = None,
    max_records: int = 100,
) -> List[Dict[str, Any]]:
    _require_airtable()
    params: Dict[str, Any] = {"filterByFormula": formula, "maxRecords": str(max_records)}

    if view_name:
        params["view"] = view_name

    if sort:
        for i, s in enumerate(sort):
            field = (s.get("field") or "").strip()
            direction = (s.get("direction") or "asc").strip()
            if not field:
                continue
            params[f"sort[{i}][field]"] = field
            params[f"sort[{i}][direction]"] = direction

    r = _HTTP_SESSION.get(
        _airtable_url(table_name),
        headers=_airtable_headers(),
        params=params,
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    if r.status_code >= 300:
        raise HTTPException(status_code=500, detail=f"Airtable filtered list failed: {r.status_code} {r.text}")
    return r.json().get("records", [])


def _json_load_maybe(val: Any) -> Dict[str, Any]:
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


def _verify_hmac_signature(raw_body: bytes, signature_header: Optional[str]) -> bool:
    if not RUN_SHARED_SECRET:
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    their_hex = signature_header.split("=", 1)[1].strip()
    ours = hmac.new(RUN_SHARED_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(their_hex, ours)


def _verify_scheduler_secret(headers: Dict[str, str]) -> bool:
    if not SCHEDULER_SECRET:
        return False
    got = (headers.get("x-scheduler-secret") or "").strip()
    if not got:
        return False
    return hmac.compare_digest(got, SCHEDULER_SECRET)


def verify_request_auth_or_401(raw_body: bytes, headers: Dict[str, str]) -> None:
    """
    Auth policy (SAFE):
    - If either secret exists, require at least one valid auth method.
      * scheduler secret via x-scheduler-secret
      * OR HMAC signature via x-run-signature
    - If no secrets configured: dev mode (no auth).
    """
    if not SCHEDULER_SECRET and not RUN_SHARED_SECRET:
        return

    if _verify_scheduler_secret(headers):
        return

    if _verify_hmac_signature(raw_body, headers.get("x-run-signature")):
        return

    raise HTTPException(status_code=401, detail="Unauthorized (missing/invalid scheduler secret or run signature)")


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


# ============================================================
# Commands Lock / Retry helpers (SAFE, best-effort)
# ============================================================

def _new_lock_token() -> str:
    return uuid.uuid4().hex


def _command_lock_ttl_min() -> int:
    try:
        v = int(COMMAND_LOCK_TTL_MIN or 10)
        return v if v > 0 else 10
    except Exception:
        return 10


def _utc_plus_minutes_iso(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def _compute_next_retry_at(fields: Dict[str, Any]) -> str:
    """
    Exponential backoff capped (SAFE):
    - base from Retry_Backoff_Sec (default 60)
    - count from Retry_Count (default 0)
    - delay = min(3600, base * 2^count)
    """
    try:
        base = int(fields.get("Retry_Backoff_Sec", 60) or 60)
    except Exception:
        base = 60
    try:
        count = int(fields.get("Retry_Count", 0) or 0)
    except Exception:
        count = 0

    if base <= 0:
        base = 60
    if count < 0:
        count = 0

    delay = min(3600, base * (2 ** count))
    return (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()


def _airtable_update_best_effort(table_name: str, record_id: str, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    last_err: Optional[str] = None
    for fields in candidates:
        if not fields:
            continue
        try:
            airtable_update(table_name, record_id, fields)
            return {"ok": True, "applied_fields": list(fields.keys())}
        except HTTPException as e:
            last_err = str(e.detail)
            continue
        except Exception as e:
            last_err = repr(e)
            continue
    return {"ok": False, "error": last_err or "update_failed"}


def _release_command_lock_best_effort(command_id: str) -> None:
    """
    SAFE: attempts to clear lock fields if they exist; otherwise no-op.
    """
    now = utc_now_iso()
    _airtable_update_best_effort(
        COMMANDS_TABLE_NAME,
        command_id,
        [
            {"Is_Locked": False, "Lock_Expires_At": None, "Lock_Token": "", "Last_Heartbeat_At": now},
            {"Is_Locked": False, "Lock_Expires_At": None, "Lock_Token": ""},
            {"Is_Locked": False},
        ],
    )


# ============================================================
# No-Chaos: stale Running TTL cleanup (System_Runs)
# ============================================================

def cleanup_stale_runs() -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        return {"ok": True, "noop": True, "reason": "airtable_env_missing"}

    ttl = int(RUN_LOCK_TTL_SECONDS or 600)
    formula = "AND({Status_select}='Running',DATETIME_DIFF(NOW(), {Started_At}, 'seconds') > " + str(ttl) + ")"

    try:
        r = _HTTP_SESSION.get(
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
                airtable_update(
                    SYSTEM_RUNS_TABLE_NAME,
                    rid,
                    {
                        "Status_select": "Error",
                        "Finished_At": utc_now_iso(),
                        "Result_JSON": json.dumps({"error": "lock_ttl_expired"}, ensure_ascii=False),
                    },
                )
                cleaned += 1
            except Exception:
                continue

        return {"ok": True, "ttl_seconds": ttl, "found": len(records), "cleaned": cleaned}
    except Exception as e:
        return {"ok": True, "noop": True, "reason": "exception", "detail": repr(e)}


# ============================================================
# System_Runs helpers
# ============================================================

def create_system_run(req: RunRequest) -> Tuple[str, str]:
    run_uuid = str(uuid.uuid4())
    fields = {
        "Run_ID": run_uuid,
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
    record_id = airtable_create(SYSTEM_RUNS_TABLE_NAME, fields)
    return record_id, run_uuid


def finish_system_run(record_id: str, status: str, result_obj: Dict[str, Any]) -> None:
    airtable_update(
        SYSTEM_RUNS_TABLE_NAME,
        record_id,
        {
            "Status_select": status,
            "Finished_At": utc_now_iso(),
            "Result_JSON": json.dumps(result_obj, ensure_ascii=False),
        },
    )


def fail_system_run(record_id: str, error_message: str) -> None:
    airtable_update(
        SYSTEM_RUNS_TABLE_NAME,
        record_id,
        {
            "Status_select": "Error",
            "Finished_At": utc_now_iso(),
            "Result_JSON": json.dumps({"error": error_message}, ensure_ascii=False),
        },
    )


def idempotency_lookup(req: RunRequest) -> Optional[Dict[str, Any]]:
    formula = f"AND({{Idempotency_Key}}='{req.idempotency_key}',OR({{Status_select}}='Done',{{Status_select}}='Error'))"
    try:
        return airtable_find_first(SYSTEM_RUNS_TABLE_NAME, formula=formula, max_records=1)
    except HTTPException as e:
        if "INVALID_FILTER_BY_FORMULA" in str(e.detail):
            return None
        raise


# ============================================================
# State table helpers (KV + Locks)
# ============================================================

def state_get_record(app_key: str) -> Optional[Dict[str, Any]]:
    return airtable_find_first(STATE_TABLE_NAME, formula=f"{{App_Key}}='{app_key}'", max_records=1)


def state_put(app_key: str, value_obj: Dict[str, Any]) -> Dict[str, Any]:
    existing = state_get_record(app_key)
    fields = {
        "App_Key": app_key,
        "Value_JSON": json.dumps(value_obj, ensure_ascii=False),
        "Updated_At": utc_now_iso(),
        "App_Version": APP_VERSION,
    }
    if existing:
        airtable_update(STATE_TABLE_NAME, existing["id"], fields)
        return {"ok": True, "mode": "update", "record_id": existing["id"]}
    rid = airtable_create(STATE_TABLE_NAME, fields)
    return {"ok": True, "mode": "create", "record_id": rid}


def lock_acquire(lock_key: str, holder: str) -> Dict[str, Any]:
    app_key = f"lock:{lock_key}"
    rec = state_get_record(app_key)
    now = utc_now_iso()

    if rec:
        fields = rec.get("fields", {}) or {}
        status = str(fields.get("Lock_Status", "")).strip()
        if status == STATE_LOCK_ACTIVE:
            return {"ok": False, "locked": True, "record_id": rec["id"], "lock_status": status}

        airtable_update(
            STATE_TABLE_NAME,
            rec["id"],
            {
                "App_Key": app_key,
                "Lock_Status": STATE_LOCK_ACTIVE,
                "Value_JSON": json.dumps({"holder": holder, "acquired_at": now}, ensure_ascii=False),
                "Updated_At": now,
                "App_Version": APP_VERSION,
            },
        )
        return {"ok": True, "locked": True, "record_id": rec["id"], "lock_status": STATE_LOCK_ACTIVE}

    rid = airtable_create(
        STATE_TABLE_NAME,
        {
            "App_Key": app_key,
            "Lock_Status": STATE_LOCK_ACTIVE,
            "Value_JSON": json.dumps({"holder": holder, "acquired_at": now}, ensure_ascii=False),
            "Updated_At": now,
            "App_Version": APP_VERSION,
        },
    )
    return {"ok": True, "locked": True, "record_id": rid, "lock_status": STATE_LOCK_ACTIVE}


def lock_release(lock_key: str, holder: str) -> Dict[str, Any]:
    app_key = f"lock:{lock_key}"
    rec = state_get_record(app_key)
    if not rec:
        return {"ok": True, "released": False, "reason": "not_found"}

    fields = rec.get("fields", {}) or {}
    val = _json_load_maybe(fields.get("Value_JSON"))
    current_holder = str(val.get("holder", "")).strip()

    if current_holder and current_holder != holder:
        return {"ok": False, "released": False, "reason": "holder_mismatch", "current_holder": current_holder}

    now = utc_now_iso()
    airtable_update(
        STATE_TABLE_NAME,
        rec["id"],
        {
            "Lock_Status": STATE_LOCK_RELEASED,
            "Updated_At": now,
            "Value_JSON": json.dumps({"holder": holder, "released_at": now}, ensure_ascii=False),
            "App_Version": APP_VERSION,
        },
    )
    return {"ok": True, "released": True, "record_id": rec["id"]}


# ============================================================
# Capabilities
# ============================================================

def capability_health_tick(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return {"ok": True, "probe": "airtable_ok", "ts": utc_now_iso(), "run_record_id": run_record_id}


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
        fields = rec.get("fields", {}) or {}

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

    return {"ok": True, "updated": updated, "skipped": skipped, "errors_count": len(errors), "errors": errors[:10]}


def capability_commands_tick(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    inp = req.input or {}
    limit = int(inp.get("limit", 5) or 5)
    if limit <= 0:
        limit = 5
    if limit > 50:
        limit = 50

    view = (req.view or COMMANDS_VIEW_NAME or "Queue").strip()
    cmds = airtable_list_view(COMMANDS_TABLE_NAME, view, max_records=limit)

    now = utc_now_iso()
    processed: List[str] = []
    updated = 0
    update_fail = 0
    update_errors: List[str] = []

    for c in cmds:
        cid = c.get("id")
        if not cid:
            continue

        processed.append(cid)

        candidates = [
            {"Is_Locked": True, "Locked_At": now, "Locked_By": req.worker, "Last_Status": "Running", "Last_Error": "", "Linked_Run": [run_record_id]},
            {"Is_Locked": True, "Locked_At": now, "Locked_By": req.worker, "Last_Status": "Running"},
            {"Is_Locked": True, "Locked_By": req.worker},
            {"Status_select": "Running", "Linked_Run": [run_record_id], "Error_Message": ""},
            {"Status_select": "Running"},
        ]

        res = _airtable_update_best_effort(COMMANDS_TABLE_NAME, cid, candidates)
        if res.get("ok"):
            updated += 1
        else:
            update_fail += 1
            update_errors.append(f"{cid}: {res.get('error')}")

    return {
        "ok": True,
        "view": view,
        "limit": limit,
        "scanned": len(cmds),
        "processed": processed,
        "updated": updated,
        "update_fail": update_fail,
        "errors_count": len(update_errors),
        "errors": update_errors[:10],
        "run_record_id": run_record_id,
        "ts": now,
    }


def capability_http_exec(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return capability_http_exec_impl(req, run_record_id, session=_HTTP_SESSION)


def _compose_command_input(fields: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("Command_JSON", "Payload_JSON", "Input_JSON"):
        obj = _json_load_maybe(fields.get(key))
        if isinstance(obj, dict) and obj:
            return obj

    built: Dict[str, Any] = {}

    http_target = str(fields.get("http_target", "") or "").strip()
    if http_target:
        built["http_target"] = http_target

    method = str(fields.get("HTTP_Method", "") or "").strip()
    if method:
        built["method"] = method

    payload_raw = fields.get("HTTP_Payload_JSON")
    payload_obj = _json_load_maybe(payload_raw)
    if payload_obj:
        built["json"] = payload_obj
    else:
        if isinstance(payload_raw, str) and payload_raw.strip():
            built["data"] = payload_raw.strip()

    tool_key = str(fields.get("Tool_Key", "") or "").strip()
    if tool_key:
        built["Tool_Key"] = tool_key
    tool_mode = str(fields.get("Tool_Mode", "") or "").strip()
    if tool_mode:
        built["Tool_Mode"] = tool_mode
    tool_intent = str(fields.get("Tool_Intent", "") or "").strip()
    if tool_intent:
        built["Tool_Intent"] = tool_intent
    approved = fields.get("Approved")
    if approved is not None:
        built["Approved"] = bool(approved)

    return built


def capability_state_get(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    key = str(req.input.get("key", "")).strip()
    if not key:
        raise HTTPException(status_code=400, detail="state_get requires input.key")
    rec = state_get_record(key)
    if not rec:
        return {"ok": True, "found": False, "key": key}
    fields = rec.get("fields", {}) or {}
    return {
        "ok": True,
        "found": True,
        "key": key,
        "record_id": rec.get("id"),
        "value": _json_load_maybe(fields.get("Value_JSON")),
        "updated_at": fields.get("Updated_At"),
        "app_version": fields.get("App_Version"),
        "lock_status": fields.get("Lock_Status"),
    }


def capability_state_put(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    key = str(req.input.get("key", "")).strip()
    value = req.input.get("value")
    if not key:
        raise HTTPException(status_code=400, detail="state_put requires input.key")
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="state_put requires input.value to be an object (dict)")
    return state_put(key, value)


def capability_lock_acquire(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    key = str(req.input.get("key", "")).strip()
    holder = str(req.input.get("holder", req.worker)).strip()
    if not key:
        raise HTTPException(status_code=400, detail="lock_acquire requires input.key")
    return lock_acquire(key, holder)


def capability_lock_release(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    key = str(req.input.get("key", "")).strip()
    holder = str(req.input.get("holder", req.worker)).strip()
    if not key:
        raise HTTPException(status_code=400, detail="lock_release requires input.key")
    return lock_release(key, holder)


def _read_command_status(fields: Dict[str, Any]) -> str:
    return str(fields.get("Status_select", fields.get("Status", fields.get("Status_raw", ""))) or "").strip()


def capability_command_orchestrator(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    max_cmds = int(req.max_commands or 0) or 5

    # Determine view (used for both scheduler and fallback)
    view_name = (req.view or COMMANDS_VIEW_NAME or "Queue").strip()

    # Scheduler selection (SAFE, best-effort):
    # - Queued due: Scheduled_At blank OR <= NOW
    # - Retry due: Next_Retry_At <= NOW
    # - Stale lock: Is_Lock_Stale = 1 (if exists)
    formula = (
        "OR("
        "AND({Status_select}='Queued',OR(IS_BLANK({Scheduled_At}),IS_BEFORE({Scheduled_At},NOW()),{Scheduled_At}=NOW())),"
        "AND({Status_select}='Retry',{Next_Retry_At}!=BLANK(),OR(IS_BEFORE({Next_Retry_At},NOW()),{Next_Retry_At}=NOW())),"
        "{Is_Lock_Stale}=1"
        ")"
    )

    try:
        cmds = airtable_list_filtered(
            COMMANDS_TABLE_NAME,
            formula=formula,
            view_name=view_name,
            sort=[
                {"field": "Priority", "direction": "desc"},
                {"field": "Scheduled_At", "direction": "asc"},
                {"field": "Next_Retry_At", "direction": "asc"},
            ],
            max_records=max_cmds,
        )
        selection_mode = "scheduler"
        view = f"scheduler_formula+view:{view_name}"
    except Exception:
        # Fallback (SAFE)
        selection_mode = "view_fallback"
        view = view_name
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

        status = _read_command_status(fields)

        # Allow only runnable statuses
        if status and status not in ("Queued", "QUEUE", "Queue", "Retry"):
            blocked += 1
            continue

        capability = str(fields.get("Capability", "")).strip()
        if not capability:
            failed += 1
            _airtable_update_best_effort(
                COMMANDS_TABLE_NAME,
                cid,
                [
                    {"Status_select": "Error", "Error_Message": "Missing Capability", "Linked_Run": [run_record_id]},
                    {"Status_select": "Error"},
                ],
            )
            _release_command_lock_best_effort(cid)
            continue

        fn = CAPABILITIES.get(capability)
        if not fn:
            unsupported += 1
            _airtable_update_best_effort(
                COMMANDS_TABLE_NAME,
                cid,
                [
                    {"Status_select": "Unsupported", "Error_Message": f"Unsupported capability: {capability}", "Linked_Run": [run_record_id]},
                    {"Status_select": "Unsupported"},
                ],
            )
            _release_command_lock_best_effort(cid)
            continue

        idem = str(fields.get("Idempotency_Key", "")).strip() or f"cmd:{cid}:{capability}"
        cmd_input = _compose_command_input(fields)

        # Lock + Running (SAFE best-effort)
        now = utc_now_iso()
        ttl_min = _command_lock_ttl_min()
        lock_token = _new_lock_token()
        expires_at = _utc_plus_minutes_iso(ttl_min)

        lock_candidates = [
            {
                "Status_select": "Running",
                "Idempotency_Key": idem,
                "Linked_Run": [run_record_id],
                "Error_Message": "",
                "Is_Locked": True,
                "Locked_At": now,
                "Locked_By": req.worker,
                "Lock_Token": lock_token,
                "Lock_TTL_Min": ttl_min,
                "Lock_Expires_At": expires_at,
                "Last_Heartbeat_At": now,
            },
            {
                "Status_select": "Running",
                "Idempotency_Key": idem,
                "Linked_Run": [run_record_id],
                "Error_Message": "",
                "Is_Locked": True,
                "Locked_At": now,
                "Locked_By": req.worker,
            },
            {
                "Status_select": "Running",
                "Idempotency_Key": idem,
                "Linked_Run": [run_record_id],
                "Error_Message": "",
            },
        ]

        lock_res = _airtable_update_best_effort(COMMANDS_TABLE_NAME, cid, lock_candidates)
        if not lock_res.get("ok"):
            blocked += 1
            continue

        executed += 1

        try:
            cmd_req = RunRequest.from_payload(
                {
                    "worker": req.worker,
                    "capability": capability,
                    "idempotency_key": idem,
                    "input": cmd_input,
                    "priority": req.priority,
                    "dry_run": bool(req.dry_run),
                }
            )

            result_obj = fn(cmd_req, run_record_id)

            # Done + unlock (SAFE)
            _airtable_update_best_effort(
                COMMANDS_TABLE_NAME,
                cid,
                [
                    {
                        "Status_select": "Done",
                        "Result_JSON": json.dumps(result_obj, ensure_ascii=False),
                        "Linked_Run": [run_record_id],
                        "Is_Locked": False,
                        "Lock_Expires_At": None,
                        "Lock_Token": "",
                        "Last_Heartbeat_At": utc_now_iso(),
                    },
                    {
                        "Status_select": "Done",
                        "Result_JSON": json.dumps(result_obj, ensure_ascii=False),
                        "Linked_Run": [run_record_id],
                    },
                ],
            )

            succeeded += 1

        except HTTPException as e:
            msg = str(e.detail)
            failed += 1

            # Retry/Dead policy (SAFE, best-effort)
            try:
                retry_count = int(fields.get("Retry_Count", 0) or 0)
            except Exception:
                retry_count = 0
            try:
                retry_max = int(fields.get("Retry_Max", 0) or 0)
            except Exception:
                retry_max = 0
            if retry_max <= 0:
                retry_max = 3

            if retry_count < retry_max:
                next_at = _compute_next_retry_at(fields)
                _airtable_update_best_effort(
                    COMMANDS_TABLE_NAME,
                    cid,
                    [
                        {
                            "Status_select": "Retry",
                            "Retry_Count": retry_count + 1,
                            "Next_Retry_At": next_at,
                            "Last_Error": msg,
                            "Error_Message": msg,
                            "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                            "Linked_Run": [run_record_id],
                            "Is_Locked": False,
                            "Lock_Expires_At": None,
                            "Lock_Token": "",
                        },
                        {
                            "Status_select": "Retry",
                            "Retry_Count": retry_count + 1,
                            "Next_Retry_At": next_at,
                            "Last_Error": msg,
                            "Error_Message": msg,
                            "Linked_Run": [run_record_id],
                        },
                        {
                            "Status_select": "Error",
                            "Error_Message": msg,
                            "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                            "Linked_Run": [run_record_id],
                        },
                    ],
                )
            else:
                _airtable_update_best_effort(
                    COMMANDS_TABLE_NAME,
                    cid,
                    [
                        {
                            "Status_select": "Dead",
                            "Last_Error": msg,
                            "Error_Message": msg,
                            "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                            "Linked_Run": [run_record_id],
                            "Is_Locked": False,
                            "Lock_Expires_At": None,
                            "Lock_Token": "",
                        },
                        {"Status_select": "Dead", "Last_Error": msg, "Linked_Run": [run_record_id]},
                        {"Status_select": "Error", "Error_Message": msg, "Linked_Run": [run_record_id]},
                    ],
                )

            _release_command_lock_best_effort(cid)
            errors.append(f"{cid}: {msg}")

        except Exception as e:
            msg = repr(e)
            failed += 1

            # Same Retry/Dead policy (SAFE)
            try:
                retry_count = int(fields.get("Retry_Count", 0) or 0)
            except Exception:
                retry_count = 0
            try:
                retry_max = int(fields.get("Retry_Max", 0) or 0)
            except Exception:
                retry_max = 0
            if retry_max <= 0:
                retry_max = 3

            if retry_count < retry_max:
                next_at = _compute_next_retry_at(fields)
                _airtable_update_best_effort(
                    COMMANDS_TABLE_NAME,
                    cid,
                    [
                        {
                            "Status_select": "Retry",
                            "Retry_Count": retry_count + 1,
                            "Next_Retry_At": next_at,
                            "Last_Error": msg,
                            "Error_Message": msg,
                            "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                            "Linked_Run": [run_record_id],
                            "Is_Locked": False,
                            "Lock_Expires_At": None,
                            "Lock_Token": "",
                        },
                        {
                            "Status_select": "Retry",
                            "Retry_Count": retry_count + 1,
                            "Next_Retry_At": next_at,
                            "Last_Error": msg,
                            "Error_Message": msg,
                            "Linked_Run": [run_record_id],
                        },
                        {
                            "Status_select": "Error",
                            "Error_Message": msg,
                            "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                            "Linked_Run": [run_record_id],
                        },
                    ],
                )
            else:
                _airtable_update_best_effort(
                    COMMANDS_TABLE_NAME,
                    cid,
                    [
                        {
                            "Status_select": "Dead",
                            "Last_Error": msg,
                            "Error_Message": msg,
                            "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                            "Linked_Run": [run_record_id],
                            "Is_Locked": False,
                            "Lock_Expires_At": None,
                            "Lock_Token": "",
                        },
                        {"Status_select": "Dead", "Last_Error": msg, "Linked_Run": [run_record_id]},
                        {"Status_select": "Error", "Error_Message": msg, "Linked_Run": [run_record_id]},
                    ],
                )

            _release_command_lock_best_effort(cid)
            errors.append(f"{cid}: {msg}")

    return {
        "ok": True,
        "selection_mode": selection_mode,
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
    "commands_tick": capability_commands_tick,
    "sla_machine": capability_sla_machine,
    "http_exec": capability_http_exec,
    "state_get": capability_state_get,
    "state_put": capability_state_put,
    "lock_acquire": capability_lock_acquire,
    "lock_release": capability_lock_release,
    "command_orchestrator": capability_command_orchestrator,
}


@app.get("/")
def root() -> Dict[str, Any]:
    return {"ok": True, "service": APP_NAME, "version": APP_VERSION}


@app.head("/")
def root_head() -> Response:
    return Response(status_code=200)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "app": APP_NAME,
        "version": APP_VERSION,
        "worker": WORKER_NAME,
        "capabilities": sorted(list(CAPABILITIES.keys())),
        "ts": utc_now_iso(),
    }


@app.get("/health/score")
def health_score() -> Dict[str, Any]:
    score = 100
    issues: List[str] = []
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        score -= 50
        issues.append("airtable_env_missing")
    if RUN_SHARED_SECRET:
        issues.append("signature_enabled")
    if SCHEDULER_SECRET:
        issues.append("scheduler_secret_enabled")
    if not (HTTP_EXEC_ALLOWLIST_RAW or "").strip():
        issues.append("http_exec_disabled_no_allowlist")
    if not (HTTP_EXEC_TARGETS_JSON or "").strip():
        issues.append("http_exec_no_alias_targets")
    if TOOLCATALOG_ENFORCE_HTTP_EXEC:
        issues.append("toolcatalog_http_exec_enforced")
    return {"ok": True, "score": max(0, score), "issues": issues, "ts": utc_now_iso()}


@app.post("/run", response_model=RunResponse)
async def run(request: Request, response: Response) -> RunResponse:
    started = time.time()
    raw = await request.body()

    headers_lc = {k.lower(): v for k, v in request.headers.items()}
    verify_request_auth_or_401(raw, headers_lc)

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    req = RunRequest.from_payload(payload)

    cleanup_stale_runs()

    if (time.time() - started) > RUN_MAX_SECONDS:
        raise HTTPException(status_code=408, detail="Request timed out before start.")

    existing = idempotency_lookup(req)
    if existing:
        fields = existing.get("fields", {}) or {}
        try:
            previous_result = json.loads(fields.get("Result_JSON", "{}") or "{}")
        except Exception:
            previous_result = {"note": "Result_JSON unreadable"}

        return RunResponse(
            ok=True,
            worker=req.worker,
            capability=req.capability,
            idempotency_key=req.idempotency_key,
            run_id=str(fields.get("Run_ID", "")) or "unknown",
            airtable_record_id=existing.get("id"),
            result={"idempotent_replay": True, "previous": previous_result},
        )

    run_record_id, run_uuid = create_system_run(req)
    response.headers["X-Run-Record-Id"] = run_record_id
    response.headers["X-Run-Id"] = run_uuid

    try:
        fn = CAPABILITIES.get(req.capability)
        if not fn:
            finish_system_run(run_record_id, "Unsupported", {"ok": False, "error": "unsupported_capability"})
            raise HTTPException(status_code=400, detail=f"Unsupported capability: {req.capability}")

        result_obj = fn(req, run_record_id)
        if isinstance(result_obj, dict) and "run_record_id" not in result_obj:
            result_obj["run_record_id"] = run_record_id

        finish_system_run(run_record_id, "Done", result_obj)

        return RunResponse(
            ok=True,
            worker=req.worker,
            capability=req.capability,
            idempotency_key=req.idempotency_key,
            run_id=run_uuid,
            airtable_record_id=run_record_id,
            result=result_obj,
        )

    except HTTPException as e:
        fail_system_run(run_record_id, str(e.detail))
        raise
    except Exception as e:
        fail_system_run(run_record_id, repr(e))
        raise HTTPException(status_code=500, detail="Internal error.")
