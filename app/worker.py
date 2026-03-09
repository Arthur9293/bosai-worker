# app/worker.py — BOSAI Worker (v2.5.5)
# SAFE PATCH over your v2.5.4:
# - Keeps existing behavior intact (auth/idempotency/locks/retry/CORS unchanged)
# - Keeps existing /run and command_orchestrator behavior intact
# - Keeps READ-ONLY dashboard endpoints intact:
#   * GET /runs
#   * GET /commands
#   * GET /sla
# - Adds Event Engine v1:
#   * new Airtable table: Events
#   * new env vars: EVENTS_TABLE_NAME, EVENTS_VIEW_NAME
#   * new capability: event_engine
# - Event Engine guardrails:
#   * no crash if Airtable env missing
#   * no crash if fields absent / payload empty / view missing
#   * best-effort create/update
#   * anti-duplicate via deterministic command idempotency key per event

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
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.capabilities.http_exec import capability_http_exec as capability_http_exec_impl
from app.policies import get_policies

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

EVENTS_TABLE_NAME = os.getenv("EVENTS_TABLE_NAME", "Events").strip()

LOGS_ERRORS_VIEW_NAME = os.getenv("LOGS_ERRORS_VIEW_NAME", "Active").strip()
COMMANDS_VIEW_NAME = os.getenv("COMMANDS_VIEW_NAME", "Queue").strip()
EVENTS_VIEW_NAME = os.getenv("EVENTS_VIEW_NAME", "Queue").strip()
EVENTS_DASHBOARD_VIEW_NAME = os.getenv("EVENTS_DASHBOARD_VIEW_NAME", EVENTS_VIEW_NAME or "Grid view").strip()


# SAFE read-only dashboard view settings
SYSTEM_RUNS_VIEW_NAME = os.getenv("SYSTEM_RUNS_VIEW_NAME", "Grid view").strip()
COMMANDS_DASHBOARD_VIEW_NAME = os.getenv("COMMANDS_DASHBOARD_VIEW_NAME", COMMANDS_VIEW_NAME or "Queue").strip()
SLA_DASHBOARD_VIEW_NAME = os.getenv("SLA_DASHBOARD_VIEW_NAME", LOGS_ERRORS_VIEW_NAME or "Active").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()
APP_NAME = os.getenv("APP_NAME", "bosai-worker").strip()
APP_VERSION = os.getenv("APP_VERSION", "2.5.5").strip()

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
            "SLA_Status,Last_SLA_Check,Linked_Run,Escalation_Queued",
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
# CORS (SAFE)
# ============================================================

CORS_ALLOW_ORIGINS_RAW = os.getenv("CORS_ALLOW_ORIGINS", "*").strip()
CORS_ALLOW_METHODS_RAW = os.getenv("CORS_ALLOW_METHODS", "*").strip()
CORS_ALLOW_HEADERS_RAW = os.getenv("CORS_ALLOW_HEADERS", "*").strip()
CORS_EXPOSE_HEADERS_RAW = os.getenv("CORS_EXPOSE_HEADERS", "X-Run-Record-Id,X-Run-Id").strip()
CORS_ALLOW_CREDENTIALS = (os.getenv("CORS_ALLOW_CREDENTIALS", "0").strip().lower() in ("1", "true", "yes", "on"))


def _csv_env_list(raw: str, default: List[str]) -> List[str]:
    items = [x.strip() for x in (raw or "").split(",") if x.strip()]
    return items or default


CORS_ALLOW_ORIGINS = _csv_env_list(CORS_ALLOW_ORIGINS_RAW, ["*"])
CORS_ALLOW_METHODS = _csv_env_list(CORS_ALLOW_METHODS_RAW, ["*"])
CORS_ALLOW_HEADERS = _csv_env_list(CORS_ALLOW_HEADERS_RAW, ["*"])
CORS_EXPOSE_HEADERS = _csv_env_list(CORS_EXPOSE_HEADERS_RAW, ["X-Run-Record-Id", "X-Run-Id"])

# Starlette/FastAPI rule:
# allow_credentials=True cannot be combined with wildcard "*" safely for origins.
if CORS_ALLOW_CREDENTIALS and "*" in CORS_ALLOW_ORIGINS:
    CORS_ALLOW_CREDENTIALS = False

# ============================================================
# Policies (SAFE, defaults-first)
# ============================================================

POLICIES = get_policies() or {}


def _policy_get(name: str, default: Any) -> Any:
    try:
        value = POLICIES.get(name, default)
        return default if value is None else value
    except Exception:
        return default


def _policy_get_bool(name: str, default: bool) -> bool:
    value = _policy_get(name, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def _policy_get_int(name: str, default: int) -> int:
    try:
        return int(_policy_get(name, default))
    except Exception:
        return default


def _policy_get_float(name: str, default: float) -> float:
    try:
        return float(_policy_get(name, default))
    except Exception:
        return default


POLICY_MAX_TOOL_CALLS = _policy_get_int("MAX_TOOL_CALLS", 0)
POLICY_RETRY_LIMIT = _policy_get_int("RETRY_LIMIT", 0)
POLICY_LOCK_TTL_MINUTES = _policy_get_int("LOCK_TTL_MINUTES", 0)
POLICY_SLA_WARNING_THRESHOLD_MIN = _policy_get_float("SLA_WARNING_THRESHOLD_MIN", SLA_WARNING_THRESHOLD_MIN)
POLICY_APPROVAL_REQUIRED_FOR_WRITE = _policy_get_bool("APPROVAL_REQUIRED_FOR_WRITE", False)
POLICY_REDACT_SECRETS_IN_LOGS = _policy_get_bool("REDACT_SECRETS_IN_LOGS", True)
POLICY_STORE_TOOL_TRACE = _policy_get_bool("STORE_TOOL_TRACE", False)

# ============================================================
# FastAPI
# ============================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=CORS_ALLOW_METHODS,
    allow_headers=CORS_ALLOW_HEADERS,
    expose_headers=CORS_EXPOSE_HEADERS,
)

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


def _is_truthy(v: Any) -> bool:
    if v is True:
        return True
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "y", "on")


def _safe_limit(raw_limit: int, default: int, minimum: int = 1, maximum: int = 200) -> int:
    try:
        v = int(raw_limit)
    except Exception:
        v = default
    if v < minimum:
        return default
    if v > maximum:
        return maximum
    return v


def _safe_records_from_view(table_name: str, view_name: str, limit: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    SAFE read helper:
    - never crashes the endpoint
    - returns [] + diagnostic metadata on failure
    """
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        return [], {"ok": False, "reason": "airtable_env_missing", "table": table_name, "view": view_name}

    try:
        records = airtable_list_view(table_name, view_name, max_records=limit)
        return records, {"ok": True, "table": table_name, "view": view_name}
    except HTTPException as e:
        return [], {"ok": False, "reason": "airtable_read_failed", "detail": str(e.detail), "table": table_name, "view": view_name}
    except Exception as e:
        return [], {"ok": False, "reason": "exception", "detail": repr(e), "table": table_name, "view": view_name}


# ============================================================
# Commands idempotency protection (SAFE)
# ============================================================

def _at_escape(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace("'", "\\'").strip()


def find_done_command_by_idem(idem_key: str, exclude_record_id: str) -> Optional[Dict[str, Any]]:
    """
    If another command exists with same Idempotency_Key and Status_select='Done', return it.
    SAFE: returns None on any Airtable error; does not break execution.
    """
    try:
        idem = _at_escape(idem_key)
        excl = _at_escape(exclude_record_id)
        if not idem:
            return None

        formula = (
            "AND("
            f"{{Idempotency_Key}}='{idem}',"
            "{{Status_select}}='Done',"
            f"RECORD_ID()!='{excl}'"
            ")"
        )
        return airtable_find_first(COMMANDS_TABLE_NAME, formula=formula, max_records=1)
    except Exception:
        return None


def find_command_by_idem(idem_key: str) -> Optional[Dict[str, Any]]:
    """
    Find any existing command by deterministic idempotency key.
    SAFE: returns None on any Airtable error.
    """
    try:
        idem = _at_escape(idem_key)
        if not idem:
            return None
        formula = f"{{Idempotency_Key}}='{idem}'"
        return airtable_find_first(COMMANDS_TABLE_NAME, formula=formula, max_records=1)
    except Exception:
        return None


# ============================================================
# Commands Lock / Retry helpers (SAFE, best-effort)
# ============================================================

def _new_lock_token() -> str:
    return uuid.uuid4().hex


def _command_lock_ttl_min() -> int:
    try:
        if POLICY_LOCK_TTL_MINUTES and POLICY_LOCK_TTL_MINUTES > 0:
            return POLICY_LOCK_TTL_MINUTES
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

    if POLICY_RETRY_LIMIT > 0 and count > POLICY_RETRY_LIMIT:
        count = POLICY_RETRY_LIMIT

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


def _airtable_create_best_effort(table_name: str, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    last_err: Optional[str] = None
    for fields in candidates:
        if not fields:
            continue
        try:
            record_id = airtable_create(table_name, fields)
            return {"ok": True, "record_id": record_id, "applied_fields": list(fields.keys())}
        except HTTPException as e:
            last_err = str(e.detail)
            continue
        except Exception as e:
            last_err = repr(e)
            continue
    return {"ok": False, "error": last_err or "create_failed"}


def _release_command_lock_best_effort(command_id: str) -> None:
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
# Event Engine helpers (SAFE, deterministic)
# ============================================================

EVENT_TYPE_TO_CAPABILITY: Dict[str, str] = {
    "sla.breached": "escalation_engine",
    "command.stale_lock": "lock_recovery",
    "system.health.check": "health_tick",
    "http.call.requested": "http_exec",
}


def _event_target_capability(event_type: str) -> Optional[str]:
    return EVENT_TYPE_TO_CAPABILITY.get(str(event_type or "").strip())


def _event_command_idem(event_id: str, target_capability: str) -> str:
    return f"event:{event_id}:{target_capability}"


def _event_has_linked_command(fields: Dict[str, Any]) -> bool:
    linked = fields.get("Linked_Command")
    if isinstance(linked, list) and len(linked) > 0:
        return True
    if linked:
        return True
    return False


def _event_payload(fields: Dict[str, Any]) -> Dict[str, Any]:
    payload = _json_load_maybe(fields.get("Payload_JSON"))
    if isinstance(payload, dict):
        return payload
    return {}


def _event_status(fields: Dict[str, Any]) -> str:
    return str(fields.get("Status", fields.get("Status_select", "")) or "").strip()


def _build_command_fields_candidates(
    capability: str,
    idem_key: str,
    input_obj: Dict[str, Any],
    run_record_id: str,
    event_id: str,
    event_type: str,
) -> List[Dict[str, Any]]:
    input_json = json.dumps(input_obj or {}, ensure_ascii=False)
    now = utc_now_iso()

    return [
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Idempotency_Key": idem_key,
            "Input_JSON": input_json,
            "Linked_Run": [run_record_id],
            "Source_Event_ID": event_id,
            "Event_Type": event_type,
            "Scheduled_At": now,
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Idempotency_Key": idem_key,
            "Input_JSON": input_json,
            "Linked_Run": [run_record_id],
            "Source_Event_ID": event_id,
            "Event_Type": event_type,
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Idempotency_Key": idem_key,
            "Input_JSON": input_json,
            "Linked_Run": [run_record_id],
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Idempotency_Key": idem_key,
            "Input_JSON": input_json,
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Idempotency_Key": idem_key,
        },
    ]


def _mark_event_processed_best_effort(event_id: str, command_record_id: str, capability: str) -> Dict[str, Any]:
    now = utc_now_iso()
    return _airtable_update_best_effort(
        EVENTS_TABLE_NAME,
        event_id,
        [
            {
                "Status": "Processed",
                "Command_Created": True,
                "Linked_Command": [command_record_id],
                "Processed_At": now,
                "Mapped_Capability": capability,
            },
            {
                "Status_select": "Processed",
                "Command_Created": True,
                "Linked_Command": [command_record_id],
                "Processed_At": now,
                "Mapped_Capability": capability,
            },
            {
                "Status": "Processed",
                "Command_Created": True,
                "Linked_Command": [command_record_id],
            },
            {
                "Status_select": "Processed",
                "Command_Created": True,
                "Linked_Command": [command_record_id],
            },
            {
                "Status": "Processed",
                "Command_Created": True,
            },
            {
                "Status_select": "Processed",
                "Command_Created": True,
            },
            {
                "Command_Created": True,
                "Linked_Command": [command_record_id],
            },
        ],
    )


def _mark_event_ignored_best_effort(event_id: str, reason: str, event_type: str) -> Dict[str, Any]:
    now = utc_now_iso()
    payload = json.dumps({"reason": reason, "event_type": event_type}, ensure_ascii=False)
    return _airtable_update_best_effort(
        EVENTS_TABLE_NAME,
        event_id,
        [
            {
                "Status": "Ignored",
                "Processed_At": now,
                "Error_Message": reason,
                "Result_JSON": payload,
            },
            {
                "Status_select": "Ignored",
                "Processed_At": now,
                "Error_Message": reason,
                "Result_JSON": payload,
            },
            {
                "Status": "Ignored",
                "Error_Message": reason,
            },
            {
                "Status_select": "Ignored",
                "Error_Message": reason,
            },
            {
                "Status": "Ignored",
            },
            {
                "Status_select": "Ignored",
            },
        ],
    )


def _mark_event_error_best_effort(event_id: str, error_message: str) -> Dict[str, Any]:
    now = utc_now_iso()
    payload = json.dumps({"error": error_message}, ensure_ascii=False)
    return _airtable_update_best_effort(
        EVENTS_TABLE_NAME,
        event_id,
        [
            {
                "Status": "Error",
                "Processed_At": now,
                "Error_Message": error_message,
                "Result_JSON": payload,
            },
            {
                "Status_select": "Error",
                "Processed_At": now,
                "Error_Message": error_message,
                "Result_JSON": payload,
            },
            {
                "Status": "Error",
                "Error_Message": error_message,
            },
            {
                "Status_select": "Error",
                "Error_Message": error_message,
            },
            {
                "Status": "Error",
            },
            {
                "Status_select": "Error",
            },
        ],
    )


# ============================================================
# Capabilities
# ============================================================

def capability_health_tick(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return {"ok": True, "probe": "airtable_ok", "ts": utc_now_iso(), "run_record_id": run_record_id}


def _sla_status_for_remaining(remaining_min: float) -> str:
    warning_threshold = POLICY_SLA_WARNING_THRESHOLD_MIN
    if remaining_min <= 0:
        return SLA_STATUS_BREACHED
    if remaining_min <= warning_threshold:
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


def capability_escalation_engine(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    """
    SAFE escalation engine:
    - Scan Logs_Erreurs view Active
    - If breached (SLA_Status == Breached OR SLA_Remaining_Minutes <= 0)
      and not Escalated and not Escalation_Queued
      -> set Escalation_Queued=true (if allowed) + Linked_Run=[run_record_id] (if allowed)
    """
    inp = req.input or {}
    limit = int(inp.get("limit", 200) or 200)
    if limit <= 0:
        limit = 200
    if limit > 500:
        limit = 500

    only_breached = bool(inp.get("only_breached", True))

    records = airtable_list_view(LOGS_ERRORS_TABLE_NAME, LOGS_ERRORS_VIEW_NAME, max_records=limit)

    queued = 0
    skipped = 0
    failed = 0
    errors: List[str] = []
    now = utc_now_iso()

    for rec in records:
        rid = rec.get("id")
        if not rid:
            continue
        fields = rec.get("fields", {}) or {}

        sla_status = str(fields.get("SLA_Status", "") or "").strip()
        remaining = _parse_float(fields.get("SLA_Remaining_Minutes"))

        breached = False
        if sla_status == SLA_STATUS_BREACHED:
            breached = True
        elif remaining is not None and remaining <= 0:
            breached = True

        if only_breached and not breached:
            skipped += 1
            continue

        if sla_status == SLA_STATUS_ESCALATED:
            skipped += 1
            continue

        if _is_truthy(fields.get("Escalation_Queued")):
            skipped += 1
            continue

        update_fields: Dict[str, Any] = {}

        if "Escalation_Queued" in LOGS_ERRORS_FIELDS_ALLOWED:
            update_fields["Escalation_Queued"] = True
        if "Linked_Run" in LOGS_ERRORS_FIELDS_ALLOWED:
            update_fields["Linked_Run"] = [run_record_id]

        if not update_fields:
            skipped += 1
            continue

        try:
            airtable_update(LOGS_ERRORS_TABLE_NAME, rid, update_fields)
            queued += 1
        except HTTPException as e:
            failed += 1
            errors.append(f"{rid}: {e.detail}")
        except Exception as e:
            failed += 1
            errors.append(f"{rid}: {repr(e)}")

    return {
        "ok": True,
        "view": LOGS_ERRORS_VIEW_NAME,
        "scanned": len(records),
        "queued": queued,
        "skipped": skipped,
        "failed": failed,
        "errors_count": len(errors),
        "errors": errors[:10],
        "run_record_id": run_record_id,
        "ts": now,
    }


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

    url_value = str(fields.get("URL", "") or "").strip()
    if url_value:
        built["URL"] = url_value

    url_lower = str(fields.get("url", "") or "").strip()
    if url_lower:
        built["url"] = url_lower

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
        built["Approved"] = approved

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


# ============================================================
# Retry Queue (SAFE, best-effort)
# ============================================================

def capability_retry_queue(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    """
    Promote due Retry commands back to Queued so the view-based fallback also works.
    SAFE:
    - If formulas/fields missing, it no-ops without crashing.
    """
    inp = req.input or {}
    limit = int(inp.get("limit", 50) or 50)
    if limit <= 0:
        limit = 50
    if limit > 200:
        limit = 200

    formula = (
        "AND("
        "{Status_select}='Retry',"
        "{Next_Retry_At}!=BLANK(),"
        "OR(IS_BEFORE({Next_Retry_At},NOW()),{Next_Retry_At}=NOW())"
        ")"
    )

    try:
        recs = airtable_list_filtered(
            COMMANDS_TABLE_NAME,
            formula=formula,
            view_name=(req.view or COMMANDS_VIEW_NAME or "Queue").strip(),
            sort=[{"field": "Next_Retry_At", "direction": "asc"}],
            max_records=limit,
        )
        mode = "formula"
    except Exception:
        recs = airtable_list_view(
            COMMANDS_TABLE_NAME,
            (req.view or COMMANDS_VIEW_NAME or "Queue").strip(),
            max_records=limit,
        )
        mode = "view_fallback"

    promoted = 0
    failed = 0
    errors: List[str] = []

    for r in recs:
        cid = r.get("id")
        if not cid:
            continue
        fields = r.get("fields", {}) or {}
        if _read_command_status(fields) != "Retry":
            continue

        res = _airtable_update_best_effort(
            COMMANDS_TABLE_NAME,
            cid,
            [
                {"Status_select": "Queued", "Next_Retry_At": None, "Linked_Run": [run_record_id]},
                {"Status_select": "Queued", "Linked_Run": [run_record_id]},
                {"Status_select": "Queued"},
            ],
        )
        if res.get("ok"):
            promoted += 1
        else:
            failed += 1
            errors.append(f"{cid}: {res.get('error')}")

    return {"ok": True, "mode": mode, "scanned": len(recs), "promoted": promoted, "failed": failed, "errors": errors[:10]}


# ============================================================
# Lock Recovery (SAFE, best-effort)
# ============================================================

def capability_lock_recovery(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    """
    Recover stale locks by moving stuck Running commands back to Retry (or Queued),
    and clearing lock fields best-effort.
    """
    inp = req.input or {}
    limit = int(inp.get("limit", 50) or 50)
    if limit <= 0:
        limit = 50
    if limit > 200:
        limit = 200

    view_name = (req.view or COMMANDS_VIEW_NAME or "Queue").strip()

    formula = (
        "OR("
        "{Is_Lock_Stale}=1,"
        "AND({Status_select}='Running',{Is_Locked}=1,{Lock_Expires_At}!=BLANK(),IS_BEFORE({Lock_Expires_At},NOW()))"
        ")"
    )

    try:
        recs = airtable_list_filtered(
            COMMANDS_TABLE_NAME,
            formula=formula,
            view_name=view_name,
            sort=[{"field": "Lock_Expires_At", "direction": "asc"}],
            max_records=limit,
        )
        mode = "formula"
    except Exception:
        recs = airtable_list_view(COMMANDS_TABLE_NAME, view_name, max_records=limit)
        mode = "view_fallback"

    recovered = 0
    skipped = 0
    failed = 0
    errors: List[str] = []

    now = utc_now_iso()

    for r in recs:
        cid = r.get("id")
        if not cid:
            continue
        fields = r.get("fields", {}) or {}
        status = _read_command_status(fields)

        if status not in ("Running", "Queued", "Retry"):
            skipped += 1
            continue

        is_locked = fields.get("Is_Locked")
        if status == "Running" and is_locked is not True:
            skipped += 1
            continue

        note = {"note": "lock_recovered", "at": now}

        res = _airtable_update_best_effort(
            COMMANDS_TABLE_NAME,
            cid,
            [
                {
                    "Status_select": "Retry",
                    "Next_Retry_At": now,
                    "Last_Error": json.dumps(note, ensure_ascii=False),
                    "Error_Message": "",
                    "Is_Locked": False,
                    "Lock_Expires_At": None,
                    "Lock_Token": "",
                    "Last_Heartbeat_At": now,
                    "Linked_Run": [run_record_id],
                },
                {
                    "Status_select": "Retry",
                    "Next_Retry_At": now,
                    "Is_Locked": False,
                    "Lock_Expires_At": None,
                    "Lock_Token": "",
                    "Linked_Run": [run_record_id],
                },
                {"Status_select": "Retry", "Next_Retry_At": now, "Linked_Run": [run_record_id]},
            ],
        )

        if res.get("ok"):
            recovered += 1
        else:
            failed += 1
            errors.append(f"{cid}: {res.get('error')}")

        _release_command_lock_best_effort(cid)

    return {
        "ok": True,
        "mode": mode,
        "scanned": len(recs),
        "recovered": recovered,
        "skipped": skipped,
        "failed": failed,
        "errors": errors[:10],
    }


# ============================================================
# Event Engine v1 (SAFE, best-effort)
# ============================================================

def capability_event_engine(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    """
    Event Engine v1:
    - Read Events view Queue
    - If Status=Queued and no command already created:
      -> map Event_Type deterministically to target capability
      -> create one Command
      -> mark Event Processed + Command_Created + Linked_Command
    - Unknown Event_Type -> Ignored
    - Error -> Error
    Guardrails:
    - anti-duplicate via deterministic command idempotency key
    - Payload_JSON may be empty
    - best-effort updates
    - no crash if fields absent
    """
    inp = req.input or {}
    limit = int(inp.get("limit", 50) or 50)
    if limit <= 0:
        limit = 50
    if limit > 200:
        limit = 200

    view_name = (req.view or EVENTS_VIEW_NAME or "Queue").strip()

    try:
        events = airtable_list_view(EVENTS_TABLE_NAME, view_name, max_records=limit)
        selection_mode = "view"
    except Exception as e:
        return {
            "ok": True,
            "view": view_name,
            "selection_mode": "view_error",
            "scanned": 0,
            "created": 0,
            "processed": 0,
            "ignored": 0,
            "errors_count": 1,
            "errors": [repr(e)],
            "run_record_id": run_record_id,
            "ts": utc_now_iso(),
        }

    scanned = 0
    created = 0
    processed = 0
    ignored = 0
    skipped = 0
    errored = 0

    commands_record_ids: List[str] = []
    processed_event_ids: List[str] = []
    ignored_event_ids: List[str] = []
    skipped_event_ids: List[str] = []
    error_event_ids: List[str] = []
    errors: List[str] = []

    for ev in events:
        event_id = ev.get("id")
        if not event_id:
            continue

        scanned += 1
        fields = ev.get("fields", {}) or {}

        status = _event_status(fields)
        command_created = _is_truthy(fields.get("Command_Created"))
        has_linked_command = _event_has_linked_command(fields)

        if status != "Queued":
            skipped += 1
            skipped_event_ids.append(event_id)
            continue

        if command_created or has_linked_command:
            skipped += 1
            skipped_event_ids.append(event_id)
            continue

        event_type = str(fields.get("Event_Type", "") or "").strip()
        target_capability = _event_target_capability(event_type)

        if not target_capability:
            res = _mark_event_ignored_best_effort(event_id, "Unknown Event_Type", event_type)
            if not res.get("ok"):
                errors.append(f"{event_id}: ignored_update_failed:{res.get('error')}")
                errored += 1
                error_event_ids.append(event_id)
            else:
                ignored += 1
                ignored_event_ids.append(event_id)
            continue

        idem_key = _event_command_idem(event_id, target_capability)

        existing_cmd = find_command_by_idem(idem_key)
        if existing_cmd:
            existing_cmd_id = existing_cmd.get("id")
            if existing_cmd_id:
                res = _mark_event_processed_best_effort(event_id, existing_cmd_id, target_capability)
                if res.get("ok"):
                    processed += 1
                    processed_event_ids.append(event_id)
                    commands_record_ids.append(existing_cmd_id)
                else:
                    errored += 1
                    error_event_ids.append(event_id)
                    errors.append(f"{event_id}: processed_update_failed:{res.get('error')}")
            else:
                err = "existing_command_without_id"
                _mark_event_error_best_effort(event_id, err)
                errored += 1
                error_event_ids.append(event_id)
                errors.append(f"{event_id}: {err}")
            continue

        payload = _event_payload(fields)
        if not isinstance(payload, dict):
            payload = {}

        create_res = _airtable_create_best_effort(
            COMMANDS_TABLE_NAME,
            _build_command_fields_candidates(
                capability=target_capability,
                idem_key=idem_key,
                input_obj=payload,
                run_record_id=run_record_id,
                event_id=event_id,
                event_type=event_type,
            ),
        )

        if not create_res.get("ok"):
            err = f"command_create_failed:{create_res.get('error')}"
            _mark_event_error_best_effort(event_id, err)
            errored += 1
            error_event_ids.append(event_id)
            errors.append(f"{event_id}: {err}")
            continue

        command_record_id = str(create_res.get("record_id") or "").strip()
        if not command_record_id:
            err = "command_created_but_missing_record_id"
            _mark_event_error_best_effort(event_id, err)
            errored += 1
            error_event_ids.append(event_id)
            errors.append(f"{event_id}: {err}")
            continue

        created += 1
        commands_record_ids.append(command_record_id)

        mark_res = _mark_event_processed_best_effort(event_id, command_record_id, target_capability)
        if mark_res.get("ok"):
            processed += 1
            processed_event_ids.append(event_id)
        else:
            errored += 1
            error_event_ids.append(event_id)
            errors.append(f"{event_id}: processed_update_failed:{mark_res.get('error')}")

    return {
        "ok": True,
        "view": view_name,
        "selection_mode": selection_mode,
        "scanned": scanned,
        "created": created,
        "processed": processed,
        "ignored": ignored,
        "skipped": skipped,
        "errored": errored,
        "commands_record_ids": commands_record_ids,
        "processed_event_ids": processed_event_ids,
        "ignored_event_ids": ignored_event_ids,
        "skipped_event_ids": skipped_event_ids,
        "error_event_ids": error_event_ids,
        "errors_count": len(errors),
        "errors": errors[:10],
        "run_record_id": run_record_id,
        "ts": utc_now_iso(),
    }
def _extract_http_status_from_result(result_obj: Dict[str, Any]) -> Optional[int]:
    if not isinstance(result_obj, dict):
        return None

    for key in ("status_code", "http_status", "status"):
        value = result_obj.get(key)
        try:
            if value is None:
                continue
            n = int(value)
            if 100 <= n <= 599:
                return n
        except Exception:
            pass

    response_obj = result_obj.get("response")
    if isinstance(response_obj, dict):
        for key in ("status_code", "http_status", "status"):
            value = response_obj.get(key)
            try:
                if value is None:
                    continue
                n = int(value)
                if 100 <= n <= 599:
                    return n
            except Exception:
                pass

    return None


def _command_mark_running_best_effort(command_id: str, run_record_id: str, worker_name: str, idem: str) -> Dict[str, Any]:
    now = utc_now_iso()
    ttl_min = _command_lock_ttl_min()
    lock_token = _new_lock_token()
    expires_at = _utc_plus_minutes_iso(ttl_min)

    return _airtable_update_best_effort(
        COMMANDS_TABLE_NAME,
        command_id,
        [
            {
                "Status_select": "Running",
                "Idempotency_Key": idem,
                "Linked_Run": [run_record_id],
                "Started_At": now,
                "Error_Message": "",
                "Last_Error": "",
                "Is_Locked": True,
                "Locked_At": now,
                "Locked_By": worker_name,
                "Lock_Token": lock_token,
                "Lock_TTL_Min": ttl_min,
                "Lock_Expires_At": expires_at,
                "Last_Heartbeat_At": now,
            },
            {
                "Status_select": "Running",
                "Idempotency_Key": idem,
                "Linked_Run": [run_record_id],
                "Started_At": now,
                "Error_Message": "",
                "Last_Error": "",
                "Is_Locked": True,
                "Locked_At": now,
                "Locked_By": worker_name,
            },
            {
                "Status_select": "Running",
                "Idempotency_Key": idem,
                "Linked_Run": [run_record_id],
                "Started_At": now,
                "Error_Message": "",
                "Last_Error": "",
            },
            {
                "Status_select": "Running",
                "Linked_Run": [run_record_id],
                "Started_At": now,
                "Error_Message": "",
            },
            {
                "Status_select": "Running",
                "Started_At": now,
            },
            {
                "Status_select": "Running",
            },
        ],
    )


def _command_mark_done_best_effort(
    command_id: str,
    run_record_id: str,
    result_obj: Dict[str, Any],
) -> Dict[str, Any]:
    now = utc_now_iso()
    result_json = json.dumps(result_obj, ensure_ascii=False)
    http_status = _extract_http_status_from_result(result_obj)

    candidates: List[Dict[str, Any]] = [
        {
            "Status_select": "Done",
            "Finished_At": now,
            "Result_JSON": result_json,
            "Last_Error": "",
            "Error_Message": "",
            "Linked_Run": [run_record_id],
            "Is_Locked": False,
            "Lock_Expires_At": None,
            "Lock_Token": "",
            "Last_Heartbeat_At": now,
            "Last_HTTP_Status": http_status,
        },
        {
            "Status_select": "Done",
            "Finished_At": now,
            "Result_JSON": result_json,
            "Last_Error": "",
            "Error_Message": "",
            "Linked_Run": [run_record_id],
            "Is_Locked": False,
            "Lock_Expires_At": None,
            "Lock_Token": "",
            "Last_Heartbeat_At": now,
        },
        {
            "Status_select": "Done",
            "Finished_At": now,
            "Result_JSON": result_json,
            "Linked_Run": [run_record_id],
        },
        {
            "Status_select": "Done",
            "Result_JSON": result_json,
            "Linked_Run": [run_record_id],
        },
        {
            "Status_select": "Done",
            "Linked_Run": [run_record_id],
        },
        {
            "Status_select": "Done",
        },
    ]

    return _airtable_update_best_effort(COMMANDS_TABLE_NAME, command_id, candidates)


def _command_mark_blocked_duplicate_best_effort(
    command_id: str,
    run_record_id: str,
    note: Dict[str, Any],
) -> Dict[str, Any]:
    now = utc_now_iso()
    payload = json.dumps(note, ensure_ascii=False)

    return _airtable_update_best_effort(
        COMMANDS_TABLE_NAME,
        command_id,
        [
            {
                "Status_select": "Blocked",
                "Finished_At": now,
                "Result_JSON": payload,
                "Last_Error": payload,
                "Error_Message": "",
                "Linked_Run": [run_record_id],
                "Is_Locked": False,
                "Lock_Expires_At": None,
                "Lock_Token": "",
                "Last_Heartbeat_At": now,
            },
            {
                "Status_select": "Blocked",
                "Finished_At": now,
                "Result_JSON": payload,
                "Linked_Run": [run_record_id],
            },
            {
                "Status_select": "Blocked",
                "Linked_Run": [run_record_id],
            },
            {
                "Status_select": "Blocked",
            },
        ],
    )


def _command_mark_unsupported_best_effort(
    command_id: str,
    run_record_id: str,
    message: str,
) -> Dict[str, Any]:
    now = utc_now_iso()
    payload = json.dumps({"error": message}, ensure_ascii=False)

    return _airtable_update_best_effort(
        COMMANDS_TABLE_NAME,
        command_id,
        [
            {
                "Status_select": "Unsupported",
                "Finished_At": now,
                "Error_Message": message,
                "Last_Error": message,
                "Result_JSON": payload,
                "Linked_Run": [run_record_id],
                "Is_Locked": False,
                "Lock_Expires_At": None,
                "Lock_Token": "",
            },
            {
                "Status_select": "Unsupported",
                "Finished_At": now,
                "Error_Message": message,
                "Result_JSON": payload,
                "Linked_Run": [run_record_id],
            },
            {
                "Status_select": "Unsupported",
                "Error_Message": message,
                "Linked_Run": [run_record_id],
            },
            {
                "Status_select": "Unsupported",
            },
        ],
    )


def _command_mark_retry_or_dead_best_effort(
    command_id: str,
    run_record_id: str,
    fields: Dict[str, Any],
    message: str,
) -> Dict[str, Any]:
    now = utc_now_iso()
    payload = json.dumps({"error": message}, ensure_ascii=False)

    try:
        retry_count = int(fields.get("Retry_Count", 0) or 0)
    except Exception:
        retry_count = 0

    try:
        retry_max = int(fields.get("Retry_Max", 0) or 0)
    except Exception:
        retry_max = 0

    if POLICY_RETRY_LIMIT > 0:
        retry_max = POLICY_RETRY_LIMIT
    elif retry_max <= 0:
        retry_max = 3

    if retry_count < retry_max:
        next_at = _compute_next_retry_at(fields)
        return _airtable_update_best_effort(
            COMMANDS_TABLE_NAME,
            command_id,
            [
                {
                    "Status_select": "Retry",
                    "Retry_Count": retry_count + 1,
                    "Next_Retry_At": next_at,
                    "Finished_At": now,
                    "Last_Error": message,
                    "Error_Message": message,
                    "Result_JSON": payload,
                    "Linked_Run": [run_record_id],
                    "Is_Locked": False,
                    "Lock_Expires_At": None,
                    "Lock_Token": "",
                    "Last_Heartbeat_At": now,
                },
                {
                    "Status_select": "Retry",
                    "Retry_Count": retry_count + 1,
                    "Next_Retry_At": next_at,
                    "Finished_At": now,
                    "Last_Error": message,
                    "Error_Message": message,
                    "Linked_Run": [run_record_id],
                },
                {
                    "Status_select": "Retry",
                    "Retry_Count": retry_count + 1,
                    "Next_Retry_At": next_at,
                    "Linked_Run": [run_record_id],
                },
                {
                    "Status_select": "Retry",
                    "Linked_Run": [run_record_id],
                },
            ],
        )

    return _airtable_update_best_effort(
        COMMANDS_TABLE_NAME,
        command_id,
        [
            {
                "Status_select": "Dead",
                "Finished_At": now,
                "Last_Error": message,
                "Error_Message": message,
                "Result_JSON": payload,
                "Linked_Run": [run_record_id],
                "Is_Locked": False,
                "Lock_Expires_At": None,
                "Lock_Token": "",
                "Last_Heartbeat_At": now,
            },
            {
                "Status_select": "Dead",
                "Finished_At": now,
                "Last_Error": message,
                "Error_Message": message,
                "Linked_Run": [run_record_id],
            },
            {
                "Status_select": "Dead",
                "Linked_Run": [run_record_id],
            },
            {
                "Status_select": "Error",
                "Finished_At": now,
                "Error_Message": message,
                "Linked_Run": [run_record_id],
            },
        ],
    )    

def capability_command_orchestrator(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    max_cmds = int(req.max_commands or 0) or 5
    if POLICY_MAX_TOOL_CALLS > 0:
        max_cmds = min(max_cmds, POLICY_MAX_TOOL_CALLS)

    view_name = (req.view or COMMANDS_VIEW_NAME or "Queue").strip()

    formula = (
        "OR("
        "AND({Status_select}='Queued',OR({Scheduled_At}=BLANK(),IS_BEFORE({Scheduled_At},NOW()),{Scheduled_At}=NOW())),"
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
            ],
            max_records=max_cmds,
        )
        selection_mode = "scheduler"
        view = f"scheduler_formula+view:{view_name}"

    except Exception as e:
        
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

        status = _read_command_status(fields).lower()
        
        if status not in ("queued", "queue", "retry"):
            blocked += 1
            continue
        capability = str(fields.get("Capability", "")).strip()
        if not capability:
            failed += 1
            _command_mark_retry_or_dead_best_effort(
                command_id=cid,
                run_record_id=run_record_id,
                fields=fields,
                message="Missing Capability",
            )
            _release_command_lock_best_effort(cid)
            continue

        fn = CAPABILITIES.get(capability)
        if not fn:
            unsupported += 1
            _command_mark_unsupported_best_effort(
                command_id=cid,
                run_record_id=run_record_id,
                message=f"Unsupported capability: {capability}",
            )
            _release_command_lock_best_effort(cid)
            continue

        if POLICY_APPROVAL_REQUIRED_FOR_WRITE and capability in ("http_exec", "state_put"):
            approved = fields.get("Approved")
            if not _is_truthy(approved):
                blocked += 1
                approval_payload = {
                    "error": "Approval required by policy",
                    "capability": capability,
                    "approved_raw": approved,
                    "policy": "APPROVAL_REQUIRED_FOR_WRITE",
                }
                _airtable_update_best_effort(
                    COMMANDS_TABLE_NAME,
                    cid,
                    [
                        {
                            "Status_select": "Blocked",
                            "Finished_At": utc_now_iso(),
                            "Error_Message": "Approval required by policy",
                            "Last_Error": "Approval required by policy",
                            "Result_JSON": json.dumps(approval_payload, ensure_ascii=False),
                            "Linked_Run": [run_record_id],
                            "Is_Locked": False,
                            "Lock_Expires_At": None,
                            "Lock_Token": "",
                        },
                        {
                            "Status_select": "Blocked",
                            "Error_Message": "Approval required by policy",
                            "Result_JSON": json.dumps(approval_payload, ensure_ascii=False),
                            "Linked_Run": [run_record_id],
                        },
                        {"Status_select": "Blocked"},
                    ],
                )
                _release_command_lock_best_effort(cid)
                continue

        idem = str(fields.get("Idempotency_Key", "")).strip() or f"cmd:{cid}:{capability}"
        cmd_input = _compose_command_input(fields)

        dup_done = find_done_command_by_idem(idem, exclude_record_id=cid)
        if dup_done:
            note = {
                "ok": True,
                "skipped": True,
                "reason": "idempotent_duplicate_done_exists",
                "idempotency_key": idem,
                "matched_done_record_id": dup_done.get("id"),
            }
            _command_mark_blocked_duplicate_best_effort(
                command_id=cid,
                run_record_id=run_record_id,
                note=note,
            )
            _release_command_lock_best_effort(cid)
            blocked += 1
            continue

        lock_res = _command_mark_running_best_effort(
            command_id=cid,
            run_record_id=run_record_id,
            worker_name=req.worker,
            idem=idem,
        )
        if not lock_res.get("ok"):
            blocked += 1
            errors.append(f"{cid}: failed_to_mark_running:{lock_res.get('error')}")
            continue

        if capability == "http_exec":
            resolved_url = _resolve_http_exec_url_from_command_input(cmd_input)
            if not resolved_url:
                msg = "HTTP_EXEC missing url (Input_JSON.url / http_target / URL)"
                failed += 1

                try:
                    retry_count = int(fields.get("Retry_Count", 0) or 0)
                except Exception:
                    retry_count = 0
                try:
                    retry_max = int(fields.get("Retry_Max", 0) or 0)
                except Exception:
                    retry_max = 0

                if POLICY_RETRY_LIMIT > 0:
                    retry_max = POLICY_RETRY_LIMIT
                elif retry_max <= 0:
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
                                "Finished_At": utc_now_iso(),
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
                                "Finished_At": utc_now_iso(),
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
            if not isinstance(result_obj, dict):
                result_obj = {"ok": True, "result": result_obj}

            _command_mark_done_best_effort(
                command_id=cid,
                run_record_id=run_record_id,
                result_obj=result_obj,
            )

            succeeded += 1

        except HTTPException as e:
            msg = str(e.detail)
            failed += 1

            _command_mark_retry_or_dead_best_effort(
                command_id=cid,
                run_record_id=run_record_id,
                fields=fields,
                message=msg,
            )

            _release_command_lock_best_effort(cid)
            errors.append(f"{cid}: {msg}")

        except Exception as e:
            msg = repr(e)
            failed += 1

            _command_mark_retry_or_dead_best_effort(
                command_id=cid,
                run_record_id=run_record_id,
                fields=fields,
                message=msg,
            )

            _release_command_lock_best_effort(cid)
            errors.append(f"{cid}: {msg}")

    result = {
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

    inp2 = req.input or {}
    post_ops: Dict[str, Any] = {}

    if bool(inp2.get("run_retry_queue")):
        try:
            post_ops["retry_queue"] = capability_retry_queue(req, run_record_id)
        except Exception as e:
            post_ops["retry_queue"] = {"ok": False, "error": repr(e)}

    if bool(inp2.get("run_lock_recovery")):
        try:
            post_ops["lock_recovery"] = capability_lock_recovery(req, run_record_id)
        except Exception as e:
            post_ops["lock_recovery"] = {"ok": False, "error": repr(e)}

    if bool(inp2.get("run_escalation_engine")):
        try:
            post_ops["escalation_engine"] = capability_escalation_engine(req, run_record_id)
        except Exception as e:
            post_ops["escalation_engine"] = {"ok": False, "error": repr(e)}

    if bool(inp2.get("run_event_engine")):
        try:
            post_ops["event_engine"] = capability_event_engine(req, run_record_id)
        except Exception as e:
            post_ops["event_engine"] = {"ok": False, "error": repr(e)}

    if post_ops:
        result["post_ops"] = post_ops

    return result

def _resolve_http_exec_url_from_command_input(cmd_input: Dict[str, Any]) -> str:
    if not isinstance(cmd_input, dict):
        return ""

    for key in ("url", "http_target", "URL"):
        value = str(cmd_input.get(key, "") or "").strip()
        if value:
            return value

    return ""

CAPABILITIES = {
    "health_tick": capability_health_tick,
    "commands_tick": capability_commands_tick,
    "sla_machine": capability_sla_machine,
    "escalation_engine": capability_escalation_engine,
    "http_exec": capability_http_exec,
    "state_get": capability_state_get,
    "state_put": capability_state_put,
    "lock_acquire": capability_lock_acquire,
    "lock_release": capability_lock_release,
    "retry_queue": capability_retry_queue,
    "lock_recovery": capability_lock_recovery,
    "event_engine": capability_event_engine,
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
        "policies_loaded": bool(POLICIES),
        "policy_keys": sorted(list(POLICIES.keys())) if isinstance(POLICIES, dict) else [],
        "cors": {
            "allow_origins": CORS_ALLOW_ORIGINS,
            "allow_methods": CORS_ALLOW_METHODS,
            "allow_headers": CORS_ALLOW_HEADERS,
            "expose_headers": CORS_EXPOSE_HEADERS,
            "allow_credentials": CORS_ALLOW_CREDENTIALS,
        },
       "dashboard_views": {
            "system_runs_view": SYSTEM_RUNS_VIEW_NAME,
            "commands_dashboard_view": COMMANDS_DASHBOARD_VIEW_NAME,
            "sla_dashboard_view": SLA_DASHBOARD_VIEW_NAME,
            "events_dashboard_view": EVENTS_DASHBOARD_VIEW_NAME,
       },
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
    if POLICIES:
        issues.append("policies_loaded")
    return {"ok": True, "score": max(0, score), "issues": issues, "ts": utc_now_iso()}


# ============================================================
# READ-ONLY dashboard endpoints (SAFE)
# ============================================================

@app.get("/runs")
def get_runs(limit: int = 20) -> Dict[str, Any]:
    limit = _safe_limit(limit, default=20, minimum=1, maximum=100)
    records, meta = _safe_records_from_view(SYSTEM_RUNS_TABLE_NAME, SYSTEM_RUNS_VIEW_NAME, limit)
    runs: List[Dict[str, Any]] = []
    stats = {
        "running": 0,
        "done": 0,
        "error": 0,
        "unsupported": 0,
        "other": 0,
    }

    for r in records:
        f = r.get("fields", {}) or {}
        status = str(f.get("Status_select", "") or "").strip()

        if status == "Running":
            stats["running"] += 1
        elif status == "Done":
            stats["done"] += 1
        elif status == "Error":
            stats["error"] += 1
        elif status == "Unsupported":
            stats["unsupported"] += 1
        else:
            stats["other"] += 1

        runs.append(
            {
                "id": r.get("id"),
                "run_id": f.get("Run_ID"),
                "worker": f.get("Worker"),
                "capability": f.get("Capability"),
                "status": status,
                "priority": f.get("Priority"),
                "started_at": f.get("Started_At"),
                "finished_at": f.get("Finished_At"),
                "dry_run": f.get("Dry_Run"),
            }
        )

    return {
        "ok": bool(meta.get("ok")),
        "source": meta,
        "count": len(runs),
        "stats": stats,
        "runs": runs,
        "ts": utc_now_iso(),
    }


@app.get("/commands")
def get_commands(limit: int = 30) -> Dict[str, Any]:
    limit = _safe_limit(limit, default=30, minimum=1, maximum=100)
    records, meta = _safe_records_from_view(COMMANDS_TABLE_NAME, COMMANDS_DASHBOARD_VIEW_NAME, limit)

    commands: List[Dict[str, Any]] = []
    stats = {
        "queued": 0,
        "running": 0,
        "retry": 0,
        "done": 0,
        "dead": 0,
        "blocked": 0,
        "unsupported": 0,
        "error": 0,
        "other": 0,
    }

    for r in records:
        f = r.get("fields", {}) or {}
        status = _read_command_status(f)

        key = status.lower()
        if key == "queued" or key == "queue":
            stats["queued"] += 1
        elif key == "running":
            stats["running"] += 1
        elif key == "retry":
            stats["retry"] += 1
        elif key == "done":
            stats["done"] += 1
        elif key == "dead":
            stats["dead"] += 1
        elif key == "blocked":
            stats["blocked"] += 1
        elif key == "unsupported":
            stats["unsupported"] += 1
        elif key == "error":
            stats["error"] += 1
        else:
            stats["other"] += 1

        commands.append(
            {
                "id": r.get("id"),
                "capability": f.get("Capability"),
                "status": status,
                "priority": f.get("Priority"),
                "retry_count": f.get("Retry_Count"),
                "retry_max": f.get("Retry_Max"),
                "scheduled_at": f.get("Scheduled_At"),
                "next_retry_at": f.get("Next_Retry_At"),
                "is_locked": f.get("Is_Locked"),
                "locked_by": f.get("Locked_By"),
                "idempotency_key": f.get("Idempotency_Key"),
            }
        )

    return {
        "ok": bool(meta.get("ok")),
        "source": meta,
        "count": len(commands),
        "stats": stats,
        "commands": commands,
        "ts": utc_now_iso(),
    }


@app.get("/sla")
def get_sla(limit: int = 50) -> Dict[str, Any]:
    limit = _safe_limit(limit, default=50, minimum=1, maximum=200)
    records, meta = _safe_records_from_view(LOGS_ERRORS_TABLE_NAME, SLA_DASHBOARD_VIEW_NAME, limit)

    incidents: List[Dict[str, Any]] = []
    stats = {
        "ok": 0,
        "warning": 0,
        "breached": 0,
        "escalated": 0,
        "unknown": 0,
        "escalation_queued": 0,
    }

    for r in records:
        f = r.get("fields", {}) or {}
        status = str(f.get("SLA_Status", "") or "").strip()

        if status == SLA_STATUS_OK:
            stats["ok"] += 1
        elif status == SLA_STATUS_WARNING:
            stats["warning"] += 1
        elif status == SLA_STATUS_BREACHED:
            stats["breached"] += 1
        elif status == SLA_STATUS_ESCALATED:
            stats["escalated"] += 1
        else:
            stats["unknown"] += 1

        escalation_queued = _is_truthy(f.get("Escalation_Queued"))
        if escalation_queued:
            stats["escalation_queued"] += 1

        incidents.append(
            {
                "id": r.get("id"),
                "name": f.get("Name"),
                "sla_status": status,
                "sla_remaining_minutes": f.get("SLA_Remaining_Minutes"),
                "escalation_queued": escalation_queued,
                "last_sla_check": f.get("Last_SLA_Check"),
                "linked_run": f.get("Linked_Run"),
            }
        )

    return {
        "ok": bool(meta.get("ok")),
        "source": meta,
        "count": len(incidents),
        "stats": stats,
        "incidents": incidents,
        "ts": utc_now_iso(),
    }


@app.get("/events")
def get_events(limit: int = 30) -> Dict[str, Any]:
    limit = _safe_limit(limit, default=30, minimum=1, maximum=100)
    records, meta = _safe_records_from_view(EVENTS_TABLE_NAME, EVENTS_VIEW_NAME, limit)

    events: List[Dict[str, Any]] = []
    stats = {
        "queued": 0,
        "processed": 0,
        "ignored": 0,
        "error": 0,
        "other": 0,
    }

    for r in records:
        f = r.get("fields", {}) or {}

        status = str(f.get("Status", f.get("Status_select", "")) or "").strip()
        key = status.lower()

        if key == "queued":
            stats["queued"] += 1
        elif key == "processed":
            stats["processed"] += 1
        elif key == "ignored":
            stats["ignored"] += 1
        elif key == "error":
            stats["error"] += 1
        else:
            stats["other"] += 1

        payload = _event_payload(f)

        events.append(
            {
                "id": r.get("id"),
                "event_type": f.get("Event_Type"),
                "status": status,
                "command_created": _is_truthy(f.get("Command_Created")),
                "linked_command": f.get("Linked_Command"),
                "mapped_capability": f.get("Mapped_Capability"),
                "processed_at": f.get("Processed_At"),
                "source": payload.get("source") if isinstance(payload, dict) else None,
                "run_id": payload.get("run_id") if isinstance(payload, dict) else None,
                "command_id": payload.get("command_id") if isinstance(payload, dict) else None,
                "payload": payload,
            }
        )

    return {
        "ok": bool(meta.get("ok")),
        "source": meta,
        "count": len(events),
        "stats": stats,
        "events": events,
        "ts": utc_now_iso(),
    }


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

@app.get("/incidents")
def get_incidents():
    records = airtable_get_records(
        table=LOGS_ERRORS_TABLE_NAME,
        view="Active",
        max_records=50
    )

    incidents = []

    for r in records:
        f = r.get("fields", {})

        incidents.append({
            "id": r.get("id"),
            "title": f.get("Error_Message"),
            "status": f.get("Statut incident"),
            "severity": f.get("Urgence IA"),
            "sla_status": f.get("SLA_Status"),
            "created": f.get("Created time"),
            "worker": f.get("Worker"),
        })

    return {
        "ok": True,
        "count": len(incidents),
        "incidents": incidents
    }
