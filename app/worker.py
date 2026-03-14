# app/worker.py — BOSAI Worker rebuilt bootstrap
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.capabilities.commands_tick import run as capability_commands_tick
from app.capabilities.escalation_dispatch import capability_escalation_dispatch
from app.capabilities.health_tick import run as capability_health_tick
from app.capabilities.http_exec import capability_http_exec
from app.capabilities.sla_machine import run as capability_sla_machine
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

SYSTEM_RUNS_VIEW_NAME = os.getenv("SYSTEM_RUNS_VIEW_NAME", "Grid view").strip()
COMMANDS_DASHBOARD_VIEW_NAME = os.getenv("COMMANDS_DASHBOARD_VIEW_NAME", COMMANDS_VIEW_NAME or "Queue").strip()
SLA_DASHBOARD_VIEW_NAME = os.getenv("SLA_DASHBOARD_VIEW_NAME", LOGS_ERRORS_VIEW_NAME or "Active").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()
APP_NAME = os.getenv("APP_NAME", "bosai-worker").strip()
APP_VERSION = os.getenv("APP_VERSION", "2.5.5-rebuild").strip()

RUN_MAX_SECONDS = float((os.getenv("RUN_MAX_SECONDS", "30") or "30").strip())
HTTP_TIMEOUT_SECONDS = float((os.getenv("HTTP_TIMEOUT_SECONDS", "20") or "20").strip())
RUN_LOCK_TTL_SECONDS = int((os.getenv("RUN_LOCK_TTL_SECONDS", "600") or "600").strip())
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
# CORS
# ============================================================

CORS_ALLOW_ORIGINS_RAW = os.getenv("CORS_ALLOW_ORIGINS", "*").strip()
CORS_ALLOW_METHODS_RAW = os.getenv("CORS_ALLOW_METHODS", "*").strip()
CORS_ALLOW_HEADERS_RAW = os.getenv("CORS_ALLOW_HEADERS", "*").strip()
CORS_EXPOSE_HEADERS_RAW = os.getenv("CORS_EXPOSE_HEADERS", "X-Run-Record-Id,X-Run-Id").strip()
CORS_ALLOW_CREDENTIALS = (
    os.getenv("CORS_ALLOW_CREDENTIALS", "0").strip().lower() in ("1", "true", "yes", "on")
)


def _csv_env_list(raw: str, default: List[str]) -> List[str]:
    items = [x.strip() for x in (raw or "").split(",") if x.strip()]
    return items or default


CORS_ALLOW_ORIGINS = _csv_env_list(CORS_ALLOW_ORIGINS_RAW, ["*"])
CORS_ALLOW_METHODS = _csv_env_list(CORS_ALLOW_METHODS_RAW, ["*"])
CORS_ALLOW_HEADERS = _csv_env_list(CORS_ALLOW_HEADERS_RAW, ["*"])
CORS_EXPOSE_HEADERS = _csv_env_list(CORS_EXPOSE_HEADERS_RAW, ["X-Run-Record-Id", "X-Run-Id"])

if CORS_ALLOW_CREDENTIALS and "*" in CORS_ALLOW_ORIGINS:
    CORS_ALLOW_CREDENTIALS = False


# ============================================================
# Policies
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
POLICY_SLA_WARNING_THRESHOLD_MIN = _policy_get_float(
    "SLA_WARNING_THRESHOLD_MIN",
    SLA_WARNING_THRESHOLD_MIN,
)
POLICY_APPROVAL_REQUIRED_FOR_WRITE = _policy_get_bool("APPROVAL_REQUIRED_FOR_WRITE", False)


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
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal error", "error": repr(exc)},
    )


# ============================================================
# Models
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
                return mv(p)  # type: ignore[attr-defined]
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


class EventCreate(BaseModel):
    event_type: str
    source: Optional[str] = "api"
    payload: Optional[Dict[str, Any]] = None
    command_capability: Optional[str] = None
    command_input: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None
    workspace_id: Optional[str] = "production"


# ============================================================
# Utils
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_airtable() -> None:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise HTTPException(
            status_code=500,
            detail="Airtable env not configured (AIRTABLE_API_KEY / AIRTABLE_BASE_ID).",
        )


def _airtable_url(table_name: str) -> str:
    return f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{quote(table_name)}"


def _airtable_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }


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


def airtable_get_record(table_name: str, record_id: str) -> Dict[str, Any]:
    _require_airtable()
    r = _HTTP_SESSION.get(
        f"{_airtable_url(table_name)}/{record_id}",
        headers=_airtable_headers(),
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    if r.status_code >= 300:
        raise HTTPException(status_code=500, detail=f"Airtable get failed: {r.status_code} {r.text}")
    return r.json()


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
    params: Dict[str, Any] = {
        "filterByFormula": formula,
        "maxRecords": str(max_records),
    }

    if view_name:
        params["view"] = view_name

    if sort:
        for i, s in enumerate(sort):
            field = (s.get("field") or "").strip()
            direction = (s.get("direction") or "asc").strip()
            if field:
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
        parsed = json.loads(s)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _parse_float(val: Any) -> Optional[float]:
    if val is None:
        return None
    try:
        if isinstance(val, (int, float)):
            return float(val)
        return float(str(val).strip().replace(",", "."))
    except Exception:
        return None


def _is_truthy(v: Any) -> bool:
    if v is True:
        return True
    if v is None:
        return False
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def _safe_limit(raw_limit: int, default: int, minimum: int = 1, maximum: int = 200) -> int:
    try:
        value = int(raw_limit)
    except Exception:
        value = default
    if value < minimum:
        return default
    if value > maximum:
        return maximum
    return value


def _safe_records_from_view(table_name: str, view_name: str, limit: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        return [], {"ok": False, "reason": "airtable_env_missing", "table": table_name, "view": view_name}
    try:
        records = airtable_list_view(table_name, view_name, max_records=limit)
        return records, {"ok": True, "table": table_name, "view": view_name}
    except HTTPException as e:
        return [], {"ok": False, "reason": "airtable_read_failed", "detail": str(e.detail), "table": table_name, "view": view_name}
    except Exception as e:
        return [], {"ok": False, "reason": "exception", "detail": repr(e), "table": table_name, "view": view_name}


def _read_command_status(fields: Dict[str, Any]) -> str:
    return str(fields.get("Status_select", fields.get("Status", "")) or "").strip()


def _compose_command_input(fields: Dict[str, Any]) -> Dict[str, Any]:
    base = _json_load_maybe(fields.get("Input_JSON"))
    if not isinstance(base, dict):
        base = {}

    for direct_key in ("url", "http_target", "URL", "method", "headers", "body", "timeout"):
        if direct_key in fields and fields.get(direct_key) is not None and direct_key not in base:
            base[direct_key] = fields.get(direct_key)

    return base

def _resolve_workspace_id(
    req: Optional[RunRequest] = None,
    fields: Optional[Dict[str, Any]] = None,
    fallback: str = "production",
) -> str:
    req_input = {}
    if req and isinstance(getattr(req, "input", None), dict):
        req_input = req.input or {}

    fields = fields or {}

    workspace_id = (
        str(req_input.get("workspace_id") or "").strip()
        or str(fields.get("Workspace_ID") or "").strip()
        or fallback
    )
    return workspace_id
    
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
    if not SCHEDULER_SECRET and not RUN_SHARED_SECRET:
        return

    if _verify_scheduler_secret(headers):
        return

    if _verify_hmac_signature(raw_body, headers.get("x-run-signature")):
        return

    raise HTTPException(status_code=401, detail="Unauthorized (missing/invalid scheduler secret or run signature)")


# ============================================================
# Idempotency
# ============================================================

def _at_escape(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace("'", "\\'").strip()


def find_done_command_by_idem(idem_key: str, exclude_record_id: str) -> Optional[Dict[str, Any]]:
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
    try:
        idem = _at_escape(idem_key)
        if not idem:
            return None
        return airtable_find_first(COMMANDS_TABLE_NAME, formula=f"{{Idempotency_Key}}='{idem}'", max_records=1)
    except Exception:
        return None


# ============================================================
# Best-effort Airtable helpers
# ============================================================

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
        except Exception as e:
            last_err = repr(e)
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
        except Exception as e:
            last_err = repr(e)
    return {"ok": False, "error": last_err or "create_failed"}


# ============================================================
# System runs
# ============================================================

def create_system_run(req: RunRequest) -> Tuple[str, str]:
    run_uuid = str(uuid.uuid4())
    workspace_id = _resolve_workspace_id(req=req)

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
        "Workspace_ID": workspace_id,
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
    formula = (
        f"AND({{Idempotency_Key}}='{req.idempotency_key}',"
        "OR({Status_select}='Done',{Status_select}='Error'))"
    )
    try:
        return airtable_find_first(SYSTEM_RUNS_TABLE_NAME, formula=formula, max_records=1)
    except HTTPException as e:
        if "INVALID_FILTER_BY_FORMULA" in str(e.detail):
            return None
        raise


def cleanup_stale_runs() -> Dict[str, Any]:
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
        r = _HTTP_SESSION.get(
            _airtable_url(SYSTEM_RUNS_TABLE_NAME),
            headers=_airtable_headers(),
            params={"filterByFormula": formula, "maxRecords": "10"},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        if r.status_code >= 300:
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
# State helpers
# ============================================================

def state_get_record(app_key: str) -> Optional[Dict[str, Any]]:
    return airtable_find_first(STATE_TABLE_NAME, formula=f"{{App_Key}}='{app_key}'", max_records=1)

def state_put(app_key: str, value_obj: Dict[str, Any], workspace_id: str = "production") -> Dict[str, Any]:
    existing = airtable_find_first(
        STATE_TABLE_NAME,
        formula=f"AND({{App_Key}}='{app_key}',{{Workspace_ID}}='{workspace_id}')",
        max_records=1,
    )

    fields = {
        "App_Key": app_key,
        "Value_JSON": json.dumps(value_obj, ensure_ascii=False),
        "Updated_At": utc_now_iso(),
        "App_Version": APP_VERSION,
        "Workspace_ID": workspace_id,
    }

    if existing:
        airtable_update(STATE_TABLE_NAME, existing["id"], fields)
        return {
            "ok": True,
            "mode": "update",
            "record_id": existing["id"],
            "workspace_id": workspace_id,
        }

    rid = airtable_create(STATE_TABLE_NAME, fields)
    return {
        "ok": True,
        "mode": "create",
        "record_id": rid,
        "workspace_id": workspace_id,
    }

def capability_state_get(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    key = str((req.input or {}).get("app_key") or "").strip()
    workspace_id = _resolve_workspace_id(req=req)

    if not key:
        raise HTTPException(status_code=400, detail="state_get missing app_key")

    rec = airtable_find_first(
        STATE_TABLE_NAME,
        formula=f"AND({{App_Key}}='{key}',{{Workspace_ID}}='{workspace_id}')",
        max_records=1,
    )

    if not rec:
        return {
            "ok": True,
            "found": False,
            "app_key": key,
            "workspace_id": workspace_id,
            "run_record_id": run_record_id,
        }

    fields = rec.get("fields", {}) or {}
    return {
        "ok": True,
        "found": True,
        "app_key": key,
        "workspace_id": workspace_id,
        "record_id": rec.get("id"),
        "value": _json_load_maybe(fields.get("Value_JSON")),
        "run_record_id": run_record_id,
    }


def capability_state_put(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = req.input or {}
    app_key = str(payload.get("app_key") or "").strip()
    value = payload.get("value") or {}
    workspace_id = _resolve_workspace_id(req=req)

    if not app_key:
        raise HTTPException(status_code=400, detail="state_put missing app_key")
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="state_put value must be an object")

    res = state_put(app_key, value, workspace_id=workspace_id)
    res["run_record_id"] = run_record_id
    return res

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


def capability_lock_acquire(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = req.input or {}
    lock_key = str(payload.get("lock_key") or "").strip()
    holder = str(payload.get("holder") or req.worker).strip()
    if not lock_key:
        raise HTTPException(status_code=400, detail="lock_acquire missing lock_key")
    res = lock_acquire(lock_key, holder)
    res["run_record_id"] = run_record_id
    return res


def capability_lock_release(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = req.input or {}
    lock_key = str(payload.get("lock_key") or "").strip()
    holder = str(payload.get("holder") or req.worker).strip()
    if not lock_key:
        raise HTTPException(status_code=400, detail="lock_release missing lock_key")
    res = lock_release(lock_key, holder)
    res["run_record_id"] = run_record_id
    return res


# ============================================================
# Command queue helpers
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


def _extract_http_status_from_result(result_obj: Dict[str, Any]) -> Optional[int]:
    if not isinstance(result_obj, dict):
        return None

    for key in ("status_code", "http_status", "status"):
        value = result_obj.get(key)
        try:
            if value is not None:
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
                if value is not None:
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
            },
        ],
    )


def _command_mark_done_best_effort(command_id: str, run_record_id: str, result_obj: Dict[str, Any]) -> Dict[str, Any]:
    now = utc_now_iso()
    result_json = json.dumps(result_obj, ensure_ascii=False)
    http_status = _extract_http_status_from_result(result_obj)

    return _airtable_update_best_effort(
        COMMANDS_TABLE_NAME,
        command_id,
        [
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
                "Linked_Run": [run_record_id],
            },
            {
                "Status_select": "Done",
            },
        ],
    )


def _command_mark_blocked_duplicate_best_effort(command_id: str, run_record_id: str, note: Dict[str, Any]) -> Dict[str, Any]:
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
                "Linked_Run": [run_record_id],
                "Is_Locked": False,
                "Lock_Expires_At": None,
                "Lock_Token": "",
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


def _command_mark_unsupported_best_effort(command_id: str, run_record_id: str, message: str) -> Dict[str, Any]:
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
                "Linked_Run": [run_record_id],
            },
            {
                "Status_select": "Unsupported",
            },
        ],
    )


def _command_mark_retry_or_dead_best_effort(command_id: str, run_record_id: str, fields: Dict[str, Any], message: str) -> Dict[str, Any]:
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
                    "Linked_Run": [run_record_id],
                },
                {
                    "Status_select": "Retry",
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
                "Linked_Run": [run_record_id],
            },
            {
                "Status_select": "Error",
                "Linked_Run": [run_record_id],
            },
        ],
    )


def capability_retry_queue(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
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
        recs = airtable_list_view(COMMANDS_TABLE_NAME, (req.view or COMMANDS_VIEW_NAME or "Queue").strip(), max_records=limit)
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

    return {
        "ok": True,
        "mode": mode,
        "scanned": len(recs),
        "promoted": promoted,
        "failed": failed,
        "errors": errors[:10],
    }


def capability_lock_recovery(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
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

        if status == "Running" and fields.get("Is_Locked") is not True:
            skipped += 1
            continue

        res = _airtable_update_best_effort(
            COMMANDS_TABLE_NAME,
            cid,
            [
                {
                    "Status_select": "Retry",
                    "Next_Retry_At": now,
                    "Is_Locked": False,
                    "Lock_Expires_At": None,
                    "Lock_Token": "",
                    "Last_Heartbeat_At": now,
                    "Linked_Run": [run_record_id],
                },
                {
                    "Status_select": "Retry",
                    "Linked_Run": [run_record_id],
                },
                {
                    "Status_select": "Retry",
                },
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


def _resolve_http_exec_url_from_command_input(cmd_input: Dict[str, Any]) -> str:
    if not isinstance(cmd_input, dict):
        return ""
    for key in ("url", "http_target", "URL"):
        value = str(cmd_input.get(key, "") or "").strip()
        if value:
            return value
    return ""


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
            sort=[{"field": "Priority", "direction": "desc"}],
            max_records=max_cmds,
        )
        selection_mode = "scheduler"
        view = f"scheduler_formula+view:{view_name}"
    except Exception:
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
            _command_mark_retry_or_dead_best_effort(cid, run_record_id, fields, "Missing Capability")
            _release_command_lock_best_effort(cid)
            continue

        fn = CAPABILITIES.get(capability)
        if not fn:
            unsupported += 1
            _command_mark_unsupported_best_effort(cid, run_record_id, f"Unsupported capability: {capability}")
            _release_command_lock_best_effort(cid)
            continue

        if POLICY_APPROVAL_REQUIRED_FOR_WRITE and capability in ("http_exec", "state_put"):
            approved = fields.get("Approved")
            if not _is_truthy(approved):
                blocked += 1
                _airtable_update_best_effort(
                    COMMANDS_TABLE_NAME,
                    cid,
                    [
                        {
                            "Status_select": "Blocked",
                            "Finished_At": utc_now_iso(),
                            "Error_Message": "Approval required by policy",
                            "Linked_Run": [run_record_id],
                            "Is_Locked": False,
                            "Lock_Expires_At": None,
                            "Lock_Token": "",
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
            _command_mark_blocked_duplicate_best_effort(
                cid,
                run_record_id,
                {
                    "ok": True,
                    "skipped": True,
                    "reason": "idempotent_duplicate_done_exists",
                    "idempotency_key": idem,
                    "matched_done_record_id": dup_done.get("id"),
                },
            )
            _release_command_lock_best_effort(cid)
            blocked += 1
            continue

        lock_res = _command_mark_running_best_effort(cid, run_record_id, req.worker, idem)
        if not lock_res.get("ok"):
            blocked += 1
            errors.append(f"{cid}: failed_to_mark_running:{lock_res.get('error')}")
            continue

        if capability == "http_exec":
            resolved_url = _resolve_http_exec_url_from_command_input(cmd_input)
            if not resolved_url:
                msg = "HTTP_EXEC missing url (Input_JSON.url / http_target / URL)"
                failed += 1
                _command_mark_retry_or_dead_best_effort(cid, run_record_id, fields, msg)
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

            _command_mark_done_best_effort(cid, run_record_id, result_obj)
            succeeded += 1

        except HTTPException as e:
            msg = str(e.detail)
            failed += 1
            _command_mark_retry_or_dead_best_effort(cid, run_record_id, fields, msg)
            _release_command_lock_best_effort(cid)
            errors.append(f"{cid}: {msg}")

        except Exception as e:
            msg = repr(e)
            failed += 1
            _command_mark_retry_or_dead_best_effort(cid, run_record_id, fields, msg)
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
        post_ops["event_engine"] = {
            "ok": False,
            "error": "event_engine temporarily disabled in worker bootstrap",
        }

    if post_ops:
        result["post_ops"] = post_ops

    return result

def capability_escalation_engine(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return capability_escalation_dispatch(
        req,
        run_record_id,
        airtable_list_filtered=airtable_list_filtered,
        airtable_list_view=airtable_list_view,
        airtable_create=airtable_create,
        airtable_update=airtable_update,
        http_timeout_seconds=HTTP_TIMEOUT_SECONDS,
        logs_errors_table_name=LOGS_ERRORS_TABLE_NAME,
        logs_errors_view_name=LOGS_ERRORS_VIEW_NAME,
        commands_table_name=COMMANDS_TABLE_NAME,
    )

# ============================================================
# Event Engine minimal V1
# ============================================================

def _event_status(fields: Dict[str, Any]) -> str:
    return str(fields.get("Status_select", fields.get("Status", "")) or "").strip()


def _build_command_fields_candidates(
    *,
    capability: str,
    command_input: Dict[str, Any],
    workspace_id: str,
    event_record_id: str,
    idempotency_key: Optional[str] = None,
    priority: int = 1,
) -> List[Dict[str, Any]]:
    idem = str(idempotency_key or f"evt:{event_record_id}:{capability}").strip()

    input_json = json.dumps(command_input or {}, ensure_ascii=False)

    candidates: List[Dict[str, Any]] = [
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Priority": priority,
            "Input_JSON": input_json,
            "Idempotency_Key": idem,
            "Workspace_ID": workspace_id,
            "Source_Event": [event_record_id],
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Priority": priority,
            "Input_JSON": input_json,
            "Idempotency_Key": idem,
            "Workspace_ID": workspace_id,
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Priority": priority,
            "Input_JSON": input_json,
            "Idempotency_Key": idem,
        },
    ]

    return candidates

def _create_command_from_event(event_record: Dict[str, Any]) -> Dict[str, Any]:
    fields = event_record.get("fields", {}) or {}
    event_record_id = str(event_record.get("id") or "").strip()

    if not event_record_id:
        return {"ok": False, "error": "missing_event_record_id"}

    mapped_capability_raw = fields.get("Mapped_Capability")

    if isinstance(mapped_capability_raw, dict):
        mapped_capability = str(mapped_capability_raw.get("name") or "").strip()
    elif isinstance(mapped_capability_raw, list) and mapped_capability_raw:
        first_item = mapped_capability_raw[0]
        if isinstance(first_item, dict):
            mapped_capability = str(first_item.get("name") or "").strip()
        else:
            mapped_capability = str(first_item or "").strip()
    else:
        mapped_capability = str(mapped_capability_raw or "").strip()

    if not mapped_capability:
        return {"ok": False, "error": "missing_mapped_capability"}

    if mapped_capability not in CAPABILITIES:
        return {
            "ok": False,
            "error": f"unsupported_mapped_capability:{mapped_capability}",
        }

    workspace_id = str(fields.get("Workspace_ID") or "production").strip() or "production"
    idempotency_key = str(fields.get("Idempotency_Key") or "").strip()

    command_input = _json_load_maybe(fields.get("Command_Input_JSON"))
    if not isinstance(command_input, dict):
        command_input = {}

    http_target = str(
        fields.get("http_target")
        or fields.get("URL")
        or fields.get("Http_Target")
        or ""
    ).strip()
    if http_target and "url" not in command_input:
        command_input["url"] = http_target
    if http_target and "http_target" not in command_input:
        command_input["http_target"] = http_target

    http_method = str(
        fields.get("HTTP_Method")
        or fields.get("Http_Method")
        or fields.get("method")
        or ""
    ).strip()
    if http_method and "method" not in command_input:
        command_input["method"] = http_method

    existing = None
    if idempotency_key:
        existing = find_command_by_idem(idempotency_key)

    if existing:
        existing_id = str(existing.get("id") or "").strip()

        _airtable_update_best_effort(
            EVENTS_TABLE_NAME,
            event_record_id,
            [
                {
                    "Linked_Command": [existing_id],
                    "Command_ID": existing_id,
                    "Status_select": "Queued",
                    "Command_Created": True,
                    "Processed_At": utc_now_iso(),
                },
                {
                    "Linked_Command": [existing_id],
                    "Status_select": "Queued",
                    "Command_Created": True,
                    "Processed_At": utc_now_iso(),
                },
                {
                    "Command_ID": existing_id,
                    "Status_select": "Queued",
                    "Command_Created": True,
                    "Processed_At": utc_now_iso(),
                },
                {
                    "Status_select": "Queued",
                    "Command_Created": True,
                    "Processed_At": utc_now_iso(),
                },
            ],
        )

        return {
            "ok": True,
            "mode": "existing_command",
            "event_id": event_record_id,
            "command_record_id": existing_id,
            "capability": mapped_capability,
            "workspace_id": workspace_id,
        }

    candidates = _build_command_fields_candidates(
        capability=mapped_capability,
        command_input=command_input,
        workspace_id=workspace_id,
        event_record_id=event_record_id,
        idempotency_key=idempotency_key or f"evt:{event_record_id}:{mapped_capability}",
        priority=1,
    )

    create_res = _airtable_create_best_effort(COMMANDS_TABLE_NAME, candidates)
    if not create_res.get("ok"):
        return {
            "ok": False,
            "error": f"command_create_failed:{create_res.get('error')}",
            "event_id": event_record_id,
        }

    command_record_id = str(create_res.get("record_id") or "").strip()

    _airtable_update_best_effort(
        EVENTS_TABLE_NAME,
        event_record_id,
        [
            {
                "Linked_Command": [command_record_id],
                "Command_ID": command_record_id,
                "Status_select": "Queued",
                "Command_Created": True,
                "Processed_At": utc_now_iso(),
            },
            {
                "Linked_Command": [command_record_id],
                "Status_select": "Queued",
                "Command_Created": True,
                "Processed_At": utc_now_iso(),
            },
            {
                "Command_ID": command_record_id,
                "Status_select": "Queued",
                "Command_Created": True,
                "Processed_At": utc_now_iso(),
            },
            {
                "Status_select": "Queued",
                "Command_Created": True,
                "Processed_At": utc_now_iso(),
            },
        ],
    )

    return {
        "ok": True,
        "mode": "created_command",
        "event_id": event_record_id,
        "command_record_id": command_record_id,
        "capability": mapped_capability,
        "workspace_id": workspace_id,
    }
# ============================================================
# Capabilities registry
# ============================================================

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
    "command_orchestrator": capability_command_orchestrator,
}


# ============================================================
# Root / health
# ============================================================

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
# Read-only endpoints
# ============================================================

@app.get("/runs")
def get_runs(limit: int = 20) -> Dict[str, Any]:
    limit = _safe_limit(limit, default=20, minimum=1, maximum=100)
    records, meta = _safe_records_from_view(SYSTEM_RUNS_TABLE_NAME, SYSTEM_RUNS_VIEW_NAME, limit)

    runs: List[Dict[str, Any]] = []
    stats = {"running": 0, "done": 0, "error": 0, "unsupported": 0, "other": 0}

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

        if key in ("queued", "queue"):
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
    records, meta = _safe_records_from_view(EVENTS_TABLE_NAME, EVENTS_DASHBOARD_VIEW_NAME, limit)

    events: List[Dict[str, Any]] = []
    stats = {"new": 0, "queued": 0, "processed": 0, "ignored": 0, "error": 0, "other": 0}

    for r in records:
        f = r.get("fields", {}) or {}
        status = str(f.get("Status_select", f.get("Status", "")) or "").strip()
        key = status.lower()

        if key == "new":
            stats["new"] += 1
        elif key == "queued":
            stats["queued"] += 1
        elif key == "processed":
            stats["processed"] += 1
        elif key == "ignored":
            stats["ignored"] += 1
        elif key == "error":
            stats["error"] += 1
        else:
            stats["other"] += 1

        payload = _json_load_maybe(f.get("Payload_JSON"))

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

# ============================================================
# Webhook Monitor
# ============================================================

class WebhookIn(BaseModel):
    source: Optional[str] = "generic"
    event_type: Optional[str] = "webhook_received"
    workspace_id: Optional[str] = "production"
    target_capability: Optional[str] = None
    command_input: Optional[Dict[str, Any]] = None
    payload: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None


def _build_webhook_event_fields(
    source: str,
    event_type: str,
    workspace_id: str,
    payload: Dict[str, Any],
    target_capability: Optional[str] = None,
    command_input: Optional[Dict[str, Any]] = None,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    fields: Dict[str, Any] = {
        "Event_Type": event_type,
        "Source": source,
        "Workspace_ID": workspace_id,
        "Payload_JSON": json.dumps(payload or {}, ensure_ascii=False),
        "Status_select": "New",
        "Status": "New",
        "Command_Created": False,
    }

    if target_capability:
        fields["Mapped_Capability"] = target_capability

    if command_input is not None:
        fields["Command_Input_JSON"] = json.dumps(command_input, ensure_ascii=False)

    if idempotency_key:
        fields["Idempotency_Key"] = idempotency_key

    return fields
    
# ============================================================
# Event endpoints
# ============================================================
@app.post("/webhook")
async def webhook_receiver(request: Request) -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise HTTPException(status_code=500, detail="airtable not configured")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object.")

    source = str(payload.get("source") or request.headers.get("x-webhook-source") or "generic").strip() or "generic"
    event_type = str(payload.get("event_type") or request.headers.get("x-webhook-event") or "webhook_received").strip() or "webhook_received"
    workspace_id = str(payload.get("workspace_id") or request.headers.get("x-workspace-id") or "production").strip() or "production"

    target_capability = payload.get("target_capability")
    if target_capability is not None:
        target_capability = str(target_capability).strip() or None

    command_input = payload.get("command_input")
    if command_input is not None and not isinstance(command_input, dict):
        raise HTTPException(status_code=400, detail="command_input must be an object when provided")

    idempotency_key = payload.get("idempotency_key")
    if idempotency_key is not None:
        idempotency_key = str(idempotency_key).strip() or None

    event_fields = _build_webhook_event_fields(
        source=source,
        event_type=event_type,
        workspace_id=workspace_id,
        payload=payload,
        target_capability=target_capability,
        command_input=command_input,
        idempotency_key=idempotency_key,
    )

    event_id = airtable_create(EVENTS_TABLE_NAME, event_fields)

    return {
        "ok": True,
        "event_id": event_id,
        "event_type": event_type,
        "source": source,
        "workspace_id": workspace_id,
        "ts": utc_now_iso(),
    }


@app.post("/webhook/failure")
async def webhook_failure_receiver(request: Request) -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise HTTPException(status_code=500, detail="airtable not configured")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object.")

    source = str(payload.get("source") or request.headers.get("x-webhook-source") or "generic").strip() or "generic"
    workspace_id = str(payload.get("workspace_id") or request.headers.get("x-workspace-id") or "production").strip() or "production"

    retry_url = str(
        payload.get("retry_url")
        or payload.get("url")
        or payload.get("http_target")
        or ""
    ).strip()

    retry_method = str(payload.get("method") or "POST").strip().upper() or "POST"

    command_input: Dict[str, Any] = {}
    if retry_url:
        command_input["url"] = retry_url
        command_input["http_target"] = retry_url
        command_input["method"] = retry_method

    event_fields = _build_webhook_event_fields(
        source=source,
        event_type="webhook_failed",
        workspace_id=workspace_id,
        payload=payload,
        target_capability="http_exec" if retry_url else None,
        command_input=command_input if retry_url else None,
        idempotency_key=str(payload.get("idempotency_key") or "").strip() or None,
    )

    event_id = airtable_create(EVENTS_TABLE_NAME, event_fields)

    return {
        "ok": True,
        "event_id": event_id,
        "event_type": "webhook_failed",
        "source": source,
        "workspace_id": workspace_id,
        "retry_ready": bool(retry_url),
        "ts": utc_now_iso(),
    }

@app.post("/events")
def create_event(evt: EventCreate) -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise HTTPException(status_code=500, detail="airtable not configured")

    payload_json = evt.payload or {}
    command_input_json = evt.command_input or {}
    workspace_id = str(evt.workspace_id or "production").strip() or "production"

    fields = {
        "Event_Type": evt.event_type,
        "Status_select": "New",
        "Status": "New",
        "Source": evt.source,
        "Workspace_ID": workspace_id,
        "Payload_JSON": json.dumps(payload_json, ensure_ascii=False),
        "Mapped_Capability": evt.command_capability,
        "Command_Input_JSON": json.dumps(command_input_json, ensure_ascii=False),
        "Idempotency_Key": evt.idempotency_key,
        "Command_Created": False,
    }

    event_id = airtable_create(EVENTS_TABLE_NAME, fields)

    return {
        "ok": True,
        "event_id": event_id,
        "status": "New",
        "workspace_id": workspace_id,
        "ts": utc_now_iso(),
    }

@app.post("/events/process")
def process_events(limit: int = 50) -> Dict[str, Any]:
    limit = _safe_limit(limit, default=10, minimum=1, maximum=100)

    records, meta = _safe_records_from_view(
        EVENTS_TABLE_NAME,
        EVENTS_VIEW_NAME or "Queue",
        limit,
    )

    scanned = 0
    created = 0
    failed = 0
    skipped = 0
    processed_ids: List[str] = []
    errors: List[str] = []

    for event_record in records:
        event_id = str(event_record.get("id") or "").strip()
        fields = event_record.get("fields", {}) or {}
        status = _event_status(fields).lower()

        if status not in ("new", "queued"):
            skipped += 1
            continue

        scanned += 1
        processed_ids.append(event_id)

        res = _create_command_from_event(event_record)

        if res.get("ok"):
            created += 1
        else:
            failed += 1
            errors.append(f"{event_id}: {res.get('error')}")
            _airtable_update_best_effort(
                EVENTS_TABLE_NAME,
                event_id,
                [
                    {
                        "Status_select": "Error",
                        "Status": "Error",
                        "Processed_At": utc_now_iso(),
                    },
                    {
                        "Status_select": "Error",
                        "Processed_At": utc_now_iso(),
                    },
                    {
                        "Status": "Error",
                        "Processed_At": utc_now_iso(),
                    },
                    {
                        "Status_select": "Error",
                    },
                    {
                        "Status": "Error",
                    },
                ],
            )

    return {
        "ok": True,
        "source": meta,
        "scanned": scanned,
        "created": created,
        "failed": failed,
        "skipped": skipped,
        "event_record_ids": processed_ids,
        "errors": errors[:10],
        "ts": utc_now_iso(),
    }
# ============================================================
# Run endpoint
# ============================================================

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


# ============================================================
# Incidents / graphs / details
# ============================================================

@app.get("/incidents")
def get_incidents():
    try:
        if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
            return {
                "ok": True,
                "source": {"ok": False, "reason": "missing_airtable_env"},
                "count": 0,
                "stats": {"open": 0, "critical": 0, "warning": 0, "resolved": 0, "other": 0},
                "incidents": [],
                "ts": datetime.now(timezone.utc).isoformat(),
            }

        response = requests.get(
            _airtable_url(LOGS_ERRORS_TABLE_NAME),
            headers={"Authorization": f"Bearer {AIRTABLE_API_KEY}", "Accept": "application/json"},
            params={"view": LOGS_ERRORS_VIEW_NAME or "Active", "maxRecords": 50},
            timeout=20,
        )
        response.raise_for_status()

        payload = response.json()
        records = payload.get("records", [])
        incidents = []
        stats = {"open": 0, "critical": 0, "warning": 0, "resolved": 0, "other": 0}

        for r in records:
            f = r.get("fields", {}) or {}
            status = str(f.get("Statut incident") or "").strip()
            severity = str(f.get("Urgence IA") or "").strip()

            incidents.append(
                {
                    "id": r.get("id"),
                    "title": f.get("Error_Message") or "Untitled incident",
                    "status": status,
                    "severity": severity,
                    "sla_status": f.get("SLA_Status"),
                    "created_at": f.get("Created time"),
                    "source": "Logs_Erreurs",
                    "worker": f.get("Worker"),
                }
            )

            normalized_status = status.lower()
            normalized_severity = severity.lower()

            if normalized_status in ("open", "opened", "new", "en cours"):
                stats["open"] += 1
            elif normalized_status in ("resolved", "closed", "done", "résolu"):
                stats["resolved"] += 1
            elif normalized_severity in ("critical", "critique", "high"):
                stats["critical"] += 1
            elif normalized_severity in ("warning", "warn", "medium", "surveillance"):
                stats["warning"] += 1
            else:
                stats["other"] += 1

        return {
            "ok": True,
            "source": {"ok": True, "table": LOGS_ERRORS_TABLE_NAME, "view": LOGS_ERRORS_VIEW_NAME or "Active"},
            "count": len(incidents),
            "stats": stats,
            "incidents": incidents,
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    except requests.HTTPError as exc:
        detail = exc.response.text if getattr(exc, "response", None) is not None else str(exc)
        raise HTTPException(status_code=502, detail=f"Airtable incidents request failed: {detail}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"detail": "Internal error", "error": repr(exc)})


@app.get("/commands/{record_id}")
def get_command_detail(record_id: str) -> Dict[str, Any]:
    try:
        rec = airtable_get_record(COMMANDS_TABLE_NAME, record_id)
        f = rec.get("fields", {}) or {}
        return {
            "ok": True,
            "command": {
                "id": rec.get("id"),
                "capability": f.get("Capability"),
                "status": _read_command_status(f),
                "priority": f.get("Priority"),
                "retry_count": f.get("Retry_Count"),
                "retry_max": f.get("Retry_Max"),
                "scheduled_at": f.get("Scheduled_At"),
                "next_retry_at": f.get("Next_Retry_At"),
                "is_locked": f.get("Is_Locked"),
                "locked_by": f.get("Locked_By"),
                "idempotency_key": f.get("Idempotency_Key"),
                "linked_run": f.get("Linked_Run"),
                "input_json": f.get("Input_JSON"),
                "result_json": f.get("Result_JSON"),
                "error_message": f.get("Error_Message"),
                "last_error": f.get("Last_Error"),
                "started_at": f.get("Started_At"),
                "finished_at": f.get("Finished_At"),
            },
            "ts": utc_now_iso(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"command_detail_failed: {repr(e)}")


@app.get("/runs/{record_id}")
def get_run_detail(record_id: str) -> Dict[str, Any]:
    try:
        rec = airtable_get_record(SYSTEM_RUNS_TABLE_NAME, record_id)
        f = rec.get("fields", {}) or {}
        return {
            "ok": True,
            "run": {
                "id": rec.get("id"),
                "run_id": f.get("Run_ID"),
                "worker": f.get("Worker"),
                "capability": f.get("Capability"),
                "status": f.get("Status_select"),
                "priority": f.get("Priority"),
                "dry_run": f.get("Dry_Run"),
                "started_at": f.get("Started_At"),
                "finished_at": f.get("Finished_At"),
                "idempotency_key": f.get("Idempotency_Key"),
                "input_json": f.get("Input_JSON"),
                "result_json": f.get("Result_JSON"),
                "app_name": f.get("App_Name"),
                "app_version": f.get("App_Version"),
            },
            "ts": utc_now_iso(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"run_detail_failed: {repr(e)}")
