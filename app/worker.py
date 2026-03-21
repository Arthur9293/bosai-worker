# app/worker.py — BOSAI Worker rebuilt
import hashlib
import hmac
import json
import os
import threading
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
from app.policies import get_policies
from app.capabilities.internal_escalate import capability_internal_escalate


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
APP_VERSION = os.getenv("APP_VERSION", "2.6.0-internal-scheduler-clean").strip()

RUN_MAX_SECONDS = float((os.getenv("RUN_MAX_SECONDS", "30") or "30").strip())
HTTP_TIMEOUT_SECONDS = float((os.getenv("HTTP_TIMEOUT_SECONDS", "20") or "20").strip())
RUN_LOCK_TTL_SECONDS = int((os.getenv("RUN_LOCK_TTL_SECONDS", "600") or "600").strip())
COMMAND_LOCK_TTL_MIN = int((os.getenv("COMMAND_LOCK_TTL_MIN", "10") or "10").strip())
CHAIN_MAX_DEPTH = int((os.getenv("CHAIN_MAX_DEPTH", "5") or "5").strip())

FLOWS_TABLE_NAME = os.getenv("FLOWS_TABLE_NAME", "Flows").strip()
RUN_SHARED_SECRET = os.getenv("RUN_SHARED_SECRET", "").strip()
SCHEDULER_SECRET = os.getenv("SCHEDULER_SECRET", "").strip()
INTERNAL_SCHEDULER_ENABLED = (
    os.getenv("INTERNAL_SCHEDULER_ENABLED", "1").strip().lower()
    in ("1", "true", "yes", "on")
)

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

SCHEDULER_LAST_TICK_AT: Optional[str] = None
SCHEDULER_LAST_EVENT_RESULT: Dict[str, Any] = {}
SCHEDULER_LAST_COMMAND_RESULT: Dict[str, Any] = {}
SCHEDULER_LAST_ERROR: Optional[str] = None


def bosai_scheduler_loop() -> None:
    global SCHEDULER_LAST_TICK_AT
    global SCHEDULER_LAST_EVENT_RESULT
    global SCHEDULER_LAST_COMMAND_RESULT
    global SCHEDULER_LAST_ERROR

    while True:
        try:
            SCHEDULER_LAST_TICK_AT = utc_now_iso()
            SCHEDULER_LAST_ERROR = None
            print(f"[scheduler] tick at {SCHEDULER_LAST_TICK_AT}")

            evt_run_record_id: Optional[str] = None
            cmd_run_record_id: Optional[str] = None

            # 1) Event engine
            try:
                evt_payload = {
                    "worker": WORKER_NAME,
                    "capability": "event_engine",
                    "idempotency_key": f"scheduler-events-{int(time.time())}",
                    "input": {},
                }
                req_evt = RunRequest.from_payload(evt_payload)
                evt_run_record_id, _ = create_system_run(req_evt)

                evt_result = process_events(limit=20)
                SCHEDULER_LAST_EVENT_RESULT = (
                    evt_result if isinstance(evt_result, dict) else {"raw": str(evt_result)}
                )

                if isinstance(evt_result, dict) and "run_record_id" not in evt_result:
                    evt_result["run_record_id"] = evt_run_record_id

                finish_system_run(evt_run_record_id, "Done", evt_result)
                print(f"[scheduler] event_engine result={evt_result}")

            except Exception as e:
                SCHEDULER_LAST_ERROR = f"event_engine: {repr(e)}"
                if evt_run_record_id:
                    try:
                        fail_system_run(evt_run_record_id, repr(e))
                    except Exception:
                        pass
                print("scheduler event_engine error:", repr(e))

            # 2) Command orchestrator
            try:
                cmd_payload = {
                    "worker": WORKER_NAME,
                    "capability": "command_orchestrator",
                    "idempotency_key": f"scheduler-commands-{int(time.time())}",
                    "input": {
                        "run_retry_queue": True,
                        "run_lock_recovery": True,
                    },
                    "max_commands": 10,
                }
                req_cmd = RunRequest.from_payload(cmd_payload)
                cmd_run_record_id, _ = create_system_run(req_cmd)

                cmd_result = capability_command_orchestrator(req_cmd, cmd_run_record_id)
                SCHEDULER_LAST_COMMAND_RESULT = (
                    cmd_result if isinstance(cmd_result, dict) else {"raw": str(cmd_result)}
                )

                if isinstance(cmd_result, dict) and "run_record_id" not in cmd_result:
                    cmd_result["run_record_id"] = cmd_run_record_id

                finish_system_run(cmd_run_record_id, "Done", cmd_result)
                print(f"[scheduler] command_orchestrator result={cmd_result}")

            except Exception as e:
                SCHEDULER_LAST_ERROR = f"command_orchestrator: {repr(e)}"
                if cmd_run_record_id:
                    try:
                        fail_system_run(cmd_run_record_id, repr(e))
                    except Exception:
                        pass
                print("scheduler command_orchestrator error:", repr(e))

        except Exception as e:
            SCHEDULER_LAST_ERROR = f"scheduler_crash: {repr(e)}"
            print("scheduler crash:", repr(e))

        time.sleep(10)


@app.get("/health/scheduler")
def health_scheduler() -> Dict[str, Any]:
    return {
        "ok": True,
        "internal_scheduler_enabled": INTERNAL_SCHEDULER_ENABLED,
        "last_tick_at": SCHEDULER_LAST_TICK_AT,
        "last_event_result": SCHEDULER_LAST_EVENT_RESULT,
        "last_command_result": SCHEDULER_LAST_COMMAND_RESULT,
        "last_error": SCHEDULER_LAST_ERROR,
        "ts": utc_now_iso(),
    }
    
@app.on_event("startup")
def start_scheduler() -> None:
    if not INTERNAL_SCHEDULER_ENABLED:
        print("[startup] internal scheduler disabled")
        return

    thread = threading.Thread(
        target=bosai_scheduler_loop,
        daemon=True,
        name="bosai-internal-scheduler",
    )
    thread.start()
    print("[startup] internal scheduler enabled")
    
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    print("UNHANDLED_EXCEPTION:", repr(exc))
    print(tb)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal error",
            "error": repr(exc),
            "path": str(request.url.path),
        },
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

def _normalize_flow_keys(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    normalized = dict(payload)

    flow_id = str(
        normalized.get("flow_id")
        or normalized.get("flowid")
        or normalized.get("flowId")
        or normalized.get("Flow_ID")
        or normalized.get("FlowId")
        or ""
    ).strip()

    root_event_id = str(
        normalized.get("root_event_id")
        or normalized.get("rooteventid")
        or normalized.get("rootEventId")
        or normalized.get("root_eventid")
        or normalized.get("Root_Event_ID")
        or normalized.get("RootEventId")
        or ""
    ).strip()

    goal = str(
        normalized.get("goal")
        or normalized.get("Goal")
        or ""
    ).strip()

    raw_step_index = (
        normalized.get("step_index")
        or normalized.get("stepindex")
        or normalized.get("stepIndex")
        or normalized.get("Step_Index")
        or normalized.get("StepIndex")
    )

    step_index = 0
    try:
        if raw_step_index is not None and str(raw_step_index).strip() != "":
            step_index = int(raw_step_index)
    except Exception:
        step_index = 0

    if flow_id:
        normalized["flow_id"] = flow_id
        normalized["flowid"] = flow_id

    if root_event_id:
        normalized["root_event_id"] = root_event_id
        normalized["rooteventid"] = root_event_id

    if goal:
        normalized["goal"] = goal

    normalized["step_index"] = step_index
    normalized["stepindex"] = step_index

    return normalized

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
    base: Dict[str, Any] = {}
    parse_errors: List[Dict[str, Any]] = []

    for source_key in ("Input_JSON", "Command_JSON", "Command_Input_JSON"):
        raw_val = fields.get(source_key)

        if raw_val is None:
            continue

        parsed: Dict[str, Any] = {}

        if isinstance(raw_val, dict):
            parsed = raw_val
        else:
            raw_text = str(raw_val).strip()
            if not raw_text:
                continue

            try:
                obj = json.loads(raw_text)
                if isinstance(obj, dict):
                    parsed = obj
            except Exception as e:
                parse_errors.append(
                    {
                        "source": source_key,
                        "error": repr(e),
                        "raw_preview": raw_text[:500],
                    }
                )
                continue

        if not isinstance(parsed, dict) or not parsed:
            continue

        # IMPORTANT:
        # si le JSON est une enveloppe {"capability": "...", "input": {...}}
        # on extrait seulement le bloc input
        if isinstance(parsed.get("input"), dict) and parsed.get("input"):
            base = parsed.get("input") or {}
        else:
            base = parsed

        if isinstance(base, dict) and base:
            break

    if not isinstance(base, dict):
        base = {}

    field_alias_map = {
        "url": ("url", "URL", "http_target", "Http_Target"),
        "http_target": ("http_target", "Http_Target", "URL", "url"),
        "method": ("method", "HTTP_Method", "Http_Method"),
        "headers": ("headers", "HTTP_Headers_JSON"),
        "body": ("body", "HTTP_Payload_JSON"),
        "json": ("json", "JSON", "Payload_JSON"),
        "timeout": ("timeout",),
        "flow_id": ("flow_id", "flowid", "flowId", "Flow_ID"),
        "root_event_id": ("root_event_id", "rooteventid", "rootEventId", "Root_Event_ID"),
        "step_index": ("step_index", "stepindex", "stepIndex", "Step_Index"),
        "goal": ("goal", "Goal"),
        "retry_count": ("retry_count", "retrycount", "Retry_Count"),
        "retry_max": ("retry_max", "retrymax", "Retry_Max"),
        "failed_url": ("failed_url", "failedurl", "Failed_URL"),
        "failed_method": ("failed_method", "failedmethod", "Failed_Method"),
        "failed_goal": ("failed_goal", "failedgoal", "Failed_Goal"),
        "http_status": ("http_status", "httpstatus", "HTTP_Status"),
    }

    for target_key, aliases in field_alias_map.items():
        if target_key in base and base.get(target_key) not in (None, ""):
            continue

        for alias in aliases:
            value = fields.get(alias)
            if value is not None and str(value).strip() != "":
                base[target_key] = value
                break

    base = _normalize_flow_keys(base)

    if parse_errors:
        print(f"[compose_command_input] parse_errors={json.dumps(parse_errors, ensure_ascii=False)}")
    print(f"[compose_command_input] final_base={json.dumps(base, ensure_ascii=False)}")

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
            print("[AIRTABLE CREATE] table =", table_name)
            print("[AIRTABLE CREATE] trying fields =", fields)

            record_id = airtable_create(table_name, fields)

            return {
                "ok": True,
                "record_id": record_id,
                "applied_fields": list(fields.keys()),
            }

        except HTTPException as e:
            last_err = str(e.detail)
            print("[AIRTABLE CREATE] failed table =", table_name)
            print("[AIRTABLE CREATE] failed fields =", fields)
            print("[AIRTABLE CREATE] error =", str(e.detail))

        except Exception as e:
            last_err = repr(e)
            print("[AIRTABLE CREATE] failed table =", table_name)
            print("[AIRTABLE CREATE] failed fields =", fields)
            print("[AIRTABLE CREATE] error =", repr(e))

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

# ============================================================
# Flow helpers
# ============================================================

def _resolve_flow_ids(payload: Dict[str, Any]) -> Tuple[str, str]:
    if not isinstance(payload, dict):
        payload = {}

    flow_id = str(
        payload.get("flow_id")
        or payload.get("root_event_id")
        or payload.get("event_id")
        or ""
    ).strip()

    root_event_id = str(
        payload.get("root_event_id")
        or flow_id
        or ""
    ).strip()

    return flow_id, (root_event_id or flow_id)


def _resolve_flow_step_index(payload: Dict[str, Any], default: int = 0) -> int:
    try:
        return int(payload.get("step_index") or default)
    except Exception:
        return default


def _append_flow_step_safe(
    *,
    flow_id: str,
    workspace_id: str,
    step_obj: Dict[str, Any],
) -> None:
    try:
        flow_state_append_step(
            flow_id=flow_id,
            workspace_id=workspace_id,
            step_obj=step_obj,
        )
    except Exception:
        pass


def _update_flow_registry_safe(
    *,
    flow_id: str,
    workspace_id: str,
    status: Optional[str] = None,
    current_step: Optional[int] = None,
    last_decision: Optional[str] = None,
    memory_obj: Optional[Dict[str, Any]] = None,
    result_obj: Optional[Dict[str, Any]] = None,
    linked_run: Optional[List[str]] = None,
    finished: bool = False,
) -> None:
    try:
        flow_update(
            flow_id=flow_id,
            workspace_id=workspace_id,
            status=status,
            current_step=current_step,
            last_decision=last_decision,
            memory_obj=memory_obj,
            result_obj=result_obj,
            linked_run=linked_run,
            finished=finished,
        )
    except Exception:
        pass
        
# ============================================================
# Flow state helpers
# ============================================================

def _flow_state_key(flow_id: str) -> str:
    return f"flow:{flow_id}"


def flow_state_get(flow_id: str, workspace_id: str = "production") -> Dict[str, Any]:
    key = _flow_state_key(flow_id)

    rec = airtable_find_first(
        STATE_TABLE_NAME,
        formula=f"AND({{App_Key}}='{key}',{{Workspace_ID}}='{workspace_id}')",
        max_records=1,
    )

    if not rec:
        return {
            "ok": True,
            "found": False,
            "flow_id": flow_id,
            "workspace_id": workspace_id,
            "state": {
                "flow_id": flow_id,
                "root_event_id": flow_id,
                "latest_status": "new",
                "latest_decision": None,
                "steps": [],
            },
        }

    fields = rec.get("fields", {}) or {}
    value = _json_load_maybe(fields.get("Value_JSON"))

    if not isinstance(value, dict):
        value = {}

    value.setdefault("flow_id", flow_id)
    value.setdefault("root_event_id", flow_id)
    value.setdefault("latest_status", "running")
    value.setdefault("latest_decision", None)
    value.setdefault("steps", [])

    if not isinstance(value.get("steps"), list):
        value["steps"] = []

    return {
        "ok": True,
        "found": True,
        "flow_id": flow_id,
        "workspace_id": workspace_id,
        "record_id": rec.get("id"),
        "state": value,
    }


def flow_state_put(flow_id: str, state_obj: Dict[str, Any], workspace_id: str = "production") -> Dict[str, Any]:
    key = _flow_state_key(flow_id)

    if not isinstance(state_obj, dict):
        raise HTTPException(status_code=400, detail="flow_state_put state_obj must be an object")

    state_obj = dict(state_obj)
    state_obj.setdefault("flow_id", flow_id)
    state_obj.setdefault("root_event_id", flow_id)
    state_obj.setdefault("latest_status", "running")
    state_obj.setdefault("latest_decision", None)
    state_obj.setdefault("steps", [])

    return state_put(key, state_obj, workspace_id=workspace_id)


def flow_state_append_step(
    flow_id: str,
    step_obj: Dict[str, Any],
    workspace_id: str = "production",
) -> Dict[str, Any]:
    if not isinstance(step_obj, dict):
        raise HTTPException(status_code=400, detail="flow_state_append_step step_obj must be an object")

    current = flow_state_get(flow_id, workspace_id=workspace_id)
    state = dict(current.get("state") or {})

    steps = state.get("steps")
    if not isinstance(steps, list):
        steps = []

    step_copy = dict(step_obj)
    step_copy.setdefault("recorded_at", utc_now_iso())

    steps.append(step_copy)

    state["steps"] = steps
    state["flow_id"] = flow_id
    state.setdefault("root_event_id", flow_id)

    if "status" in step_copy:
        state["latest_status"] = step_copy.get("status")

    if "decision" in step_copy:
        state["latest_decision"] = step_copy.get("decision")

    saved = flow_state_put(flow_id, state, workspace_id=workspace_id)
    saved["appended_step"] = step_copy
    return saved


def capability_flow_state_get(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = req.input or {}
    flow_id = str(payload.get("flow_id") or payload.get("root_event_id") or "").strip()
    workspace_id = _resolve_workspace_id(req=req)

    if not flow_id:
        raise HTTPException(status_code=400, detail="flow_state_get missing flow_id")

    result = flow_state_get(flow_id, workspace_id=workspace_id)
    result["run_record_id"] = run_record_id
    return result


def capability_flow_state_put(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = req.input or {}
    flow_id = str(payload.get("flow_id") or payload.get("root_event_id") or "").strip()
    state_obj = payload.get("state") or {}
    workspace_id = _resolve_workspace_id(req=req)

    if not flow_id:
        raise HTTPException(status_code=400, detail="flow_state_put missing flow_id")
    if not isinstance(state_obj, dict):
        raise HTTPException(status_code=400, detail="flow_state_put state must be an object")

    result = flow_state_put(flow_id, state_obj, workspace_id=workspace_id)
    result["run_record_id"] = run_record_id
    return result


def capability_flow_state_append_step(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = req.input or {}
    flow_id = str(payload.get("flow_id") or payload.get("root_event_id") or "").strip()
    step_obj = payload.get("step") or {}
    workspace_id = _resolve_workspace_id(req=req)

    if not flow_id:
        raise HTTPException(status_code=400, detail="flow_state_append_step missing flow_id")
    if not isinstance(step_obj, dict):
        raise HTTPException(status_code=400, detail="flow_state_append_step step must be an object")

    result = flow_state_append_step(flow_id, step_obj, workspace_id=workspace_id)
    result["run_record_id"] = run_record_id
    return result
    
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
# Flows registry helpers
# ============================================================

def flow_get_record(flow_id: str, workspace_id: str = "production") -> Optional[Dict[str, Any]]:
    if not flow_id:
        return None
    return airtable_find_first(
        FLOWS_TABLE_NAME,
        formula=f"AND({{Flow_ID}}='{flow_id}',{{Workspace_ID}}='{workspace_id}')",
        max_records=1,
    )


def flow_create(
    flow_id: str,
    root_event_id: str,
    workspace_id: str = "production",
    goal: str = "",
    status: str = "New",
    current_step: int = 0,
    last_decision: str = "",
    plan_obj: Optional[Dict[str, Any]] = None,
    memory_obj: Optional[Dict[str, Any]] = None,
    result_obj: Optional[Dict[str, Any]] = None,
    linked_run: Optional[List[str]] = None,
) -> Dict[str, Any]:
    now = utc_now_iso()

    fields: Dict[str, Any] = {
        "Flow_ID": flow_id,
        "Root_Event_ID": root_event_id or flow_id,
        "Goal": goal or "",
        "Status_select": status or "New",
        "Current_Step": int(current_step or 0),
        "Last_Decision": last_decision or "",
        "Plan_JSON": json.dumps(plan_obj or {}, ensure_ascii=False),
        "Memory_JSON": json.dumps(memory_obj or {}, ensure_ascii=False),
        "Result_JSON": json.dumps(result_obj or {}, ensure_ascii=False),
        "Workspace_ID": workspace_id or "production",
        "Started_At": now,
        "Last_Updated_At": now,
    }

    if linked_run:
        fields["Linked_Run"] = linked_run

    record_id = airtable_create(FLOWS_TABLE_NAME, fields)

    return {
        "ok": True,
        "record_id": record_id,
        "flow_id": flow_id,
        "workspace_id": workspace_id,
        "mode": "create",
    }


def flow_update(
    flow_id: str,
    workspace_id: str = "production",
    goal: Optional[str] = None,
    status: Optional[str] = None,
    current_step: Optional[int] = None,
    last_decision: Optional[str] = None,
    plan_obj: Optional[Dict[str, Any]] = None,
    memory_obj: Optional[Dict[str, Any]] = None,
    result_obj: Optional[Dict[str, Any]] = None,
    linked_run: Optional[List[str]] = None,
    finished: bool = False,
) -> Dict[str, Any]:
    rec = flow_get_record(flow_id, workspace_id=workspace_id)
    if not rec:
        return {
            "ok": False,
            "error": "flow_not_found",
            "flow_id": flow_id,
            "workspace_id": workspace_id,
        }

    fields: Dict[str, Any] = {
        "Last_Updated_At": utc_now_iso(),
    }

    if goal is not None:
        fields["Goal"] = goal

    if status is not None:
        fields["Status_select"] = status

    if current_step is not None:
        fields["Current_Step"] = int(current_step)

    if last_decision is not None:
        fields["Last_Decision"] = last_decision

    if plan_obj is not None:
        fields["Plan_JSON"] = json.dumps(plan_obj, ensure_ascii=False)

    if memory_obj is not None:
        fields["Memory_JSON"] = json.dumps(memory_obj, ensure_ascii=False)

    if result_obj is not None:
        fields["Result_JSON"] = json.dumps(result_obj, ensure_ascii=False)

    if linked_run is not None:
        fields["Linked_Run"] = linked_run

    if finished:
        fields["Finished_At"] = utc_now_iso()

    airtable_update(FLOWS_TABLE_NAME, rec["id"], fields)

    return {
        "ok": True,
        "record_id": rec["id"],
        "flow_id": flow_id,
        "workspace_id": workspace_id,
        "mode": "update",
    }


def flow_get_or_create(
    flow_id: str,
    root_event_id: str,
    workspace_id: str = "production",
    goal: str = "",
    linked_run: Optional[List[str]] = None,
) -> Dict[str, Any]:
    rec = flow_get_record(flow_id, workspace_id=workspace_id)
    if rec:
        return {
            "ok": True,
            "record_id": rec["id"],
            "flow_id": flow_id,
            "workspace_id": workspace_id,
            "mode": "existing",
        }

    return flow_create(
        flow_id=flow_id,
        root_event_id=root_event_id,
        workspace_id=workspace_id,
        goal=goal,
        status="Running",
        current_step=0,
        linked_run=linked_run,
    )


def complete_flow(
    flow_id: str,
    workspace_id: str = "production",
    result_obj: Optional[Dict[str, Any]] = None,
    last_decision: str = "complete_flow",
    linked_run: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return flow_update(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Completed",
        last_decision=last_decision,
        result_obj=result_obj or {"ok": True, "completed": True},
        linked_run=linked_run,
        finished=True,
    )


def fail_flow(
    flow_id: str,
    workspace_id: str = "production",
    result_obj: Optional[Dict[str, Any]] = None,
    last_decision: str = "fail_flow",
    linked_run: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return flow_update(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Failed",
        last_decision=last_decision,
        result_obj=result_obj or {"ok": False, "failed": True},
        linked_run=linked_run,
        finished=True,
    )


def capability_complete_flow_demo(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    command_id = (
        payload.get("command_id")
        or payload.get("linked_command_id")
        or payload.get("command_record_id")
        or getattr(req, "command_id", None)
        or ""
    )
    command_id = str(command_id).strip()
    flow_id, root_event_id = _resolve_flow_ids(payload)

    if not flow_id:
        raise HTTPException(status_code=400, detail="complete_flow_demo missing flow_id")

    workspace_id = _resolve_workspace_id(req=req)
    step_index = _resolve_flow_step_index(payload, 0)

    _append_flow_step_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        step_obj={
            "step_index": step_index,
            "capability": "complete_flow_demo",
            "status": "done",
            "decision": "complete_flow",
            "run_record_id": run_record_id,
        },
    )

    flow_result = {
        "ok": True,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "completed": True,
        "message": "flow_completed",
        "run_record_id": run_record_id,
    }

    complete_flow(
        flow_id=flow_id,
        workspace_id=workspace_id,
        result_obj=flow_result,
        last_decision="complete_flow",
        linked_run=[run_record_id],
    )

    return flow_result

def capability_decision_router(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    raw_input = req.input or {}
    if not isinstance(raw_input, dict):
        raw_input = {}

    payload = _normalize_flow_keys(raw_input)
    flow_id, root_event_id = _resolve_flow_ids(payload)

    if not flow_id:
        raise HTTPException(status_code=400, detail="decision_router missing flow_id")

    workspace_id = _resolve_workspace_id(req=req)
    step_index = _resolve_flow_step_index(payload, 0)

    state_snapshot = flow_state_get(flow_id, workspace_id=workspace_id)
    state_obj = state_snapshot.get("state") or {}
    steps = state_obj.get("steps") or []

    http_exec_done_count = len(
        [
            s for s in steps
            if isinstance(s, dict)
            and s.get("capability") == "http_exec"
            and s.get("status") == "done"
        ]
    )

    if http_exec_done_count == 0:
        decision = "send_first_probe"
        reason = "no_http_exec_done_yet"
        next_commands = [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": "https://httpbin.org/get",
                    "method": "GET",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "first_probe",
                },
            }
        ]
        terminal = False

    elif http_exec_done_count == 1:
        decision = "send_second_probe"
        reason = "one_http_exec_done"
        next_commands = [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": "https://httpbin.org/uuid",
                    "method": "GET",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "second_probe",
                },
            }
        ]
        terminal = False

    else:
        decision = "complete_flow"
        reason = "enough_http_exec_done"
        next_commands = [
            {
                "capability": "complete_flow",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "finish_flow",
                },
            }
        ]
        terminal = False

    _append_flow_step_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        step_obj={
            "step_index": step_index,
            "capability": "decision_router",
            "status": "done",
            "decision": decision,
            "reason": reason,
            "http_exec_done_count": http_exec_done_count,
            "run_record_id": run_record_id,
        },
    )

    _update_flow_registry_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Running",
        current_step=step_index,
        last_decision=decision,
        memory_obj={
            "http_exec_done_count": http_exec_done_count,
            "last_reason": reason,
        },
        result_obj={
            "last_decision_result": {
                "decision": decision,
                "reason": reason,
            }
        },
        linked_run=[run_record_id],
    )

    return {
        "ok": True,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "decision": decision,
        "reason": reason,
        "http_exec_done_count": http_exec_done_count,
        "next_commands": next_commands,
        "terminal": terminal,
        "run_record_id": run_record_id,
    }
    

# ============================================================
# Command queue helpers
# ============================================================

def create_command_record(
    capability: str,
    priority: int = 1,
    input_data: Optional[Dict[str, Any]] = None,
    workspace_id: Optional[str] = None,
    parent_run_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not capability:
        raise ValueError("capability is required")

    payload = input_data or {}

    flow_id = str(payload.get("flow_id") or "").strip()
    root_event_id = str(payload.get("root_event_id") or "").strip()

    command_id = f"cmd_{uuid.uuid4().hex[:12]}"
    idem_key = f"spawn:{capability}:{flow_id or 'no_flow'}:{uuid.uuid4().hex[:10]}"

    fields: Dict[str, Any] = {
        "Command_ID": command_id,
        "Capability": capability,
        "Status": "Queued",
        "Priority": int(priority or 1),
        "Input_JSON": json.dumps(payload, ensure_ascii=False),
        "Idempotency_Key": idem_key,
    }

    if workspace_id:
        fields["Workspace_ID"] = workspace_id
    if flow_id:
        fields["Flow_ID"] = flow_id
    if root_event_id:
        fields["Root_Event_ID"] = root_event_id
    if parent_run_id:
        fields["Parent_Run_ID"] = parent_run_id

    url = f"{AIRTABLE_API_URL}/{BASE_ID}/{quote(COMMANDS_TABLE_NAME)}"
    headers = airtable_headers()

    resp = requests.post(
        url,
        headers=headers,
        json={"fields": fields},
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()

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

def _truncate_large_result_payload(result_obj: Dict[str, Any], max_len: int = 1200) -> Dict[str, Any]:
    if not isinstance(result_obj, dict):
        return result_obj

    cleaned = dict(result_obj)

    response_text = cleaned.get("response_text")
    if isinstance(response_text, str) and len(response_text) > max_len:
        cleaned["response_text"] = response_text[:max_len] + "...[truncated]"

    response_json = cleaned.get("response_json")
    if isinstance(response_json, str) and len(response_json) > max_len:
        cleaned["response_json"] = response_json[:max_len] + "...[truncated]"

    nested_response = cleaned.get("response")
    if isinstance(nested_response, dict):
        nested_copy = dict(nested_response)
        nested_text = nested_copy.get("text")
        if isinstance(nested_text, str) and len(nested_text) > max_len:
            nested_copy["text"] = nested_text[:max_len] + "...[truncated]"
        cleaned["response"] = nested_copy

    return cleaned

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
    
def _claim_command_for_worker(command_id: str, worker_name: str, run_record_id: str, idem: str) -> Dict[str, Any]:
    now = utc_now_iso()
    ttl_min = _command_lock_ttl_min()
    lock_token = _new_lock_token()
    expires_at = _utc_plus_minutes_iso(ttl_min)

    update_res = _airtable_update_best_effort(
        COMMANDS_TABLE_NAME,
        command_id,
        [
            {
                "Status_select": "Running",
                "Idempotency_Key": idem,
                "Linked_Run": [run_record_id],
                "Started_At": now,
                "Is_Locked": True,
                "Locked_At": now,
                "Locked_By": worker_name,
                "Lock_Token": lock_token,
                "Lock_TTL_Min": ttl_min,
                "Lock_Expires_At": expires_at,
                "Last_Heartbeat_At": now,
            }
        ],
    )

    if not update_res.get("ok"):
        return {"ok": False, "reason": "update_failed", "error": update_res.get("error")}

    try:
        rec = airtable_get_record(COMMANDS_TABLE_NAME, command_id)
        fields = rec.get("fields", {}) or {}

        if (
            str(fields.get("Locked_By") or "").strip() == worker_name
            and str(fields.get("Lock_Token") or "").strip() == lock_token
            and _read_command_status(fields) == "Running"
        ):
            return {
                "ok": True,
                "lock_token": lock_token,
                "record_id": command_id,
            }

        return {"ok": False, "reason": "lock_not_owned_after_refresh"}
    except Exception as e:
        return {"ok": False, "reason": "refresh_failed", "error": repr(e)}

def _worker_still_owns_lock(command_id: str, worker_name: str, lock_token: str) -> bool:
    try:
        rec = airtable_get_record(COMMANDS_TABLE_NAME, command_id)
        fields = rec.get("fields", {}) or {}

        if (
            str(fields.get("Locked_By") or "").strip() == worker_name
            and str(fields.get("Lock_Token") or "").strip() == lock_token
            and _read_command_status(fields) == "Running"
        ):
            return True

        return False
    except Exception:
        return False

def _command_lock_heartbeat(command_id: str, lock_token: str) -> None:
    now = utc_now_iso()
    ttl_min = _command_lock_ttl_min()
    expires_at = _utc_plus_minutes_iso(ttl_min)

    _airtable_update_best_effort(
        COMMANDS_TABLE_NAME,
        command_id,
        [
            {
                "Last_Heartbeat_At": now,
                "Lock_Expires_At": expires_at,
                "Lock_Token": lock_token,
            }
        ],
    )
    
def _command_mark_done_best_effort(command_id: str, run_record_id: str, result_obj: Dict[str, Any]) -> Dict[str, Any]:
    now = utc_now_iso()
    safe_result_obj = _truncate_large_result_payload(result_obj)
    result_json = json.dumps(safe_result_obj, ensure_ascii=False)
    http_status = _extract_http_status_from_result(safe_result_obj)

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

def _normalize_http_exec_input(cmd_input: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(cmd_input, dict):
        cmd_input = {}

    normalized = dict(cmd_input)

    url = str(
        normalized.get("url")
        or normalized.get("http_target")
        or normalized.get("URL")
        or ""
    ).strip()

    method = str(normalized.get("method") or normalized.get("HTTP_Method") or "").strip().upper()
    if not method:
        method = "GET"

    if url:
        normalized["url"] = url
        if "http_target" not in normalized or not str(normalized.get("http_target") or "").strip():
            normalized["http_target"] = url

    normalized["method"] = method
    return normalized

def _validate_command_input(capability: str, cmd_input: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    if not isinstance(cmd_input, dict):
        cmd_input = {}

    normalized = dict(cmd_input)

    if capability == "http_exec":
        normalized = _normalize_http_exec_input(normalized)
        resolved_url = _resolve_http_exec_url_from_command_input(normalized)

        if not resolved_url:
            return False, normalized, "HTTP_EXEC missing url (Input_JSON.url / http_target / URL)"

        method = str(normalized.get("method") or "").strip().upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            return False, normalized, f"HTTP_EXEC invalid method: {method or 'EMPTY'}"

        return True, normalized, None

    return True, normalized, None

def _count_chain_depth(idempotency_key: str) -> int:
    if not idempotency_key:
        return 0
    return str(idempotency_key).count(":next:")


def _infer_root_event_id(fields: Dict[str, Any], parent_idempotency_key: str) -> str:
    direct = str(fields.get("Root_Event_ID") or "").strip()
    if direct:
        return direct

    source_event = fields.get("Source_Event")
    if isinstance(source_event, list) and source_event:
        return str(source_event[0] or "").strip()

    idem = str(parent_idempotency_key or "").strip()
    if idem.startswith("evt:"):
        parts = idem.split(":")
        if len(parts) >= 2:
            return str(parts[1] or "").strip()

    return ""

def _spawn_next_commands_from_result(
    parent_command_id: str,
    parent_idempotency_key: str,
    workspace_id: str,
    result_obj: Dict[str, Any],
    root_event_id: str = "",
) -> Dict[str, Any]:

    if not isinstance(result_obj, dict):
        return {"ok": True, "spawned": 0, "skipped": 0, "errors": []}

    if bool(result_obj.get("terminal")):
        return {"ok": True, "spawned": 0, "skipped": 0, "errors": []}

    next_commands = result_obj.get("next_commands")
    if not isinstance(next_commands, list) or not next_commands:
        return {"ok": True, "spawned": 0, "skipped": 0, "errors": []}

    current_depth = _count_chain_depth(parent_idempotency_key)
    if current_depth >= CHAIN_MAX_DEPTH:
        return {
            "ok": True,
            "spawned": 0,
            "skipped": len(next_commands),
            "errors": [f"max_chain_depth_reached:{CHAIN_MAX_DEPTH}"],
        }

    spawned = 0
    skipped = 0
    errors: List[str] = []

    # =========================
    # Resolve flow IDs
    # =========================
    resolved_flow_id = str(
        result_obj.get("flow_id")
        or result_obj.get("root_event_id")
        or root_event_id
        or ""
    ).strip()

    resolved_root_event_id = str(
        result_obj.get("root_event_id")
        or root_event_id
        or resolved_flow_id
        or ""
    ).strip()

    if not resolved_flow_id:
        previous = result_obj.get("previous")
        if isinstance(previous, dict):
            resolved_flow_id = str(
                previous.get("flow_id")
                or previous.get("root_event_id")
                or ""
            ).strip()

    if not resolved_root_event_id:
        previous = result_obj.get("previous")
        if isinstance(previous, dict):
            resolved_root_event_id = str(
                previous.get("root_event_id")
                or previous.get("flow_id")
                or resolved_flow_id
                or ""
            ).strip()

    # =========================
    # Spawn next commands
    # =========================
    for idx, item in enumerate(next_commands, start=1):

        if not isinstance(item, dict):
            skipped += 1
            errors.append(f"next_commands[{idx}] invalid_item")
            continue

        capability = str(item.get("capability") or "").strip()
        cmd_input = item.get("input") or {}
        priority = int(item.get("priority") or 1)

        if not capability:
            skipped += 1
            errors.append(f"next_commands[{idx}] missing_capability")
            continue

        if capability not in EXECUTABLE_CAPABILITY_ALLOWLIST:
            skipped += 1
            errors.append(f"next_commands[{idx}] disallowed_capability:{capability}")
            continue

        if not isinstance(cmd_input, dict):
            skipped += 1
            errors.append(f"next_commands[{idx}] invalid_input")
            continue

        cmd_input = _normalize_flow_keys(cmd_input)

        if resolved_flow_id and not str(cmd_input.get("flow_id") or "").strip():
            cmd_input["flow_id"] = resolved_flow_id

        if resolved_root_event_id and not str(cmd_input.get("root_event_id") or "").strip():
            cmd_input["root_event_id"] = resolved_root_event_id

        # =========================================
        # HTTP fallback propagation
        # =========================================
        if capability == "http_exec":
            fallback_url = str(
                cmd_input.get("url")
                or cmd_input.get("http_target")
                or result_obj.get("failed_url")
                or result_obj.get("url")
                or ""
            ).strip()

            fallback_method = str(
                cmd_input.get("method")
                or result_obj.get("failed_method")
                or result_obj.get("method")
                or "GET"
            ).strip().upper()

            fallback_goal = str(
                cmd_input.get("goal")
                or result_obj.get("failed_goal")
                or result_obj.get("goal")
                or "retry_probe"
            ).strip()

            if fallback_url and not str(cmd_input.get("url") or "").strip():
                cmd_input["url"] = fallback_url

            if fallback_method and not str(cmd_input.get("method") or "").strip():
                cmd_input["method"] = fallback_method

            if fallback_goal and not str(cmd_input.get("goal") or "").strip():
                cmd_input["goal"] = fallback_goal

        cmd_input = _normalize_flow_keys(cmd_input)

        child_idem = f"{parent_idempotency_key}:next:{idx}:{capability}"

        existing = find_command_by_idem(child_idem)
        if existing:
            skipped += 1
            continue

        flat_http_target = str(
            cmd_input.get("url")
            or cmd_input.get("http_target")
            or ""
        ).strip()

        flat_http_method = str(
            cmd_input.get("method")
            or "GET"
        ).strip().upper()

        create_res = _airtable_create_best_effort(
            COMMANDS_TABLE_NAME,
            [
                {
                    "Capability": capability,
                    "Status_select": "Queued",
                    "Priority": priority,
                    "Input_JSON": json.dumps(cmd_input, ensure_ascii=False),
                    "Idempotency_Key": child_idem,
                    "Workspace_ID": workspace_id,
                    "Parent_Command_ID": parent_command_id,
                    "Root_Event_ID": resolved_root_event_id,
                    "Step_Index": current_depth + idx,
                    "Flow_ID": resolved_flow_id,
                    "http_target": flat_http_target,
                    "HTTP_Method": flat_http_method,
                },
                {
                    "Capability": capability,
                    "Status_select": "Queued",
                    "Priority": priority,
                    "Input_JSON": json.dumps(cmd_input, ensure_ascii=False),
                    "Idempotency_Key": child_idem,
                    "Workspace_ID": workspace_id,
                    "Parent_Command_ID": parent_command_id,
                    "Flow_ID": resolved_flow_id,
                    "http_target": flat_http_target,
                    "HTTP_Method": flat_http_method,
                },
                {
                    "Capability": capability,
                    "Status_select": "Queued",
                    "Priority": priority,
                    "Input_JSON": json.dumps(cmd_input, ensure_ascii=False),
                    "Idempotency_Key": child_idem,
                    "Workspace_ID": workspace_id,
                    "http_target": flat_http_target,
                    "HTTP_Method": flat_http_method,
                },
                {
                    "Capability": capability,
                    "Status_select": "Queued",
                    "Priority": priority,
                    "Input_JSON": json.dumps(cmd_input, ensure_ascii=False),
                    "Idempotency_Key": child_idem,
                },
            ],
        )

        if create_res.get("ok"):
            spawned += 1
        else:
            errors.append(f"next_commands[{idx}] create_failed:{create_res.get('error')}")

    return {
        "ok": True,
        "spawned": spawned,
        "skipped": skipped,
        "errors": errors[:10],
        "flow_id": resolved_flow_id,
        "root_event_id": resolved_root_event_id,
        "max_depth": CHAIN_MAX_DEPTH,
    }

    
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
            _command_mark_retry_or_dead_best_effort(
                cid,
                run_record_id,
                fields,
                "Missing Capability",
            )
            _release_command_lock_best_effort(cid)
            continue

        if capability not in EXECUTABLE_CAPABILITY_ALLOWLIST:
            unsupported += 1
            _command_mark_unsupported_best_effort(
                cid,
                run_record_id,
                f"legacy_or_disallowed_capability:{capability}",
            )
            _release_command_lock_best_effort(cid)
            continue

        fn = CAPABILITIES.get(capability)
        if not fn:
            unsupported += 1
            _command_mark_unsupported_best_effort(
                cid,
                run_record_id,
                f"Unsupported capability: {capability}",
            )
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

        lock_res = _claim_command_for_worker(cid, req.worker, run_record_id, idem)
        if not lock_res.get("ok"):
            blocked += 1
            errors.append(f"{cid}: failed_to_claim:{lock_res.get('reason') or lock_res.get('error')}")
            continue

        lock_token = lock_res.get("lock_token")
            
        is_valid, cmd_input, validation_error = _validate_command_input(capability, cmd_input)
        if not is_valid:
            failed += 1
            _command_mark_retry_or_dead_best_effort(
                cid,
                run_record_id,
                fields,
                validation_error or "invalid_command_input",
            )
            _release_command_lock_best_effort(cid)
            errors.append(f"{cid}: {validation_error or 'invalid_command_input'}")
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

            _command_lock_heartbeat(cid, lock_token)
            result_obj = fn(cmd_req, run_record_id)

            if not _worker_still_owns_lock(cid, req.worker, lock_token):
                blocked += 1

                _command_mark_retry_or_dead_best_effort(
                    cid,
                    run_record_id,
                    fields,
                    "lock_lost_before_finalize",
                )

                _release_command_lock_best_effort(cid)

                errors.append(f"{cid}: lock_lost_before_finalize")
                continue
    
            workspace_id = str(fields.get("Workspace_ID") or "production").strip() or "production"
            root_event_id = _infer_root_event_id(fields, idem)

            spawn_res = _spawn_next_commands_from_result(
                parent_command_id=cid,
                parent_idempotency_key=idem,
                workspace_id=workspace_id,
                result_obj=result_obj,
                root_event_id=root_event_id,
            )

            if isinstance(result_obj, dict):
                result_obj["spawn_summary"] = spawn_res

                if not result_obj.get("flow_id"):
                    result_obj["flow_id"] = (
                        spawn_res.get("flow_id")
                        or cmd_input.get("flow_id")
                        or cmd_input.get("flowid")
                        or root_event_id
                    )

                if not result_obj.get("root_event_id"):
                    result_obj["root_event_id"] = (
                        spawn_res.get("root_event_id")
                        or cmd_input.get("root_event_id")
                        or cmd_input.get("rooteventid")
                        or root_event_id
                    )

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
        try:
            post_ops["event_engine"] = capability_event_engine(req, run_record_id)
        except Exception as e:
            post_ops["event_engine"] = {"ok": False, "error": repr(e)}

    if post_ops:
        result["post_ops"] = post_ops

    return result

def capability_escalation_engine(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    def _lock_acquire_adapter(lock_key: str, owner: str = "", holder: str = "", *args, **kwargs):
        chosen_holder = str(owner or holder or getattr(req, "worker", "") or "escalation_engine").strip()
        return lock_acquire(lock_key, chosen_holder)

    def _lock_release_adapter(lock_key: str, owner: str = "", holder: str = "", *args, **kwargs):
        chosen_holder = str(owner or holder or getattr(req, "worker", "") or "escalation_engine").strip()
        return lock_release(lock_key, chosen_holder)

    payload = _normalize_flow_keys(req.input or {})
    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = _resolve_flow_step_index(payload, 0)

    dispatch_result = capability_escalation_dispatch(
        req,
        run_record_id,
        airtable_list_filtered=airtable_list_filtered,
        airtable_list_view=airtable_list_view,
        airtable_create=airtable_create,
        airtable_update=airtable_update,
        lock_acquire=_lock_acquire_adapter,
        lock_release=_lock_release_adapter,
        http_timeout_seconds=HTTP_TIMEOUT_SECONDS,
        logs_errors_table_name=LOGS_ERRORS_TABLE_NAME,
        logs_errors_view_name=LOGS_ERRORS_VIEW_NAME,
        commands_table_name=COMMANDS_TABLE_NAME,
    )

    if not isinstance(dispatch_result, dict):
        return {
            "ok": False,
            "run_record_id": run_record_id,
            "error": "invalid_escalation_dispatch_result",
            "terminal": True,
            "next_commands": [],
        }

    dispatch_ok = bool(dispatch_result.get("ok"))
    dispatch_mode = str(dispatch_result.get("mode") or "").strip().lower()
    dispatch_errors = dispatch_result.get("errors") or []
    spawn_summary = dispatch_result.get("spawn_summary") or {}

    escalation_command_id = str(
        dispatch_result.get("escalation_command_id")
        or dispatch_result.get("command_id")
        or ""
    ).strip()

    # Cas 1 : escalade bien traitée -> on ferme le flow proprement
    if dispatch_ok and dispatch_mode in ("formula", "view", "active", "scan", "dispatch", "processed", ""):
        return {
            "ok": True,
            "flow_id": flow_id or None,
            "root_event_id": root_event_id or None,
            "decision": "escalation_sent_and_close",
            "run_record_id": run_record_id,
            "escalation_command_id": escalation_command_id or None,
            "dispatch_result": dispatch_result,
            "next_commands": [
                {
                    "capability": "complete_flow_demo",
                    "priority": 1,
                    "input": {
                        "flow_id": flow_id,
                        "root_event_id": root_event_id,
                        "step_index": step_index + 1,
                        "goal": "incident_escalated_and_closed",
                        "reason": "escalation_sent",
                        "run_record_id": run_record_id,
                        "escalation_command_id": escalation_command_id,
                    },
                }
            ],
            "terminal": False,
            "spawn_summary": spawn_summary,
            "errors": dispatch_errors[:10] if isinstance(dispatch_errors, list) else [],
        }

    # Cas 2 : pas d’escalade utile mais pas de crash -> fermeture propre
    if dispatch_ok:
        return {
            "ok": True,
            "flow_id": flow_id or None,
            "root_event_id": root_event_id or None,
            "decision": "escalation_noop_close",
            "run_record_id": run_record_id,
            "dispatch_result": dispatch_result,
            "next_commands": [
                {
                    "capability": "complete_flow_demo",
                    "priority": 1,
                    "input": {
                        "flow_id": flow_id,
                        "root_event_id": root_event_id,
                        "step_index": step_index + 1,
                        "goal": "incident_closed_without_escalation",
                        "reason": "escalation_noop",
                        "run_record_id": run_record_id,
                    },
                }
            ],
            "terminal": False,
            "spawn_summary": spawn_summary,
            "errors": dispatch_errors[:10] if isinstance(dispatch_errors, list) else [],
        }

    # Cas 3 : échec réel du moteur d’escalade -> on remonte l’erreur sans boucler
    return {
        "ok": False,
        "flow_id": flow_id or None,
        "root_event_id": root_event_id or None,
        "decision": "escalation_failed",
        "run_record_id": run_record_id,
        "dispatch_result": dispatch_result,
        "next_commands": [],
        "terminal": True,
        "spawn_summary": spawn_summary,
        "errors": dispatch_errors[:10] if isinstance(dispatch_errors, list) else [],
    }

def capability_internal_escalate_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return capability_internal_escalate(
        req,
        run_record_id,
        airtable_update=airtable_update,
        logs_errors_table_name=LOGS_ERRORS_TABLE_NAME,
    )
    
def capability_chain_demo(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return {
        "ok": True,
        "message": "chain_demo_executed",
        "next_commands": [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": "https://httpbin.org/get",
                    "method": "GET",
                },
            }
        ],
        "run_record_id": run_record_id,
    }

def capability_decision_demo(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    flow_id, root_event_id = _resolve_flow_ids(payload)

    if not flow_id:
        raise HTTPException(status_code=400, detail="decision_demo missing flow_id")

    workspace_id = _resolve_workspace_id(req=req)
    goal = str(payload.get("goal") or "").strip()

    flow_get_or_create(
        flow_id=flow_id,
        root_event_id=root_event_id,
        workspace_id=workspace_id,
        goal=goal,
        linked_run=[run_record_id],
    )

    state_snapshot = flow_state_get(flow_id, workspace_id=workspace_id)
    state_obj = state_snapshot.get("state") or {}
    steps = state_obj.get("steps") or []

    http_exec_done = [
        s for s in steps
        if isinstance(s, dict)
        and s.get("capability") == "http_exec"
        and s.get("status") == "done"
    ]
    http_exec_done_count = len(http_exec_done)
    next_step_index = len(steps) + 1

    if http_exec_done_count == 0:
        decision = "send_http_ping"
        reason = "bootstrap_first_probe"
        next_commands = [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": "https://httpbin.org/get",
                    "method": "GET",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": next_step_index,
                    "goal": "first_probe",
                },
            }
        ]
        terminal = False

    elif http_exec_done_count == 1:
        decision = "send_second_http_ping"
        reason = "need_second_probe"
        next_commands = [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": "https://httpbin.org/uuid",
                    "method": "GET",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": next_step_index,
                    "goal": "second_probe",
                },
            }
        ]
        terminal = False

    else:
        decision = "complete_flow"
        reason = "enough_http_exec_done"
        next_commands = [
            {
                "capability": "complete_flow_demo",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": next_step_index,
                    "goal": "complete_flow",
                },
            }
        ]
        terminal = False

    _append_flow_step_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        step_obj={
            "step_index": next_step_index,
            "capability": "decision_demo",
            "status": "done",
            "decision": decision,
            "reason": reason,
            "run_record_id": run_record_id,
        },
    )

    _update_flow_registry_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Running",
        current_step=next_step_index,
        last_decision=decision,
        memory_obj={
            "http_exec_done_count": http_exec_done_count,
            "last_reason": reason,
        },
        result_obj={
            "last_decision_result": {
                "decision": decision,
                "reason": reason,
            }
        },
        linked_run=[run_record_id],
    )

    return {
        "ok": True,
        "decision": decision,
        "reason": reason,
        "http_exec_done_count": http_exec_done_count,
        "next_commands": next_commands,
        "terminal": terminal,
        "run_record_id": run_record_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
    }
def capability_incident_router(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})

    flow_id, root_event_id = _resolve_flow_ids(payload)
    if not flow_id:
        raise HTTPException(status_code=400, detail="incident_router missing flow_id")

    workspace_id = _resolve_workspace_id(req=req)
    step_index = _resolve_flow_step_index(payload, 0)

    command_id = str(
        payload.get("command_id")
        or payload.get("parent_command_id")
        or payload.get("Command_ID")
        or ""
    ).strip()

    reason = str(payload.get("reason") or "unknown").strip()

    raw_http_status = (
        payload.get("http_status")
        if payload.get("http_status") is not None
        else payload.get("status_code")
    )
    if raw_http_status is None:
        raw_http_status = payload.get("HTTP_Status")

    failed_goal = str(payload.get("failed_goal") or payload.get("goal") or "").strip()
    failed_url = str(
        payload.get("failed_url")
        or payload.get("url")
        or payload.get("http_target")
        or ""
    ).strip()

    failed_method = str(
        payload.get("failed_method")
        or payload.get("method")
        or "GET"
    ).strip().upper()

    sla_status = str(payload.get("sla_status") or payload.get("status") or "").strip().lower()
    severity = "low"

    try:
        http_status = int(raw_http_status) if raw_http_status is not None else None
    except Exception:
        http_status = None

    if http_status is not None and http_status >= 500:
        severity = "critical"
    elif http_status is not None and http_status >= 400:
        severity = "high"
    elif sla_status in ("breached", "escalated"):
        severity = "critical"
    elif sla_status == "warning":
        severity = "medium"
    else:
        severity = "low"

    incident_record_id = ""
    incident_create_result: Dict[str, Any] = {"ok": False, "mode": "not_attempted"}

    if severity in ("critical", "high", "medium"):
        incident_fields_candidates = [
            {
                "Error_ID": flow_id,
                "Flow_ID": flow_id,
                "Root_Event_ID": root_event_id,
                "Run_ID": run_record_id,
                "Command_ID": command_id,
                "Linked_Command": [command_id] if command_id else [],
                "Name": failed_goal or reason or f"incident-{flow_id}",
                "Statut_incident": "Nouveau",
                "Source": "bosai-worker",
                "Incident_Source": "incident_router",
                "Severity": severity,
                "Linked_Run": [run_record_id] if run_record_id else [],
                "Workspace": workspace_id,
                "Error_Message": reason,
                "HTTP_Status": http_status,
                "Failed_URL": failed_url,
                "Failed_Method": failed_method,
                "SLA_Status": sla_status,
            },
            {
                "Error_ID": flow_id,
                "Flow_ID": flow_id,
                "Root_Event_ID": root_event_id,
                "Run_ID": run_record_id,
                "Command_ID": command_id,
                "Linked_Command": [command_id] if command_id else [],
                "Name": failed_goal or reason or f"incident-{flow_id}",
                "Statut_incident": "Nouveau",
                "Source": "bosai-worker",
                "Incident_Source": "incident_router",
                "Severity": severity,
                "Linked_Run": [run_record_id] if run_record_id else [],
                "Error_Message": reason,
                "SLA_Status": sla_status,
            },
            {
                "Error_ID": flow_id,
                "Flow_ID": flow_id,
                "Root_Event_ID": root_event_id,
                "Run_ID": run_record_id,
                "Command_ID": command_id,
                "Linked_Command": [command_id] if command_id else [],
                "Name": failed_goal or reason or f"incident-{flow_id}",
                "Statut_incident": "Nouveau",
                "Source": "bosai-worker",
                "Incident_Source": "incident_router",
                "Severity": severity,
                "Linked_Run": [run_record_id] if run_record_id else [],
            },
            {
                "Name": failed_goal or reason or f"incident-{flow_id}",
                "Statut_incident": "Nouveau",
                "Source": "bosai-worker",
                "Incident_Source": "incident_router",
                "Severity": severity,
            },
        ]

        incident_create_result = _airtable_create_best_effort(
            LOGS_ERRORS_TABLE_NAME,
            incident_fields_candidates,
        )

    if incident_create_result.get("ok"):
        incident_record_id = str(incident_create_result.get("record_id") or "").strip()

    decision = ""
    next_commands: List[Dict[str, Any]] = []
    terminal = False

    if severity == "critical":
        decision = "incident_critical_escalation"
        next_commands = [
            {
                "capability": "escalation_engine",
                "priority": 2,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "critical_escalation",
                    "reason": reason,
                    "http_status": http_status,
                    "failed_goal": failed_goal,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "sla_status": sla_status,
                    "incident_record_id": incident_record_id,
                    "command_id": command_id,
                },
            }
        ]

    elif severity == "high":
        decision = "incident_high_escalation"
        next_commands = [
            {
                "capability": "escalation_engine",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "high_escalation",
                    "reason": reason,
                    "http_status": http_status,
                    "failed_goal": failed_goal,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "sla_status": sla_status,
                    "incident_record_id": incident_record_id,
                    "command_id": command_id,
                },
            }
        ]

    elif severity == "medium":
        decision = "incident_warning_log_and_close"
        next_commands = [
            {
                "capability": "complete_flow_demo",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "incident_warning_closed",
                },
            }
        ]

    else:
        decision = "incident_noop_close"
        next_commands = [
            {
                "capability": "complete_flow_demo",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "incident_closed",
                },
            }
        ]

    _append_flow_step_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        step_obj={
            "step_index": step_index,
            "capability": "incident_router",
            "status": "done",
            "decision": decision,
            "severity": severity,
            "reason": reason,
            "http_status": http_status,
            "failed_goal": failed_goal,
            "failed_url": failed_url,
            "failed_method": failed_method,
            "sla_status": sla_status,
            "incident_record_id": incident_record_id,
            "command_id": command_id,
            "run_record_id": run_record_id,
        },
    )

    _update_flow_registry_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Running",
        current_step=step_index,
        last_decision=decision,
        memory_obj={
            "incident": {
                "severity": severity,
                "reason": reason,
                "http_status": http_status,
                "failed_goal": failed_goal,
                "failed_url": failed_url,
                "failed_method": failed_method,
                "sla_status": sla_status,
                "incident_record_id": incident_record_id,
                "command_id": command_id,
            }
        },
        result_obj={
            "incident_router_result": {
                "decision": decision,
                "severity": severity,
                "reason": reason,
                "http_status": http_status,
                "failed_goal": failed_goal,
                "failed_url": failed_url,
                "failed_method": failed_method,
                "sla_status": sla_status,
                "incident_record_id": incident_record_id,
                "command_id": command_id,
                "incident_create_result": incident_create_result,
            }
        },
        linked_run=[run_record_id],
    )

    return {
        "ok": True,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "decision": decision,
        "severity": severity,
        "reason": reason,
        "http_status": http_status,
        "failed_goal": failed_goal,
        "failed_url": failed_url,
        "failed_method": failed_method,
        "sla_status": sla_status,
        "next_commands": next_commands,
        "terminal": terminal,
        "run_record_id": run_record_id,
        "command_id": command_id,
        "incident_record_id": incident_record_id,
        "incident_create_result": incident_create_result,
    }
def capability_retry_router(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    flow_id, root_event_id = _resolve_flow_ids(payload)

    if not flow_id:
        raise HTTPException(status_code=400, detail="retry_router missing flow_id")

    workspace_id = _resolve_workspace_id(req=req)
    step_index = _resolve_flow_step_index(payload, 0)

    failed_url = str(
        payload.get("failed_url")
        or payload.get("url")
        or payload.get("http_target")
        or ""
    ).strip()

    failed_goal = str(
        payload.get("failed_goal")
        or payload.get("goal")
        or "retry_probe"
    ).strip()

    failed_method = str(
        payload.get("failed_method")
        or payload.get("method")
        or "GET"
    ).strip().upper()

    reason_in = str(payload.get("reason") or "http_failure").strip()

    try:
        retry_count = int(payload.get("retry_count") or 0)
    except Exception:
        retry_count = 0

    try:
        retry_max = int(payload.get("retry_max") or 2)
    except Exception:
        retry_max = 2

    http_status_raw = payload.get("http_status")
    try:
        http_status = int(http_status_raw) if http_status_raw is not None else None
    except Exception:
        http_status = None

    retryable_statuses = {408, 409, 425, 429, 500, 502, 503, 504}
    retryable_reasons = {
        "http_failure",
        "probe_failed",
        "timeout",
        "request_failed",
        "temporary_failure",
    }

    should_retry = False
    if http_status is not None:
        should_retry = http_status in retryable_statuses
    elif reason_in in retryable_reasons:
        should_retry = True

    decision = ""
    reason = ""
    next_commands: List[Dict[str, Any]] = []
    terminal = False
    retry_delay_seconds = 0

    # 1) succès réel -> on termine proprement
    if http_status is not None and http_status < 400:
        decision = "no_retry_needed"
        reason = "http_success"
        terminal = False

        next_commands = [
            {
                "capability": "complete_flow_demo",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "success_no_retry",
                },
            }
        ]

    # 2) URL absente -> incident direct, pas de boucle inutile
    elif not failed_url:
        decision = "missing_failed_url_to_incident"
        reason = "missing_failed_url"
        terminal = False

        next_commands = [
            {
                "capability": "incident_router",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "incident_missing_failed_url",
                    "reason": "missing_failed_url",
                    "http_status": http_status,
                    "failed_goal": failed_goal,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "run_record_id": run_record_id,
                },
            }
        ]

    # 3) erreur non retryable -> incident direct
    elif not should_retry:
        decision = "non_retryable_to_incident"
        reason = f"non_retryable:{reason_in or 'unknown'}"
        terminal = False

        next_commands = [
            {
                "capability": "incident_router",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "incident_non_retryable_http_failure",
                    "reason": reason_in or "non_retryable_failure",
                    "http_status": http_status,
                    "failed_goal": failed_goal,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "run_record_id": run_record_id,
                },
            }
        ]

       # 4) retry possible -> on relance http_exec UNE SEULE FOIS par passage
    elif retry_count < retry_max:
        next_retry_count = retry_count + 1
        retry_delay_seconds = min(60, 2 ** retry_count)

        decision = "retry_http_exec"
        reason = f"{reason_in}_retry_{next_retry_count}_of_{retry_max}"
        terminal = False

        next_commands = [
            {
                "capability": "http_exec",
                "priority": 2,
                "input": {
                    "url": failed_url,
                    "http_target": failed_url,
                    "method": failed_method,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": failed_goal or "retry_after_http_failure",
                    "reason": reason,
                    "origin_reason": reason_in,
                    "retry_count": next_retry_count,
                    "retry_max": retry_max,
                    "retry_delay_seconds": retry_delay_seconds,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "failed_goal": failed_goal or "retry_after_http_failure",
                    "body": {
                        "flow_id": flow_id,
                        "root_event_id": root_event_id,
                        "retry_count": next_retry_count,
                        "retry_max": retry_max,
                        "origin_reason": reason_in,
                        "retry_delay_seconds": retry_delay_seconds,
                        "run_record_id": run_record_id,
                    },
                },
            }
        ]
    # 5) retry épuisé -> incident
    else:
        decision = "retry_exhausted_to_incident"
        reason = "retry_limit_reached"
        terminal = False

        next_commands = [
            {
                "capability": "incident_router",
                "priority": 3,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "incident_after_retry_exhausted",
                    "reason": "retry_exhausted",
                    "http_status": http_status,
                    "failed_goal": failed_goal,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "run_record_id": run_record_id,
                },
            }
        ]

    _append_flow_step_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        step_obj={
            "step_index": step_index,
            "capability": "retry_router",
            "status": "done",
            "decision": decision,
            "reason": reason,
            "retry_count": retry_count,
            "retry_max": retry_max,
            "retry_delay_seconds": retry_delay_seconds,
            "failed_url": failed_url,
            "failed_goal": failed_goal,
            "failed_method": failed_method,
            "http_status": http_status,
            "run_record_id": run_record_id,
        },
    )

    _update_flow_registry_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Running" if decision != "no_retry_needed" else "Completed",
        current_step=step_index,
        last_decision=decision,
        memory_obj={
            "retry_count": retry_count,
            "retry_max": retry_max,
            "retry_delay_seconds": retry_delay_seconds,
            "failed_url": failed_url,
            "failed_goal": failed_goal,
            "failed_method": failed_method,
            "http_status": http_status,
            "last_reason": reason,
        },
        result_obj={
            "retry_router_result": {
                "decision": decision,
                "reason": reason,
                "retry_count": retry_count,
                "retry_max": retry_max,
                "retry_delay_seconds": retry_delay_seconds,
                "failed_url": failed_url,
                "failed_goal": failed_goal,
                "failed_method": failed_method,
                "http_status": http_status,
            }
        },
        linked_run=[run_record_id],
    )

    return {
        "ok": True,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "decision": decision,
        "reason": reason,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_delay_seconds": retry_delay_seconds,
        "failed_url": failed_url,
        "failed_goal": failed_goal,
        "failed_method": failed_method,
        "http_status": http_status,
        "next_commands": next_commands,
        "terminal": terminal,
        "run_record_id": run_record_id,
    }

def capability_sla_router(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    flow_id, root_event_id = _resolve_flow_ids(payload)

    if not flow_id:
        raise HTTPException(status_code=400, detail="sla_router missing flow_id")

    workspace_id = _resolve_workspace_id(req=req)
    step_index = _resolve_flow_step_index(payload, 0)

    sla_status = str(payload.get("sla_status") or payload.get("status") or "warning").strip().lower()
    remaining_minutes_raw = payload.get("sla_remaining_minutes")
    target_url = str(
        payload.get("target_url")
        or payload.get("url")
        or "https://httpbin.org/post"
    ).strip()

    try:
        sla_remaining_minutes = float(remaining_minutes_raw) if remaining_minutes_raw is not None else None
    except Exception:
        sla_remaining_minutes = None

    decision = ""
    reason = ""
    next_commands: List[Dict[str, Any]] = []
    terminal = False

    if sla_status in ("breached", "escalated"):
        decision = "sla_breached_probe_and_close"
        reason = "sla_breached_or_escalated"
        next_commands = [
            {
                "capability": "http_exec",
                "priority": 2,
                "input": {
                    "url": target_url,
                    "method": "POST",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "sla_probe",
                    "body": {
                        "flow_id": flow_id,
                        "root_event_id": root_event_id,
                        "sla_status": sla_status,
                        "sla_remaining_minutes": sla_remaining_minutes,
                        "run_record_id": run_record_id,
                    },
                },
            },
            {
                "capability": "complete_flow_demo",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 2,
                    "goal": "sla_closed_after_probe",
                },
            },
        ]

    elif sla_status == "warning":
        decision = "sla_warning_probe"
        reason = "sla_warning_detected"
        next_commands = [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": target_url,
                    "method": "POST",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "sla_warning_probe",
                    "body": {
                        "flow_id": flow_id,
                        "root_event_id": root_event_id,
                        "sla_status": sla_status,
                        "sla_remaining_minutes": sla_remaining_minutes,
                        "run_record_id": run_record_id,
                    },
                },
            }
        ]

    else:
        decision = "sla_complete_flow"
        reason = "sla_ok_or_unknown"
        next_commands = [
            {
                "capability": "complete_flow_demo",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "sla_closed",
                },
            }
        ]

    _append_flow_step_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        step_obj={
            "step_index": step_index,
            "capability": "sla_router",
            "status": "done",
            "decision": decision,
            "reason": reason,
            "sla_status": sla_status,
            "sla_remaining_minutes": sla_remaining_minutes,
            "run_record_id": run_record_id,
        },
    )

    _update_flow_registry_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Running",
        current_step=step_index,
        last_decision=decision,
        memory_obj={
            "sla_status": sla_status,
            "sla_remaining_minutes": sla_remaining_minutes,
            "last_reason": reason,
        },
        result_obj={
            "sla_router_result": {
                "decision": decision,
                "reason": reason,
                "sla_status": sla_status,
                "sla_remaining_minutes": sla_remaining_minutes,
            }
        },
        linked_run=[run_record_id],
    )

    return {
        "ok": True,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "decision": decision,
        "reason": reason,
        "sla_status": sla_status,
        "sla_remaining_minutes": sla_remaining_minutes,
        "next_commands": next_commands,
        "terminal": terminal,
        "run_record_id": run_record_id,
    }


# ============================================================
# Event helpers
# ============================================================

def _event_workspace_id(fields: Dict[str, Any]) -> str:
    return str(fields.get("Workspace_ID") or "production").strip() or "production"


def _event_effective_idempotency_key(
    fields: Dict[str, Any],
    event_record_id: str,
    capability: str,
) -> str:
    return (
        str(fields.get("Idempotency_Key") or "").strip()
        or f"evt:{event_record_id}:{capability}"
    )


def _event_extract_mapped_capability(fields: Dict[str, Any]) -> str:
    raw = fields.get("Mapped_Capability")

    if isinstance(raw, dict):
        return str(raw.get("name") or "").strip()

    if isinstance(raw, list) and raw:
        first_item = raw[0]
        if isinstance(first_item, dict):
            return str(first_item.get("name") or "").strip()
        return str(first_item or "").strip()

    return str(raw or "").strip()


def _event_guess_http_capability(fields: Dict[str, Any], payload_guess: Dict[str, Any]) -> str:
    if (
        fields.get("http_target")
        or fields.get("URL")
        or fields.get("Http_Target")
        or (isinstance(payload_guess, dict) and payload_guess.get("url"))
    ):
        return "http_exec"
    return ""


def _event_build_command_input(fields: Dict[str, Any]) -> Dict[str, Any]:
    command_input = _json_load_maybe(fields.get("Command_Input_JSON"))
    if not command_input:
        command_input = _json_load_maybe(fields.get("Payload_JSON"))
    if not isinstance(command_input, dict):
        command_input = {}

    http_target = str(
        fields.get("http_target")
        or fields.get("URL")
        or fields.get("Http_Target")
        or command_input.get("http_target")
        or command_input.get("url")
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
        or command_input.get("method")
        or ""
    ).strip()

    if http_method and "method" not in command_input:
        command_input["method"] = http_method

    return command_input


def _event_mark_processed(
    event_record_id: str,
    *,
    command_record_id: Optional[str] = None,
    command_created: bool = True,
    idempotency_key: str = "",
) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []

    if command_record_id:
        candidates.extend(
            [
                {
                    "Linked_Command": [command_record_id],
                    "Command_ID": command_record_id,
                    "Status_select": "Processed",
                    "Status": "Processed",
                    "Command_Created": command_created,
                    "Processed_At": utc_now_iso(),
                    "Idempotency_Key": idempotency_key,
                },
                {
                    "Linked_Command": [command_record_id],
                    "Status_select": "Processed",
                    "Status": "Processed",
                    "Command_Created": command_created,
                    "Processed_At": utc_now_iso(),
                    "Idempotency_Key": idempotency_key,
                },
                {
                    "Command_ID": command_record_id,
                    "Status_select": "Processed",
                    "Status": "Processed",
                    "Command_Created": command_created,
                    "Processed_At": utc_now_iso(),
                    "Idempotency_Key": idempotency_key,
                },
            ]
        )

    candidates.append(
        {
            "Status_select": "Processed",
            "Status": "Processed",
            "Command_Created": command_created,
            "Processed_At": utc_now_iso(),
            "Idempotency_Key": idempotency_key,
        }
    )

    return _airtable_update_best_effort(EVENTS_TABLE_NAME, event_record_id, candidates)


def _event_mark_ignored(event_record_id: str, message: str) -> Dict[str, Any]:
    return _airtable_update_best_effort(
        EVENTS_TABLE_NAME,
        event_record_id,
        [
            {
                "Status_select": "Ignored",
                "Status": "Ignored",
                "Processed_At": utc_now_iso(),
                "Error_Message": message,
            },
            {
                "Status_select": "Ignored",
                "Processed_At": utc_now_iso(),
                "Error_Message": message,
            },
            {
                "Status": "Ignored",
                "Processed_At": utc_now_iso(),
                "Error_Message": message,
            },
        ],
    )


def _event_mark_error(event_record_id: str, message: str) -> Dict[str, Any]:
    return _airtable_update_best_effort(
        EVENTS_TABLE_NAME,
        event_record_id,
        [
            {
                "Status_select": "Error",
                "Status": "Error",
                "Processed_At": utc_now_iso(),
                "Error_Message": message,
            },
            {
                "Status_select": "Error",
                "Processed_At": utc_now_iso(),
                "Error_Message": message,
            },
            {
                "Status": "Error",
                "Processed_At": utc_now_iso(),
                "Error_Message": message,
            },
            {
                "Status_select": "Error",
            },
            {
                "Status": "Error",
            },
        ],
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

    command_input = command_input or {}
    input_json = json.dumps(command_input, ensure_ascii=False)

    url_value = str(
        command_input.get("url")
        or command_input.get("http_target")
        or command_input.get("URL")
        or ""
    ).strip()

    method_value = str(
        command_input.get("method")
        or command_input.get("HTTP_Method")
        or "GET"
    ).strip().upper()

    candidates: List[Dict[str, Any]] = [
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Priority": priority,
            "Input_JSON": input_json,
            "Idempotency_Key": idem,
            "Workspace_ID": workspace_id,
            "Source_Event": [event_record_id],
            "http_target": url_value,
            "URL": url_value,
            "HTTP_Method": method_value,
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Priority": priority,
            "Input_JSON": input_json,
            "Idempotency_Key": idem,
            "Workspace_ID": workspace_id,
            "http_target": url_value,
            "URL": url_value,
            "HTTP_Method": method_value,
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Priority": priority,
            "Input_JSON": input_json,
            "Idempotency_Key": idem,
            "http_target": url_value,
            "URL": url_value,
            "HTTP_Method": method_value,
        },
    ]

    return candidates

def _create_command_from_event(event_record: Dict[str, Any]) -> Dict[str, Any]:
    fields = event_record.get("fields", {}) or {}
    event_record_id = str(event_record.get("id") or "").strip()

    if not event_record_id:
        return {"ok": False, "error": "missing_event_record_id"}

    payload_guess = _json_load_maybe(fields.get("Payload_JSON"))
    mapped_capability = _event_extract_mapped_capability(fields)

    if not mapped_capability:
        mapped_capability = _event_guess_http_capability(fields, payload_guess)

    if not mapped_capability:
        return {"ok": False, "error": "missing_mapped_capability"}

    if mapped_capability not in EVENT_CAPABILITY_ALLOWLIST:
        _event_mark_ignored(
            event_record_id,
            f"legacy_or_disallowed_capability:{mapped_capability}",
        )
        return {
            "ok": False,
            "error": f"legacy_or_disallowed_capability:{mapped_capability}",
            "event_id": event_record_id,
        }

    workspace_id = _event_workspace_id(fields)
    command_input = _event_build_command_input(fields)
    effective_idempotency_key = _event_effective_idempotency_key(
        fields,
        event_record_id,
        mapped_capability,
    )

    if mapped_capability in (
        "decision_demo",
        "decision_router",
        "incident_router",
        "retry_router",
        "sla_router",
        "complete_flow",
        "complete_flow_demo",
    ):
        if not str(command_input.get("flow_id") or "").strip():
            command_input["flow_id"] = event_record_id
        if not str(command_input.get("root_event_id") or "").strip():
            command_input["root_event_id"] = event_record_id

    existing = find_command_by_idem(effective_idempotency_key)
    if existing:
        existing_id = str(existing.get("id") or "").strip()

        _event_mark_processed(
            event_record_id,
            command_record_id=existing_id,
            command_created=True,
            idempotency_key=effective_idempotency_key,
        )

        return {
            "ok": True,
            "mode": "existing_command",
            "event_id": event_record_id,
            "command_record_id": existing_id,
            "capability": mapped_capability,
            "workspace_id": workspace_id,
            "idempotency_key": effective_idempotency_key,
        }

    candidates = _build_command_fields_candidates(
        capability=mapped_capability,
        command_input=command_input,
        workspace_id=workspace_id,
        event_record_id=event_record_id,
        idempotency_key=effective_idempotency_key,
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

    _event_mark_processed(
        event_record_id,
        command_record_id=command_record_id,
        command_created=True,
        idempotency_key=effective_idempotency_key,
    )

    return {
        "ok": True,
        "mode": "created_command",
        "event_id": event_record_id,
        "command_record_id": command_record_id,
        "capability": mapped_capability,
        "workspace_id": workspace_id,
        "idempotency_key": effective_idempotency_key,
    }

def _create_command_from_next_command(
    next_cmd: Dict[str, Any],
    parent_run_id: str,
    workspace_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(next_cmd, dict):
        return {"ok": False, "error": "invalid_next_command"}

    capability = str(next_cmd.get("capability") or "").strip()
    if not capability:
        return {"ok": False, "error": "missing_capability"}

    command_input = next_cmd.get("input") or {}
    if not isinstance(command_input, dict):
        return {"ok": False, "error": "invalid_input"}

    priority = int(next_cmd.get("priority") or 1)

    flow_id = str(command_input.get("flow_id") or "").strip()
    root_event_id = str(command_input.get("root_event_id") or "").strip()

    if capability in (
        "decision_demo",
        "decision_router",
        "incident_router",
        "retry_router",
        "sla_router",
        "complete_flow",
        "complete_flow_demo",
    ):
        if not flow_id:
            flow_id = parent_run_id
            command_input["flow_id"] = flow_id
        if not root_event_id:
            root_event_id = parent_run_id
            command_input["root_event_id"] = root_event_id

    effective_idempotency_key = str(
        next_cmd.get("idempotency_key")
        or command_input.get("idempotency_key")
        or f"spawn:{capability}:{flow_id or parent_run_id}:{uuid.uuid4().hex[:10]}"
    ).strip()

    existing = find_command_by_idem(effective_idempotency_key)
    if existing:
        return {
            "ok": True,
            "mode": "existing_command",
            "command_record_id": str(existing.get("id") or "").strip(),
            "capability": capability,
            "workspace_id": workspace_id,
            "idempotency_key": effective_idempotency_key,
            "parent_run_id": parent_run_id,
        }

    candidates = _build_command_fields_candidates(
        capability=capability,
        command_input=command_input,
        workspace_id=workspace_id,
        event_record_id=root_event_id or parent_run_id,
        idempotency_key=effective_idempotency_key,
        priority=priority,
    )

    create_res = _airtable_create_best_effort(COMMANDS_TABLE_NAME, candidates)
    if not create_res.get("ok"):
        return {
            "ok": False,
            "error": f"command_create_failed:{create_res.get('error')}",
            "capability": capability,
            "parent_run_id": parent_run_id,
        }

    return {
        "ok": True,
        "mode": "created_command",
        "command_record_id": str(create_res.get("record_id") or "").strip(),
        "capability": capability,
        "workspace_id": workspace_id,
        "idempotency_key": effective_idempotency_key,
        "parent_run_id": parent_run_id,
    }
def _create_incident_log_record(incident_payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        flow_id = str(incident_payload.get("flow_id") or "").strip()
        root_event_id = str(incident_payload.get("root_event_id") or "").strip()
        goal = str(incident_payload.get("goal") or "").strip()
        reason = str(incident_payload.get("reason") or "").strip()
        error_text = str(incident_payload.get("error") or "").strip()
        original_capability = str(incident_payload.get("original_capability") or "").strip()
        failed_url = str(incident_payload.get("failed_url") or "").strip()
        failed_method = str(incident_payload.get("failed_method") or "").strip()
        workspace_id = str(incident_payload.get("workspace_id") or "").strip()
        run_record_id = str(incident_payload.get("run_record_id") or "").strip()
        incident_key = str(incident_payload.get("incident_key") or "").strip()

        http_status = incident_payload.get("http_status")
        try:
            http_status = int(http_status) if http_status is not None else None
        except Exception:
            http_status = None

        retry_count = int(incident_payload.get("retry_count") or 0)
        retry_max = int(incident_payload.get("retry_max") or 0)

        severity = "critical" if http_status is not None and http_status >= 500 else "high"

        error_id = incident_key or f"incident-{uuid.uuid4().hex[:12]}"

        candidates = [
            {
                "Error_ID": error_id,
                "Created_At": utc_now_iso(),
                "Status_incident": "Nouveau",
                "Source": "bosai-worker",
                "Severity": severity,
                "Endpoint_URL": failed_url,
                "Linked_Run": [run_record_id] if run_record_id else [],
                "Name": goal or reason or "incident",
            },
            {
                "Error_ID": error_id,
                "Created_At": utc_now_iso(),
                "Status_incident": "Nouveau",
                "Source": "bosai-worker",
                "Severity": severity,
                "Endpoint_URL": failed_url,
                "Name": goal or reason or "incident",
            },
            {
                "Error_ID": error_id,
                "Status_incident": "Nouveau",
                "Source": "bosai-worker",
                "Severity": severity,
                "Endpoint_URL": failed_url,
                "Name": goal or reason or "incident",
            },
            {
                "Name": goal or reason or "incident",
            },
        ]

        create_res = _airtable_create_best_effort(LOGS_ERREURS_TABLE_NAME, candidates)

        if not create_res.get("ok"):
            return {
                "ok": False,
                "error": create_res.get("error"),
                "debug": {
                    "table": LOGS_ERREURS_TABLE_NAME,
                    "candidates": candidates,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "goal": goal,
                    "reason": reason,
                    "error_text": error_text,
                    "original_capability": original_capability,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "http_status": http_status,
                    "workspace_id": workspace_id,
                    "run_record_id": run_record_id,
                },
            }

        return {
            "ok": True,
            "record_id": str(create_res.get("record_id") or "").strip(),
        }

    except Exception as e:
        return {
            "ok": False,
            "error": repr(e),
        }

def capability_planner_demo(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})

    flow_id = str(
        payload.get("flow_id")
        or payload.get("root_event_id")
        or payload.get("event_id")
        or ""
    ).strip()

    if not flow_id:
        flow_id = f"flow-{uuid.uuid4().hex[:12]}"

    workspace_id = _resolve_workspace_id(req=req)
    root_event_id = str(payload.get("root_event_id") or flow_id).strip() or flow_id
    goal = str(payload.get("goal") or "verify endpoint flow").strip()

    probe_url = str(payload.get("probe_url") or "https://httpbin.org/get").strip()
    confirm_url = str(payload.get("confirm_url") or "https://httpbin.org/uuid").strip()

    plan = [
        {
            "step": 1,
            "capability": "http_exec",
            "goal": "fetch_probe",
            "url": probe_url,
        },
        {
            "step": 2,
            "capability": "http_exec",
            "goal": "confirm_probe",
            "url": confirm_url,
        },
        {
            "step": 3,
            "capability": "decision_demo",
            "goal": "final_decision",
        },
    ]

    flow_get_or_create(
        flow_id=flow_id,
        root_event_id=root_event_id,
        workspace_id=workspace_id,
        goal=goal,
        linked_run=[run_record_id],
    )

    flow_update(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Running",
        current_step=0,
        last_decision="planner_initialized",
        plan_obj={"steps": plan},
        memory_obj={"planner_initialized": True},
        linked_run=[run_record_id],
    )

    flow_state_append_step(
        flow_id=flow_id,
        workspace_id=workspace_id,
        step_obj={
            "step_index": 0,
            "capability": "planner_demo",
            "status": "done",
            "plan_size": len(plan),
            "run_record_id": run_record_id,
        },
    )

    return {
        "ok": True,
        "message": "planner_demo_executed",
        "plan": plan,
        "next_commands": [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": probe_url,
                    "method": "GET",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": 1,
                    "goal": "fetch_probe",
                },
            },
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": confirm_url,
                    "method": "GET",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": 2,
                    "goal": "confirm_probe",
                },
            },
        ],
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "run_record_id": run_record_id,
    }
    
def capability_http_exec_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    workspace_id = _resolve_workspace_id(req=req)

    result = capability_http_exec(input_data=payload)

    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = _resolve_flow_step_index(payload, 0)
    goal = str(payload.get("goal") or "").strip()

    next_commands: List[Dict[str, Any]] = []

    response_obj = result.get("response") if isinstance(result, dict) else {}
    if not isinstance(response_obj, dict):
        response_obj = {}

    status_code = response_obj.get("status_code")
    if status_code is None:
        status_code = result.get("status_code")

    if status_code is not None:
        try:
            status_code = int(status_code)
        except Exception:
            status_code = None

    # ------------------------------------------------------------
    # FAILURE PATH -> retry_router only
    # ------------------------------------------------------------
    if result.get("trigger_retry_router") is True:
        retry_input = dict(payload)

        retry_input["flow_id"] = flow_id
        retry_input["root_event_id"] = root_event_id
        retry_input["step_index"] = step_index + 1
        retry_input["retry_count"] = int(
            result.get("retry_count", payload.get("retry_count", 0)) or 0
        )
        retry_input["retry_max"] = int(
            result.get("retry_max", payload.get("retry_max", 3)) or 3
        )
        retry_input["retry_reason"] = (
            result.get("retry_reason")
            or result.get("error_code")
            or "unknown"
        )
        retry_input["error"] = result.get("error")
        retry_input["original_capability"] = "http_exec"
        retry_input["goal"] = "route_retry"

        # cleanup internal fields if present
        retry_input.pop("next_capability", None)
        retry_input.pop("trigger_retry_router", None)
        retry_input.pop("next_commands", None)
        retry_input.pop("terminal", None)
        retry_input.pop("spawn_summary", None)

        next_commands = [
            {
                "capability": "retry_router",
                "priority": req.priority,
                "input": retry_input,
                "terminal": False,
            }
        ]

        result["flow_id"] = flow_id
        result["root_event_id"] = root_event_id
        result["next_commands"] = next_commands
        result["terminal"] = False

        print(
            "[worker.wrapper] http_exec failure -> retry_router",
            {
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "retry_count": retry_input.get("retry_count"),
                "retry_max": retry_input.get("retry_max"),
                "retry_reason": retry_input.get("retry_reason"),
            },
        )

        return result

    # ------------------------------------------------------------
    # SUCCESS PATH -> flow memory / next step
    # ------------------------------------------------------------
    if flow_id:
        _append_flow_step_safe(
            flow_id=flow_id,
            workspace_id=workspace_id,
            step_obj={
                "step_index": step_index,
                "capability": "http_exec",
                "status": "done",
                "goal": goal,
                "url": payload.get("url") or payload.get("http_target"),
                "result": {
                    "status_code": status_code,
                    "ok": result.get("ok"),
                },
                "run_record_id": run_record_id,
            },
        )

        current = flow_state_get(flow_id, workspace_id=workspace_id)
        state_obj = current.get("state") or {}
        steps = state_obj.get("steps") or []

        http_exec_done_count = len(
            [
                s
                for s in steps
                if isinstance(s, dict)
                and s.get("capability") == "http_exec"
                and s.get("status") == "done"
            ]
        )

        _update_flow_registry_safe(
            flow_id=flow_id,
            workspace_id=workspace_id,
            status="Running",
            current_step=step_index,
            last_decision=f"http_exec_done:{goal or 'unknown'}",
            memory_obj={
                "last_http_exec": {
                    "goal": goal,
                    "step_index": step_index,
                    "status_code": status_code,
                    "ok": result.get("ok"),
                },
                "http_exec_done_count": http_exec_done_count,
                "steps_count": len(steps),
            },
            linked_run=[run_record_id],
        )

        result["flow_id"] = flow_id
        result["root_event_id"] = root_event_id
        result["http_exec_done_count"] = http_exec_done_count

        goal_lower = goal.lower()

        if goal_lower in (
            "create_incident",
            "alert_incident",
            "sla_probe",
            "sla_warning_probe",
        ):
            next_commands = []

        elif goal_lower == "escalation_send":
            next_commands = [
                {
                    "capability": "complete_flow_demo",
                    "priority": 1,
                    "input": {
                        "flow_id": flow_id,
                        "root_event_id": root_event_id,
                        "step_index": step_index + 1,
                        "goal": "escalation_sent",
                    },
                    "terminal": False,
                }
            ]

        elif http_exec_done_count >= 2:
            next_commands = [
                {
                    "capability": "complete_flow_demo",
                    "priority": 1,
                    "input": {
                        "flow_id": flow_id,
                        "root_event_id": root_event_id,
                        "step_index": step_index + 1,
                        "goal": "complete_flow",
                    },
                    "terminal": False,
                }
            ]

        else:
            next_commands = [
                {
                    "capability": "decision_demo",
                    "priority": 1,
                    "input": {
                        "flow_id": flow_id,
                        "root_event_id": root_event_id,
                        "step_index": step_index + 1,
                        "goal": "continue_flow",
                    },
                    "terminal": False,
                }
            ]

        if next_commands:
            result["next_commands"] = next_commands
            result["terminal"] = False
        else:
            result["next_commands"] = []
            result["terminal"] = True

        print(
            "[worker.wrapper] http_exec success next_commands =",
            [x.get("capability") for x in (result.get("next_commands") or [])]
            if isinstance(result, dict) else "not_dict"
        )

    return result

def capability_retry_router_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    workspace_id = _resolve_workspace_id(req=req)

    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = int(payload.get("step_index") or 0)

    retry_count = int(payload.get("retry_count") or 0)
    retry_max = int(payload.get("retry_max") or 3)

    goal = str(payload.get("goal") or "").strip()
    original_capability = str(payload.get("original_capability") or "http_exec").strip()

    retry_reason = str(
        payload.get("retry_reason")
        or payload.get("error_code")
        or "unknown"
    ).strip()

    last_error = (
        payload.get("error")
        or payload.get("last_error")
        or payload.get("response_status")
        or payload.get("status_code")
    )

    next_commands: List[Dict[str, Any]] = []

    # ------------------------------------------------------------
    # CASE 1: retry still allowed
    # ------------------------------------------------------------
    if retry_count < retry_max:
        next_retry_count = retry_count + 1

        retry_input = dict(payload)
        retry_input["flow_id"] = flow_id
        retry_input["root_event_id"] = root_event_id
        retry_input["retry_count"] = next_retry_count
        retry_input["retry_max"] = retry_max
        retry_input["step_index"] = step_index + 1
        retry_input["goal"] = "retry_http_exec"
        retry_input["original_capability"] = original_capability
        retry_input["retry_reason"] = retry_reason
        retry_input["last_error"] = last_error

        # cleanup router-only fields if present
        retry_input.pop("next_capability", None)
        retry_input.pop("trigger_retry_router", None)
        retry_input.pop("next_commands", None)
        retry_input.pop("terminal", None)
        retry_input.pop("spawn_summary", None)

        next_commands.append(
            {
                "capability": original_capability,
                "priority": req.priority,
                "input": retry_input,
                "terminal": False,
            }
        )

        return {
            "ok": True,
            "capability": "retry_router",
            "status": "retry_scheduled",
            "run_record_id": run_record_id,
            "workspace_id": workspace_id,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "step_index": step_index,
            "retry_count": retry_count,
            "retry_max": retry_max,
            "next_retry_count": next_retry_count,
            "retry_reason": retry_reason,
            "last_error": last_error,
            "decision": "retry",
            "goal": goal,
            "terminal": False,
            "next_commands": next_commands,
        }

    # ------------------------------------------------------------
    # CASE 2: retry max reached
    # ------------------------------------------------------------
    escalation_input = {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "step_index": step_index + 1,
        "goal": "retry_exhausted",
        "original_capability": original_capability,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_reason": retry_reason,
        "last_error": last_error,
        "workspace_id": workspace_id,
    }

    next_commands.append(
        {
            "capability": "decision_router",
            "priority": req.priority,
            "input": escalation_input,
            "terminal": True,
        }
    )

    return {
        "ok": True,
        "capability": "retry_router",
        "status": "retry_exhausted",
        "run_record_id": run_record_id,
        "workspace_id": workspace_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "step_index": step_index,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_reason": retry_reason,
        "last_error": last_error,
        "decision": "stop_and_escalate",
        "goal": goal,
        "terminal": True,
        "next_commands": next_commands,
    }

def capability_decision_router_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    workspace_id = _resolve_workspace_id(req=req)

    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = _resolve_flow_step_index(payload, 0)

    goal = str(payload.get("goal") or "").strip().lower()
    retry_reason = str(payload.get("retry_reason") or "").strip().lower()
    original_capability = str(payload.get("original_capability") or "").strip()
    error_text = str(
        payload.get("error")
        or payload.get("last_error")
        or ""
    ).strip()

    http_status = payload.get("http_status") or payload.get("status_code")
    try:
        http_status = int(http_status) if http_status is not None else None
    except Exception:
        http_status = None

    retry_count = int(payload.get("retry_count") or 0)
    retry_max = int(payload.get("retry_max") or 0)

    next_commands: List[Dict[str, Any]] = []
    decision = "stop"
    status = "decision_made"
    terminal = False
    reason = ""

    # ------------------------------------------------------------
    # CASE 1: retry exhausted -> escalate / incident path
    # ------------------------------------------------------------
    if goal == "retry_exhausted":
        decision = "escalate_after_retry_exhausted"
        reason = "retry_exhausted"

        next_commands.append(
            {
                "capability": "incident_router",
                "priority": req.priority,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "create_incident_after_retry_exhausted",
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "retry_reason": retry_reason,
                    "original_capability": original_capability,
                    "http_status": http_status,
                    "error": error_text,
                    "workspace_id": workspace_id,
                },
                "terminal": False,
            }
        )

    # ------------------------------------------------------------
    # CASE 2: continue flow after successful execution
    # ------------------------------------------------------------
    elif goal in ("continue_flow", "complete_flow", "post_http_success"):
        decision = "continue_flow"
        reason = "normal_continuation"

        next_commands.append(
            {
                "capability": "complete_flow_demo",
                "priority": req.priority,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "complete_flow",
                    "workspace_id": workspace_id,
                },
                "terminal": False,
            }
        )

    # ------------------------------------------------------------
    # CASE 3: explicit escalation_send completion
    # ------------------------------------------------------------
    elif goal == "escalation_sent":
        decision = "complete_after_escalation"
        reason = "escalation_completed"

        next_commands.append(
            {
                "capability": "complete_flow_demo",
                "priority": req.priority,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "complete_flow",
                    "workspace_id": workspace_id,
                },
                "terminal": False,
            }
        )

    # ------------------------------------------------------------
    # CASE 4: HTTP/server-type failure outside retry exhausted
    # ------------------------------------------------------------
    elif http_status is not None and http_status >= 500:
        decision = "route_incident"
        reason = "server_error"

        next_commands.append(
            {
                "capability": "incident_router",
                "priority": req.priority,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "create_incident",
                    "http_status": http_status,
                    "retry_reason": retry_reason,
                    "original_capability": original_capability,
                    "error": error_text,
                    "workspace_id": workspace_id,
                },
                "terminal": False,
            }
        )

    # ------------------------------------------------------------
    # CASE 5: fallback safe stop
    # ------------------------------------------------------------
    else:
        decision = "safe_stop"
        reason = "no_matching_rule"
        terminal = True

    result = {
        "ok": True,
        "capability": "decision_router",
        "status": status,
        "run_record_id": run_record_id,
        "workspace_id": workspace_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "step_index": step_index,
        "goal": goal,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_reason": retry_reason,
        "original_capability": original_capability,
        "http_status": http_status,
        "error": error_text,
        "decision": decision,
        "reason": reason,
        "terminal": terminal,
        "next_commands": next_commands,
    }

    return result
    
EVENT_CAPABILITY_ALLOWLIST = {
    "http_exec",
    "escalation_engine",
    "internal_escalate",
    "chain_demo",
    "planner_demo",
    "decision_demo",
    "decision_router",
    "incident_router",
    "retry_router",
    "sla_router",
    "complete_flow_demo",
    "complete_flow",
}

EXECUTABLE_CAPABILITY_ALLOWLIST = {
    "http_exec",
    "escalation_engine",
    "internal_escalate",
    "chain_demo",
    "planner_demo",
    "decision_demo",
    "decision_router",
    "incident_router",
    "retry_router",
    "sla_router",
    "complete_flow",
    "complete_flow_demo",
    "flow_state_get",
    "flow_state_put",
    "flow_state_append_step",
}

def capability_incident_router_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    workspace_id = _resolve_workspace_id(req=req)

    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = _resolve_flow_step_index(payload, 0)

    goal = str(payload.get("goal") or "").strip()
    reason = str(payload.get("reason") or payload.get("retry_reason") or "unknown").strip()
    error_text = str(payload.get("error") or payload.get("last_error") or "").strip()

    original_capability = str(payload.get("original_capability") or "").strip()
    failed_url = str(payload.get("failed_url") or payload.get("url") or payload.get("http_target") or "").strip()
    failed_method = str(payload.get("failed_method") or payload.get("method") or "").strip()

    retry_count = int(payload.get("retry_count") or 0)
    retry_max = int(payload.get("retry_max") or 0)

    http_status = payload.get("http_status") or payload.get("status_code")
    try:
        http_status = int(http_status) if http_status is not None else None
    except Exception:
        http_status = None

    incident_key = "|".join(
        [
            flow_id or "no_flow",
            root_event_id or "no_root",
            original_capability or "no_cap",
            failed_method or "no_method",
            failed_url or "no_url",
            str(http_status or "no_status"),
            reason or "no_reason",
        ]
    )

    incident_payload = {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "step_index": step_index,
        "goal": goal,
        "reason": reason,
        "error": error_text,
        "original_capability": original_capability,
        "failed_url": failed_url,
        "failed_method": failed_method,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "http_status": http_status,
        "workspace_id": workspace_id,
        "run_record_id": run_record_id,
        "incident_key": incident_key,
    }

    create_res = _create_incident_log_record(incident_payload)

    next_commands: List[Dict[str, Any]] = []

    # étape suivante simple: escalade interne / ou flow completion
    next_commands.append(
        {
            "capability": "internal_escalate",
            "priority": req.priority,
            "input": {
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "step_index": step_index + 1,
                "goal": "incident_escalation",
                "reason": reason,
                "error": error_text,
                "original_capability": original_capability,
                "failed_url": failed_url,
                "failed_method": failed_method,
                "retry_count": retry_count,
                "retry_max": retry_max,
                "http_status": http_status,
                "incident_record_id": create_res.get("record_id"),
                "workspace_id": workspace_id,
            },
            "terminal": False,
        }
    )

    _append_flow_step_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        step_obj={
            "step_index": step_index,
            "capability": "incident_router",
            "status": "done",
            "goal": goal,
            "reason": reason,
            "http_status": http_status,
            "failed_url": failed_url,
            "failed_method": failed_method,
            "incident_record_id": create_res.get("record_id"),
            "run_record_id": run_record_id,
        },
    )

    _update_flow_registry_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Running",
        current_step=step_index,
        last_decision="incident_created",
        memory_obj={
            "last_incident": {
                "goal": goal,
                "reason": reason,
                "http_status": http_status,
                "failed_url": failed_url,
                "incident_record_id": create_res.get("record_id"),
            }
        },
        result_obj={
            "incident_router_result": {
                "ok": bool(create_res.get("ok")),
                "record_id": create_res.get("record_id"),
                "reason": reason,
                "http_status": http_status,
            }
        },
        linked_run=[run_record_id],
    )

    return {
        "ok": True,
        "capability": "incident_router",
        "status": "incident_created" if create_res.get("ok") else "incident_create_failed",
        "run_record_id": run_record_id,
        "workspace_id": workspace_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "step_index": step_index,
        "goal": goal,
        "reason": reason,
        "error": error_text,
        "original_capability": original_capability,
        "failed_url": failed_url,
        "failed_method": failed_method,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "http_status": http_status,
        "incident_record_id": create_res.get("record_id"),
        "incident_create_ok": bool(create_res.get("ok")),
        "next_commands": next_commands,
        "terminal": False,
    }
    
def capability_complete_flow(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    flow_id, root_event_id = _resolve_flow_ids(payload)

    if not flow_id:
        raise HTTPException(status_code=400, detail="complete_flow missing flow_id")

    workspace_id = _resolve_workspace_id(req=req)
    step_index = _resolve_flow_step_index(payload, 0)
    goal = str(payload.get("goal") or "finish").strip()

    _append_flow_step_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        step_obj={
            "step_index": step_index,
            "capability": "complete_flow",
            "status": "done",
            "decision": "complete_flow",
            "goal": goal,
            "run_record_id": run_record_id,
        },
    )

    final_result = {
        "ok": True,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "completed": True,
        "final_status": "Completed",
        "goal": goal,
        "run_record_id": run_record_id,
    }

    complete_flow(
        flow_id=flow_id,
        workspace_id=workspace_id,
        result_obj=final_result,
        last_decision="complete_flow",
        linked_run=[run_record_id],
    )

    _update_flow_registry_safe(
        flow_id=flow_id,
        workspace_id=workspace_id,
        status="Completed",
        current_step=step_index,
        last_decision="complete_flow",
        result_obj=final_result,
        linked_run=[run_record_id],
        finished=True,
    )

    return final_result
    
def capability_event_engine(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    limit = 20
    try:
        raw_limit = (req.input or {}).get("limit", 20)
        limit = _safe_limit(int(raw_limit), default=20, minimum=1, maximum=100)
    except Exception:
        limit = 20

    result = process_events(limit=limit)
    if isinstance(result, dict) and "run_record_id" not in result:
        result["run_record_id"] = run_record_id
    return result
# ============================================================
# Capabilities registry
# ============================================================

CAPABILITIES = {
    "health_tick": capability_health_tick,
    "commands_tick": capability_commands_tick,
    "escalation_engine": capability_escalation_engine,
    "internal_escalate": capability_internal_escalate_wrapped,
    "http_exec": capability_http_exec_wrapped,
    "state_get": capability_state_get,
    "state_put": capability_state_put,
    "flow_state_get": capability_flow_state_get,
    "flow_state_put": capability_flow_state_put,
    "flow_state_append_step": capability_flow_state_append_step,
    "lock_acquire": capability_lock_acquire,
    "lock_release": capability_lock_release,
    "retry_queue": capability_retry_queue,
    "lock_recovery": capability_lock_recovery,
    "command_orchestrator": capability_command_orchestrator,
    "event_engine": capability_event_engine,
    "chain_demo": capability_chain_demo,
    "planner_demo": capability_planner_demo,
    "decision_demo": capability_decision_demo,
    "decision_router": capability_decision_router,
    "complete_flow": capability_complete_flow,
    "complete_flow_demo": capability_complete_flow_demo,
    "incident_router": capability_incident_router,
    "retry_router": capability_retry_router,
    "retry_router": capability_retry_router_wrapped,
    "decision_router": capability_decision_router_wrapped,
    "incident_router": capability_incident_router_wrapped,
    "sla_router": capability_sla_router,
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
       "internal_scheduler_enabled": INTERNAL_SCHEDULER_ENABLED,
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

    if not INTERNAL_SCHEDULER_ENABLED:
        issues.append("internal_scheduler_disabled")

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

    return {
        "ok": True,
        "score": max(0, score),
        "issues": issues,
        "ts": utc_now_iso(),
    }

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
    limit = _safe_limit(limit, default=50, minimum=1, maximum=100)

    formula = "OR({Status_select}='New',{Status_select}='Queued',{Status}='New',{Status}='Queued')"
    view_name = (EVENTS_VIEW_NAME or "Queue").strip()

    try:
        records = airtable_list_filtered(
            EVENTS_TABLE_NAME,
            formula=formula,
            view_name=view_name,
            max_records=limit,
        )
        meta = {
            "ok": True,
            "table": EVENTS_TABLE_NAME,
            "view": view_name,
            "mode": "formula_plus_view",
            "formula": formula,
        }
    except Exception as e:
        try:
            records = airtable_list_view(
                EVENTS_TABLE_NAME,
                view_name,
                max_records=limit,
            )
            meta = {
                "ok": True,
                "table": EVENTS_TABLE_NAME,
                "view": view_name,
                "mode": "view_fallback",
                "formula": formula,
                "warning": repr(e),
            }
        except Exception as e2:
            records = []
            meta = {
                "ok": False,
                "table": EVENTS_TABLE_NAME,
                "view": view_name,
                "mode": "read_failed",
                "formula": formula,
                "error": repr(e2),
                "previous_error": repr(e),
            }
    print(f"[events/process] fetched={len(records)} meta={meta}")

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

        print(
            f"[events/process] handling event_id={event_id} "
            f"status={status} "
            f"mapped={fields.get('Mapped_Capability')} "
            f"name={fields.get('Name')}"
        )

        res = _create_command_from_event(event_record)

        if res.get("ok"):
            created += 1
            print(f"[events/process] success event_id={event_id} res={res}")
            continue

        error_code = str(res.get("error") or "")

        if error_code.startswith("legacy_or_disallowed_capability:"):
            skipped += 1
            errors.append(f"{event_id}: {error_code}")
            print(f"[events/process] ignored event_id={event_id} res={res}")
            continue

        failed += 1
        errors.append(f"{event_id}: {error_code or 'event_processing_failed'}")
        print(f"[events/process] failed event_id={event_id} res={res}")

        _event_mark_error(event_id, error_code or "event_processing_failed")

    result = {
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

    print(f"[events/process] result={result}")
    return result
    
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
            finish_system_run(
                run_record_id,
                "Unsupported",
                {"ok": False, "error": "unsupported_capability"},
            )
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported capability: {req.capability}",
            )

        result_obj = fn(req, run_record_id)

        next_cmds = result_obj.get("next_commands") if isinstance(result_obj, dict) else None

        if isinstance(next_cmds, list) and next_cmds:
            spawned_results = []

            for cmd in next_cmds:
                try:
                    spawn_res = _create_command_from_next_command(
                        next_cmd=cmd,
                        parent_run_id=run_record_id,
                        workspace_id=getattr(req, "workspace_id", None),
                    )
                    spawned_results.append(spawn_res)

                    print(
                        "[worker.spawn] next_command -> command",
                        {
                            "capability": cmd.get("capability"),
                            "ok": spawn_res.get("ok"),
                            "mode": spawn_res.get("mode"),
                            "command_record_id": spawn_res.get("command_record_id"),
                        },
                    )
                except Exception as e:
                    err = {
                        "ok": False,
                        "error": repr(e),
                        "capability": cmd.get("capability") if isinstance(cmd, dict) else None,
                    }
                    spawned_results.append(err)
                    print("[worker.spawn] failed to create command:", err)

            result_obj["spawn_summary"] = {
                "ok": all(bool(x.get("ok")) for x in spawned_results) if spawned_results else True,
                "spawned": len([x for x in spawned_results if x.get("ok")]),
                "failed": len([x for x in spawned_results if not x.get("ok")]),
                "results": spawned_results,
            }

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
    
@app.post("/internal/escalate")
async def internal_escalate(request: Request) -> Dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be an object.")

    return {
        "ok": True,
        "message": "incident_escalated",
        "received": payload,
        "ts": utc_now_iso(),
    }

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

