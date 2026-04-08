# app/worker.py — BOSAI Worker rebuilt
import hashlib
import hmac
import ast
import json
import os
import threading
import time
import traceback
import uuid
import smtplib

print("WORKER_MAIN_FILE_MARKER")

from dotenv import load_dotenv

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests
from fastapi import FastAPI, HTTPException, Request, Response, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.capabilities.commands_tick import run as capability_commands_tick
from app.capabilities.escalation_dispatch import capability_escalation_dispatch
from app.capabilities.health_tick import run as capability_health_tick
from app.capabilities.http_exec import capability_http_exec
from app.policies import get_policies
from app.capabilities.internal_escalate import capability_internal_escalate
from app.capabilities.incident_router_v2 import run as capability_incident_router_v2

from app.capabilities.retry_router import run as capability_retry_router_run
from app.capabilities.incident_create import run as capability_incident_create
from app.capabilities.complete_flow_incident import run as capability_complete_flow_incident
from app.capabilities.incident_deduplicate import run as capability_incident_deduplicate
from app.capabilities.incident_update import run as capability_incident_update
from app.capabilities.resolve_incident import run as capability_resolve_incident
from app.capabilities.close_incident import run as capability_close_incident
from app.capabilities.smart_resolve import run as capability_smart_resolve


# ============================================================
# MULTI-TENANT PATCH
# ============================================================

def _normalize_workspace_id(value: Any) -> str:
    text = str(value or "").strip()
    return text or WORKSPACE_DEFAULT_ID


def _extract_workspace_id(payload: Optional[Dict[str, Any]] = None, request: Optional[Request] = None) -> str:
    payload = payload or {}

    candidates = [
        payload.get("workspace_id"),
        payload.get("workspaceId"),
        payload.get("Workspace_ID"),
    ]

    if request is not None:
        candidates.extend(
            [
                request.headers.get("x-workspace-id"),
                request.headers.get("x-bosai-workspace"),
                request.query_params.get("workspace_id"),
            ]
        )

    for candidate in candidates:
        normalized = _normalize_workspace_id(candidate)
        if normalized:
            return normalized

    return WORKSPACE_DEFAULT_ID


def _inject_workspace(payload: Optional[Dict[str, Any]], workspace_id: str) -> Dict[str, Any]:
    obj = dict(payload or {})
    obj["workspace_id"] = _normalize_workspace_id(workspace_id)
    return obj


def _inject_workspace_into_next_commands(next_commands: Any, workspace_id: str) -> List[Dict[str, Any]]:
    ws = _normalize_workspace_id(workspace_id)
    output: List[Dict[str, Any]] = []

    if not isinstance(next_commands, list):
        return output

    for item in next_commands:
        if not isinstance(item, dict):
            continue

        cloned = dict(item)
        input_payload = cloned.get("input")

        if isinstance(input_payload, dict):
            cloned["input"] = _inject_workspace(input_payload, ws)
        else:
            cloned["input"] = {"workspace_id": ws}

        if not cloned.get("workspace_id"):
            cloned["workspace_id"] = ws

        output.append(cloned)

    return output


def _inject_workspace_into_result(result_obj: Optional[Dict[str, Any]], workspace_id: str) -> Dict[str, Any]:
    obj = dict(result_obj or {})
    obj["workspace_id"] = _normalize_workspace_id(workspace_id)

    if "next_commands" in obj:
        obj["next_commands"] = _inject_workspace_into_next_commands(obj.get("next_commands"), workspace_id)

    return obj


def _workspace_keys_map() -> Dict[str, str]:
    """
    Format env:
    BOSAI_WORKSPACE_API_KEYS="default:key-default,production:key-prod,clientA:key-123"
    """
    raw = WORKSPACE_API_KEYS_RAW
    result: Dict[str, str] = {}

    if not raw:
        return result

    for chunk in raw.split(","):
        part = chunk.strip()
        if not part or ":" not in part:
            continue
        ws, key = part.split(":", 1)
        ws = _normalize_workspace_id(ws)
        key = str(key or "").strip()
        if ws and key:
            result[ws] = key

    return result


def _validate_workspace_api_key(request: Request, workspace_id: str) -> None:
    mapping = _workspace_keys_map()
    if not mapping:
        return

    expected = mapping.get(_normalize_workspace_id(workspace_id))
    if not expected:
        return

    provided = (request.headers.get(WORKSPACE_API_KEY_HEADER) or "").strip()
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="invalid workspace api key")


def _workspace_matches_record(record_fields: Dict[str, Any], workspace_id: Optional[str]) -> bool:
    if not workspace_id:
        return True

    target = _normalize_workspace_id(workspace_id)
    current = _normalize_workspace_id(
        record_fields.get("Workspace_ID")
        or record_fields.get("workspace_id")
        or record_fields.get("WorkspaceId")
    )
    return current == target


def _fields_with_workspace(fields: Optional[Dict[str, Any]], workspace_id: str) -> Dict[str, Any]:
    obj = dict(fields or {})
    obj["Workspace_ID"] = _normalize_workspace_id(workspace_id)
    return obj


# ============================================================
# WORKSPACES REGISTRY PATCH
# ============================================================

def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _parse_allowed_capabilities(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [_safe_str(v) for v in value if _safe_str(v)]

    text = _safe_str(value)
    if not text:
        return []

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [_safe_str(v) for v in parsed if _safe_str(v)]
    except Exception:
        pass

    return [_safe_str(v) for v in text.split(",") if _safe_str(v)]


def _airtable_list_records_raw(
    table_name: str,
    view: Optional[str] = None,
    formula: Optional[str] = None,
    max_records: int = 100,
) -> List[Dict[str, Any]]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID or not table_name:
        return []

    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{quote(table_name)}"
    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }

    params: Dict[str, Any] = {"pageSize": min(max_records, 100)}
    if view:
        params["view"] = view
    if formula:
        params["filterByFormula"] = formula

    out: List[Dict[str, Any]] = []
    offset = None

    while True:
        local_params = dict(params)
        if offset:
            local_params["offset"] = offset

        resp = requests.get(url, headers=headers, params=local_params, timeout=20)
        if resp.status_code >= 400:
            print(f"[AIRTABLE] list raw failed table={table_name} status={resp.status_code} body={resp.text[:500]}")
            return out

        data = resp.json()
        records = data.get("records", []) or []
        out.extend(records)

        offset = data.get("offset")
        if not offset:
            break

    return out


def _get_workspace_record_by_id(workspace_id: str) -> Optional[Dict[str, Any]]:
    ws = _normalize_workspace_id(workspace_id)

    records = _airtable_list_records_raw(
        WORKSPACES_TABLE_NAME,
        view=WORKSPACES_VIEW_NAME or None,
        max_records=100,
    )

    for record in records:
        fields = record.get("fields", {}) or {}
        current = _normalize_workspace_id(fields.get("Workspace_ID"))
        if current == ws:
            return record

    return None


def _get_workspace_config(workspace_id: str) -> Dict[str, Any]:
    ws = _normalize_workspace_id(workspace_id)
    record = _get_workspace_record_by_id(ws)

    if not record:
        return {
            "exists": False,
            "workspace_id": ws,
            "status": "",
            "api_key": "",
            "allowed_capabilities": [],
            "record_id": "",
        }

    fields = record.get("fields", {}) or {}

    return {
        "exists": True,
        "record_id": record.get("id", ""),
        "workspace_id": _normalize_workspace_id(fields.get("Workspace_ID")),
        "name": _safe_str(fields.get("Name")),
        "status": _safe_str(fields.get("Status_select")).lower(),
        "api_key": _safe_str(fields.get("API_Key")),
        "plan": _safe_str(fields.get("Plan")).lower(),
        "owner_email": _safe_str(fields.get("Owner_Email")),
        "allowed_capabilities": _parse_allowed_capabilities(fields.get("Allowed_Capabilities")),
    }


def _workspace_is_active(config: Dict[str, Any]) -> bool:
    status = _safe_str(config.get("status")).lower()
    return status in ("active", "")


def _validate_workspace_from_registry(request: Request, workspace_id: str, capability: Optional[str] = None) -> Dict[str, Any]:
    ws = _normalize_workspace_id(workspace_id)
    config = _get_workspace_config(ws)

    if not config.get("exists"):
        raise HTTPException(status_code=404, detail=f"workspace not found: {ws}")

    if not _workspace_is_active(config):
        raise HTTPException(status_code=403, detail=f"workspace not active: {ws}")

    expected_key = _safe_str(config.get("api_key"))
    provided_key = _safe_str(request.headers.get("x-bosai-key"))

    if expected_key:
        if not provided_key or not hmac.compare_digest(provided_key, expected_key):
            raise HTTPException(status_code=401, detail="invalid workspace api key")

    allowed = config.get("allowed_capabilities") or []
    if capability and allowed:
        if capability not in allowed:
            raise HTTPException(status_code=403, detail=f"capability not allowed for workspace: {capability}")

    return config


def _touch_workspace_last_seen(workspace_id: str) -> None:
    ws = _normalize_workspace_id(workspace_id)
    config = _get_workspace_config(ws)
    record_id = _safe_str(config.get("record_id"))
    if not record_id:
        return

    try:
        airtable_update(
            WORKSPACES_TABLE_NAME,
            record_id,
            {
                "Last_Seen_At": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception as e:
        print(f"[workspace] touch last seen failed ws={ws} err={e}")
        
# WORKSPACES REGISTRY PATCH helper

def _generate_workspace_api_key() -> str:
    return f"bosai_{uuid.uuid4().hex}{uuid.uuid4().hex[:8]}"

def _generate_workspace_id_from_name(name: str) -> str:
    base = _safe_str(name).lower()
    allowed = []
    for ch in base:
        if ch.isalnum():
            allowed.append(ch)
        elif ch in (" ", "-", "_"):
            allowed.append("-")
    slug = "".join(allowed).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or f"workspace-{uuid.uuid4().hex[:8]}"


# ============================================================
# Env / settings
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, "..", ".env"), override=True)

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()

LEADS_TABLE_NAME = os.getenv("LEADS_TABLE_NAME", "Leads").strip()
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


WORKSPACE_DEFAULT_ID = os.getenv("BOSAI_DEFAULT_WORKSPACE_ID", "default").strip() or "default"
WORKSPACE_API_KEYS_RAW = os.getenv("BOSAI_WORKSPACE_API_KEYS", "").strip()
WORKSPACE_API_KEY_HEADER = "x-bosai-key"
WORKSPACES_TABLE_NAME = os.getenv("WORKSPACES_TABLE_NAME", "Workspaces").strip()
WORKSPACES_VIEW_NAME = os.getenv("WORKSPACES_VIEW_NAME", "").strip()


INCIDENTS_TABLE_NAME = os.getenv("INCIDENTS_TABLE_NAME", "Incidents").strip()
INCIDENTS_VIEW_NAME = os.getenv("INCIDENTS_VIEW_NAME", "Active").strip()

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
@app.post("/send-lead-email")
async def send_lead_email(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be an object")

    lead_email = str(payload.get("lead_email") or "").strip()
    lead_name = str(payload.get("lead_name") or "").strip()

    if not lead_email:
        raise HTTPException(status_code=400, detail="lead_email is required")

    from_name = os.getenv("SMTP_FROM_NAME", "").strip() or "Ferrera"

    subject = "Nous avons bien reçu votre demande"
    body = (
        f"Bonjour {lead_name or ''},\n\n"
        f"Nous avons bien reçu votre demande.\n"
        f"Notre équipe reviendra vers vous rapidement.\n\n"
        f"Cordialement,\n"
        f"{from_name}"
    )

    result = send_email_smtp(lead_email, subject, body)

    return {
        "ok": result["ok"],
        "message": "email_sent_real" if result["ok"] else "email_failed",
        "error": result.get("error"),
        "received": payload,
        "ts": utc_now_iso(),
    }
    
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
                import traceback
                SCHEDULER_LAST_ERROR = f"event_engine: {repr(e)}"
                if evt_run_record_id:
                    try:
                        fail_system_run(evt_run_record_id, repr(e))
                    except Exception:
                        pass
                print("[scheduler] event_engine error:", repr(e))
                traceback.print_exc()

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
                import traceback
                SCHEDULER_LAST_ERROR = f"command_orchestrator: {repr(e)}"
                if cmd_run_record_id:
                    try:
                        fail_system_run(cmd_run_record_id, repr(e))
                    except Exception:
                        pass
                print("[scheduler] command_orchestrator error:", repr(e))
                traceback.print_exc()

            time.sleep(10)

        except Exception as e:
            import traceback
            SCHEDULER_LAST_ERROR = f"scheduler_crash: {repr(e)}"
            print("[scheduler] crash:", repr(e))
            traceback.print_exc()
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


def _airtable_create(table_name: str, fields: Dict[str, Any]) -> str:
    url = _airtable_url(table_name)
    headers = _airtable_headers()

    r = requests.post(
        url,
        headers=headers,
        json={"fields": fields},
        timeout=HTTP_TIMEOUT_SECONDS,
    )

    print(f"[AIRTABLE] create = {table_name} ({r.status_code})")

    if r.status_code >= 300:
        raise HTTPException(
            status_code=500,
            detail=f"Airtable create failed: {r.status_code} {r.text}",
        )

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
        params={
            "filterByFormula": formula,
            "maxRecords": str(max_records),
        },
        timeout=HTTP_TIMEOUT_SECONDS,
    )

    if r.status_code >= 300:
        raise HTTPException(
            status_code=500,
            detail=f"Airtable search failed: {r.status_code} {r.text}",
        )

    records = r.json().get("records", [])
    return records[0] if records else None

def airtable_find_lead_by_id(lead_id: str) -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise RuntimeError("Airtable is not configured")

    lead_id = str(lead_id or "").strip()
    if not lead_id:
        return {}

    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{quote('Leads')}"
    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }
    params = {
        "filterByFormula": f"{{Lead_ID}}='{lead_id}'",
        "maxRecords": 1,
    }

    resp = requests.get(url, headers=headers, params=params, timeout=20)

    if resp.status_code >= 400:
        raise RuntimeError(
            f"Airtable lead fetch failed status={resp.status_code} body={resp.text[:500]}"
        )

    data = resp.json()
    records = data.get("records", []) or []

    if not records:
        return {}

    return records[0]
    
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

def airtable_list_records(
    table_name: str,
    *,
    view: Optional[str] = None,
    formula: Optional[str] = None,
    max_records: int = 100,
) -> List[Dict[str, Any]]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        return []

    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{quote(table_name)}"
    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
    }

    params: Dict[str, Any] = {
        "maxRecords": max_records,
    }
    if view:
        params["view"] = view
    if formula:
        params["filterByFormula"] = formula

    out: List[Dict[str, Any]] = []
    offset: Optional[str] = None

    while True:
        req_params = dict(params)
        if offset:
            req_params["offset"] = offset

        resp = requests.get(url, headers=headers, params=req_params, timeout=20)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Airtable list failed table={table_name} status={resp.status_code} body={resp.text[:500]}"
            )

        data = resp.json()
        records = data.get("records", [])
        if isinstance(records, list):
            out.extend(records)

        offset = data.get("offset")
        if not offset or len(out) >= max_records:
            break

    return out[:max_records]



def airtable_update_lead_by_lead_id(lead_id: str, fields_to_update: Dict[str, Any]) -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise RuntimeError("Airtable is not configured")

    lead_id = str(lead_id or "").strip()
    if not lead_id:
        raise RuntimeError("lead_id is required")

    record = airtable_find_first(
        table_name=LEADS_TABLE_NAME,
        filter_formula=f"{{Lead_ID}}='{lead_id}'",
    )

    if not record:
        raise RuntimeError(f"Lead not found for Lead_ID={lead_id}")

    record_id = record.get("id")
    if not record_id:
        raise RuntimeError("Lead record missing Airtable id")

    return airtable_update(LEADS_TABLE_NAME, record_id, fields_to_update)

def capability_send_lead_email(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})

    workspace_id = _resolve_workspace_id(req=req)
    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = _resolve_flow_step_index(payload, 0)

    lead_id = str(payload.get("lead_id") or "").strip()
    lead_name = str(payload.get("lead_name") or "").strip()
    lead_email = str(payload.get("lead_email") or "").strip()
    lead_status = str(payload.get("lead_status") or "").strip()
    action = str(payload.get("action") or "first_contact_attempt").strip()

    if not lead_id:
        raise HTTPException(status_code=400, detail="send_lead_email missing lead_id")

    if not lead_email:
        raise HTTPException(status_code=400, detail="send_lead_email missing lead_email")

    from_name = os.getenv("SMTP_FROM_NAME", "").strip() or "Ferrera"

    subject = "Nous avons bien reçu votre demande"
    body = (
        f"Bonjour {lead_name or ''},\n\n"
        f"Nous avons bien reçu votre demande.\n"
        f"Notre équipe reviendra vers vous rapidement.\n\n"
        f"Cordialement,\n"
        f"{from_name}"
    )

    smtp_result = send_email_smtp(lead_email, subject, body)

    attempted_at = utc_now_iso()

    if smtp_result.get("ok"):
        update_fields = {
            "Contact_Status": "Contacted",
            "Last_Contact_Attempt_At": attempted_at,
            "Last_Contact_Error": "",
            "Last_Contact_Run_ID": run_record_id,
        }

        try:
            airtable_update_lead_by_lead_id(lead_id, update_fields)
        except Exception as e:
            return {
                "ok": False,
                "message": "lead_email_sent_but_lead_update_failed",
                "error": str(e),
                "lead_id": lead_id,
                "lead_email": lead_email,
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "step_index": step_index,
                "terminal": True,
                "run_record_id": run_record_id,
            }

        return {
            "ok": True,
            "message": "lead_email_sent",
            "lead_id": lead_id,
            "lead_email": lead_email,
            "lead_status_before": lead_status,
            "contact_status_after": "Contacted",
            "action": action,
            "workspace_id": workspace_id,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "step_index": step_index,
            "terminal": True,
            "run_record_id": run_record_id,
        }

    error_text = str(smtp_result.get("error") or "unknown_email_error")

    try:
        airtable_update_lead_by_lead_id(
            lead_id,
            {
                "Contact_Status": "Email Failed",
                "Last_Contact_Attempt_At": attempted_at,
                "Last_Contact_Error": error_text,
                "Last_Contact_Run_ID": run_record_id,
            },
        )
    except Exception:
        pass

    return {
        "ok": False,
        "message": "lead_email_failed",
        "error": error_text,
        "lead_id": lead_id,
        "lead_email": lead_email,
        "lead_status_before": lead_status,
        "contact_status_after": "Email Failed",
        "action": action,
        "workspace_id": workspace_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "step_index": step_index,
        "terminal": True,
        "run_record_id": run_record_id,
    }

def _json_load_maybe(val: Any) -> Dict[str, Any]:
    if val is None:
        return {}

    if isinstance(val, dict):
        return val

    if isinstance(val, list):
        if val and isinstance(val[0], dict):
            return val[0]
        return {}

    s = str(val).strip()
    if not s:
        return {}

    candidates = [s]

    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        inner = s[1:-1].strip()
        if inner:
            candidates.append(inner)

    try:
        decoded = bytes(s, "utf-8").decode("unicode_escape").strip()
        if decoded:
            candidates.append(decoded)
    except Exception:
        pass

    fixed = s.replace('\\"', '"').strip()
    if fixed:
        candidates.append(fixed)

    def _unwrap_string_json(parsed: Any) -> Dict[str, Any]:
        current = parsed
        for _ in range(3):
            if isinstance(current, dict):
                return current
            if not isinstance(current, str):
                return {}
            inner = current.strip()
            if not inner:
                return {}
            try:
                current = json.loads(inner)
                continue
            except Exception:
                pass
            try:
                current = ast.literal_eval(inner)
                continue
            except Exception:
                return {}
        return current if isinstance(current, dict) else {}

    seen = set()

    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)

        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(candidate)
                out = _unwrap_string_json(parsed)
                if out:
                    return out
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass

    print("[_json_load_maybe] JSON PARSE FAILED:", s[:1000], flush=True)
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

    event_id = str(
        normalized.get("event_id")
        or normalized.get("eventid")
        or normalized.get("eventId")
        or normalized.get("Event_ID")
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

    source_event_id = str(
        normalized.get("source_event_id")
        or normalized.get("sourceeventid")
        or normalized.get("sourceEventId")
        or normalized.get("Source_Event_ID")
        or normalized.get("SourceEventId")
        or event_id
        or root_event_id
        or ""
    ).strip()

    workspace_id = str(
        normalized.get("workspace_id")
        or normalized.get("workspaceid")
        or normalized.get("workspaceId")
        or normalized.get("Workspace_ID")
        or normalized.get("workspace")
        or ""
    ).strip()

    run_record_id = str(
        normalized.get("run_record_id")
        or normalized.get("runrecordid")
        or normalized.get("runRecordId")
        or normalized.get("Run_Record_ID")
        or normalized.get("linked_run")
        or normalized.get("linkedrun")
        or normalized.get("Linked_Run")
        or ""
    ).strip()

    parent_command_id = str(
        normalized.get("parent_command_id")
        or normalized.get("parentcommandid")
        or normalized.get("parentCommandId")
        or normalized.get("Parent_Command_ID")
        or ""
    ).strip()

    command_id = str(
        normalized.get("command_id")
        or normalized.get("commandid")
        or normalized.get("commandId")
        or normalized.get("Command_ID")
        or ""
    ).strip()

    goal = str(
        normalized.get("goal")
        or normalized.get("Goal")
        or ""
    ).strip()

    raw_step_index = (
        normalized.get("step_index")
        if normalized.get("step_index") is not None
        else normalized.get("stepindex")
        if normalized.get("stepindex") is not None
        else normalized.get("stepIndex")
        if normalized.get("stepIndex") is not None
        else normalized.get("Step_Index")
        if normalized.get("Step_Index") is not None
        else normalized.get("StepIndex")
    )

    step_index = 0
    try:
        if raw_step_index is not None and str(raw_step_index).strip() != "":
            step_index = int(raw_step_index)
    except Exception:
        step_index = 0

    # ---------------------------------
    # canonical values
    # ---------------------------------
    if not root_event_id and event_id:
        root_event_id = event_id

    if not source_event_id:
        source_event_id = event_id or root_event_id

    if not event_id:
        event_id = source_event_id or root_event_id

    if flow_id:
        normalized["flow_id"] = flow_id

    if event_id:
        normalized["event_id"] = event_id

    if root_event_id:
        normalized["root_event_id"] = root_event_id

    if source_event_id:
        normalized["source_event_id"] = source_event_id

    if workspace_id:
        normalized["workspace_id"] = workspace_id
        normalized["workspace"] = workspace_id

    if run_record_id:
        normalized["run_record_id"] = run_record_id
        normalized["linked_run"] = run_record_id

    if parent_command_id:
        normalized["parent_command_id"] = parent_command_id

    if command_id:
        normalized["command_id"] = command_id

    if goal:
        normalized["goal"] = goal

    normalized["step_index"] = step_index

    # ---------------------------------
    # cleanup legacy aliases
    # ---------------------------------
    for legacy_key in (
        "flowid",
        "flowId",
        "Flow_ID",
        "FlowId",
        "eventid",
        "eventId",
        "Event_ID",
        "rooteventid",
        "rootEventId",
        "root_eventid",
        "Root_Event_ID",
        "RootEventId",
        "sourceeventid",
        "sourceEventId",
        "Source_Event_ID",
        "SourceEventId",
        "workspaceid",
        "workspaceId",
        "Workspace_ID",
        "runrecordid",
        "runRecordId",
        "Run_Record_ID",
        "linkedrun",
        "Linked_Run",
        "parentcommandid",
        "parentCommandId",
        "Parent_Command_ID",
        "commandid",
        "commandId",
        "Command_ID",
        "stepindex",
        "stepIndex",
        "Step_Index",
        "StepIndex",
        "Goal",
    ):
        normalized.pop(legacy_key, None)

    return normalized

def _resolve_flow_step_index(payload: Dict[str, Any], default: int = 0) -> int:
    if not isinstance(payload, dict):
        return default

    raw_value = (
        payload.get("step_index")
        if payload.get("step_index") is not None
        else payload.get("stepindex")
        if payload.get("stepindex") is not None
        else payload.get("stepIndex")
        if payload.get("stepIndex") is not None
        else payload.get("Step_Index")
        if payload.get("Step_Index") is not None
        else payload.get("StepIndex")
    )

    try:
        if raw_value is None or str(raw_value).strip() == "":
            return default
        return int(raw_value)
    except Exception:
        return default

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
    parsed_sources: Dict[str, Dict[str, Any]] = {}
    base: Dict[str, Any] = {}
    parse_errors: List[Dict[str, Any]] = []

    def _pick(*values: Any) -> str:
        for value in values:
            if value is None:
                continue

            if isinstance(value, list):
                for item in value:
                    text = str(item or "").strip()
                    if text:
                        return text
                continue

            text = str(value or "").strip()
            if text:
                return text
        return ""

    def _merge_if_missing(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in source.items():
            if k not in target or target.get(k) in ("", None, {}, []):
                target[k] = v
        return target

    def _extract_scalar(value: Any) -> Any:
        current = value
        for _ in range(3):
            if isinstance(current, list):
                next_value = None
                for item in current:
                    if item not in (None, "", {}, []):
                        next_value = item
                        break
                current = next_value
                continue
            if isinstance(current, tuple):
                current = list(current)
                continue
            break
        return current

    def _textify(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8", errors="ignore").strip()
            except Exception:
                return str(value).strip()
        return str(value).strip()

    def _parse_candidate(raw_val: Any, source_key: str) -> Dict[str, Any]:
        if raw_val is None:
            return {}

        raw_val = _extract_scalar(raw_val)
        if raw_val is None:
            return {}

        if isinstance(raw_val, dict):
            parsed = dict(raw_val)
        else:
            raw_text = _textify(raw_val)
            if not raw_text:
                return {}

            parsed = _json_load_maybe(raw_text)

            if not isinstance(parsed, dict) or not parsed:
                try:
                    literal = ast.literal_eval(raw_text)
                    literal = _extract_scalar(literal)

                    if isinstance(literal, dict):
                        parsed = dict(literal)
                    else:
                        literal_text = _textify(literal)
                        if literal_text:
                            parsed = _json_load_maybe(literal_text)
                except Exception:
                    pass

            if not isinstance(parsed, dict) or not parsed:
                parse_errors.append(
                    {
                        "source": source_key,
                        "error": "json_parse_failed",
                        "raw_preview": raw_text[:500],
                    }
                )
                return {}

        parsed = _normalize_keys_deep(parsed)
        parsed = _unwrap_command_payload(parsed)

        if isinstance(parsed.get("input"), dict) and parsed.get("input"):
            nested = dict(parsed.get("input") or {})
            for k, v in parsed.items():
                if k != "input" and k not in nested:
                    nested[k] = v
            parsed = nested

        parsed = _normalize_keys_deep(parsed)
        parsed = _unwrap_command_payload(parsed)
        parsed = _normalize_flow_keys(parsed)

        return parsed if isinstance(parsed, dict) else {}

    def _pick_from_dicts(dicts: List[Dict[str, Any]], *keys: str, default: Any = "") -> Any:
        for data in dicts:
            if not isinstance(data, dict):
                continue
            for key in keys:
                if key in data:
                    value = data.get(key)
                    if value not in (None, "", {}, []):
                        return value
        return default

    source_priority = (
        "Input_JSON",
        "Command_Input_JSON",
        "Command_JSON",
        "Payload_JSON",
    )

    for source_key in source_priority:
        parsed_sources[source_key] = _parse_candidate(fields.get(source_key), source_key)

    for source_key in source_priority:
        candidate = parsed_sources.get(source_key) or {}
        if candidate:
            base = dict(candidate)
            break

    for source_key in source_priority:
        candidate = parsed_sources.get(source_key) or {}
        if not candidate:
            continue
        base = _merge_if_missing(base, candidate)

    if not isinstance(base, dict):
        base = {}

    base = _normalize_keys_deep(base)
    base = _unwrap_command_payload(base)
    base = _normalize_flow_keys(base)

    original_input_obj = base.get("original_input") if isinstance(base.get("original_input"), dict) else {}
    if original_input_obj:
        original_input_obj = _normalize_keys_deep(dict(original_input_obj))
        original_input_obj = _unwrap_command_payload(original_input_obj)
        original_input_obj = _normalize_flow_keys(original_input_obj)

    body_obj = base.get("body") if isinstance(base.get("body"), dict) else {}
    if body_obj:
        body_obj = _normalize_keys_deep(dict(body_obj))
        body_obj = _unwrap_command_payload(body_obj)
        body_obj = _normalize_flow_keys(body_obj)

    request_obj = base.get("request") if isinstance(base.get("request"), dict) else {}
    if request_obj:
        request_obj = _normalize_keys_deep(dict(request_obj))

    response_obj = base.get("response") if isinstance(base.get("response"), dict) else {}
    if response_obj:
        response_obj = _normalize_keys_deep(dict(response_obj))

    search_dicts: List[Dict[str, Any]] = [
        base,
        original_input_obj,
        body_obj,
        request_obj,
        response_obj,
        parsed_sources.get("Input_JSON") or {},
        parsed_sources.get("Command_Input_JSON") or {},
        parsed_sources.get("Command_JSON") or {},
        parsed_sources.get("Payload_JSON") or {},
    ]

    flow_id = _pick(
        _pick_from_dicts(search_dicts, "flow_id", "flowid"),
        fields.get("Flow_ID"),
        fields.get("flow_id"),
        fields.get("flowid"),
    )

    root_event_id = _pick(
        _pick_from_dicts(search_dicts, "root_event_id", "rooteventid", "event_id", "eventid"),
        fields.get("Root_Event_ID"),
        fields.get("root_event_id"),
        fields.get("rooteventid"),
        fields.get("Event_ID"),
        fields.get("event_id"),
        flow_id,
    )

    source_event_id = _pick(
        _pick_from_dicts(search_dicts, "source_event_id", "sourceeventid", "event_id", "eventid"),
        fields.get("Source_Event_ID"),
        fields.get("source_event_id"),
        fields.get("sourceeventid"),
        fields.get("Event_ID"),
        fields.get("event_id"),
        root_event_id,
        flow_id,
    )

    workspace_id = _pick(
        _pick_from_dicts(search_dicts, "workspace_id", "workspaceid", "workspace"),
        fields.get("Workspace_ID"),
        fields.get("workspace_id"),
        fields.get("workspaceid"),
        "production",
    )

    run_record_id = _pick(
        _pick_from_dicts(search_dicts, "run_record_id", "runrecordid", "linked_run", "linkedrun"),
        fields.get("Run_Record_ID"),
        fields.get("run_record_id"),
        fields.get("Linked_Run"),
    )

    linked_run = _pick(
        _pick_from_dicts(search_dicts, "linked_run", "linkedrun", "run_record_id", "runrecordid"),
        fields.get("Linked_Run"),
        fields.get("Run_Record_ID"),
    )

    parent_command_id = _pick(
        _pick_from_dicts(search_dicts, "parent_command_id", "parentcommandid"),
        fields.get("Parent_Command_ID"),
        fields.get("parent_command_id"),
        fields.get("parentcommandid"),
    )

    command_id = _pick(
        _pick_from_dicts(search_dicts, "command_id", "commandid"),
        fields.get("Command_ID"),
        fields.get("command_id"),
        fields.get("commandid"),
    )

    step_index_candidate = _pick_from_dicts(search_dicts, "step_index", "stepindex", default=None)
    step_index = _to_int(
        step_index_candidate
        if step_index_candidate is not None
        else fields.get("Step_Index")
        if fields.get("Step_Index") is not None
        else fields.get("step_index")
        if fields.get("step_index") is not None
        else fields.get("stepindex"),
        0,
    )

    depth_candidate = _pick_from_dicts(search_dicts, "_depth", "depth", default=None)
    depth = _to_int(
        depth_candidate
        if depth_candidate is not None
        else fields.get("_depth")
        if fields.get("_depth") is not None
        else fields.get("Depth"),
        0,
    )

    url_value = _pick(
        _pick_from_dicts(
            search_dicts,
            "url",
            "http_target",
            "target_url",
            "failed_url",
            "URL",
        ),
        fields.get("http_target"),
        fields.get("Http_Target"),
        fields.get("URL"),
        fields.get("url"),
    )

    method_value = _pick(
        _pick_from_dicts(search_dicts, "method", "failed_method", "HTTP_Method", "Http_Method"),
        fields.get("HTTP_Method"),
        fields.get("Http_Method"),
        fields.get("method"),
        "GET",
    ).upper()

    if not method_value:
        method_value = "GET"

    headers_obj = base.get("headers") if isinstance(base.get("headers"), dict) else {}
    if not headers_obj:
        headers_obj = request_obj.get("headers") if isinstance(request_obj.get("headers"), dict) else {}
    if not headers_obj:
        maybe_headers = _json_load_maybe(fields.get("HTTP_Headers_JSON"))
        headers_obj = maybe_headers if isinstance(maybe_headers, dict) else {}

    json_obj = base.get("json") if isinstance(base.get("json"), dict) else {}
    if not json_obj and isinstance(body_obj.get("json"), dict):
        json_obj = dict(body_obj.get("json") or {})
    if not json_obj:
        maybe_json = _json_load_maybe(fields.get("JSON"))
        json_obj = maybe_json if isinstance(maybe_json, dict) else {}

    body_dict = body_obj if isinstance(body_obj, dict) else {}
    if not body_dict:
        maybe_body = _json_load_maybe(fields.get("HTTP_Payload_JSON"))
        body_dict = maybe_body if isinstance(maybe_body, dict) else {}

    if not request_obj:
        maybe_request = _json_load_maybe(fields.get("Request_JSON"))
        request_obj = maybe_request if isinstance(maybe_request, dict) else {}

    if not response_obj:
        maybe_response = _json_load_maybe(fields.get("Response_JSON"))
        response_obj = maybe_response if isinstance(maybe_response, dict) else {}

    base["flow_id"] = flow_id
    base["root_event_id"] = root_event_id
    base["source_event_id"] = source_event_id
    base["event_id"] = source_event_id or root_event_id or flow_id
    base["workspace_id"] = workspace_id
    base["workspace"] = workspace_id
    base["run_record_id"] = run_record_id
    base["linked_run"] = linked_run or run_record_id
    base["parent_command_id"] = parent_command_id
    base["command_id"] = command_id
    base["step_index"] = step_index
    base["_depth"] = depth
    base["method"] = method_value

    if url_value:
        base["url"] = url_value
        base["http_target"] = url_value
        if not _pick(base.get("target_url")):
            base["target_url"] = url_value

    if headers_obj:
        base["headers"] = headers_obj

    if json_obj:
        base["json"] = json_obj

    if body_dict:
        base["body"] = body_dict

    if request_obj:
        base["request"] = request_obj

    if response_obj:
        base["response"] = response_obj

    if original_input_obj:
        base["original_input"] = original_input_obj

    if not _pick(base.get("failed_method")):
        base["failed_method"] = method_value

    if url_value and not _pick(base.get("failed_url")):
        base["failed_url"] = url_value

    for src in (original_input_obj, body_dict, request_obj, response_obj):
        if not isinstance(src, dict) or not src:
            continue

        for k in (
            "goal",
            "failed_goal",
            "retry_reason",
            "reason",
            "failed_url",
            "failed_method",
            "original_capability",
            "source_capability",
            "failed_capability",
            "target_capability",
            "http_status",
            "status_code",
            "error",
            "error_message",
            "last_error",
            "request_error",
            "incident_code",
            "incident_message",
            "retry_count",
            "retry_max",
            "retry_delay_seconds",
            "next_retry_at",
            "max_depth",
        ):
            if base.get(k) in (None, "", {}, []) and src.get(k) not in (None, "", {}, []):
                base[k] = src.get(k)

    resp_status = None
    if isinstance(response_obj, dict) and response_obj:
        resp_status = response_obj.get("status_code")

    if base.get("http_status") in (None, "", {}, []) and resp_status not in (None, ""):
        base["http_status"] = resp_status

    if base.get("status_code") in (None, "", {}, []) and resp_status not in (None, ""):
        base["status_code"] = resp_status

    field_alias_map = {
        "goal": ("goal", "Goal", "failed_goal", "failedgoal", "Failed_Goal"),
        "reason": ("reason", "Reason", "retry_reason", "retryreason", "incident_code"),
        "retry_reason": ("retry_reason", "retryreason", "reason", "Reason", "incident_code"),
        "retry_count": ("retry_count", "retrycount", "Retry_Count"),
        "retry_max": ("retry_max", "retrymax", "Retry_Max"),
        "retry_delay_seconds": ("retry_delay_seconds", "retrydelayseconds", "Retry_Delay_Seconds"),
        "failed_goal": ("failed_goal", "failedgoal", "Failed_Goal", "goal", "Goal"),
        "failed_url": ("failed_url", "failedurl", "Failed_URL", "url", "URL", "http_target"),
        "failed_method": ("failed_method", "failedmethod", "Failed_Method", "method", "HTTP_Method"),
        "http_status": ("http_status", "httpstatus", "status_code", "statuscode", "HTTP_Status", "Response_Status"),
        "status_code": ("status_code", "statuscode", "http_status", "httpstatus", "HTTP_Status", "Response_Status"),
        "error": ("error", "Error", "last_error", "Last_Error", "Error_Message", "incident_code"),
        "error_message": ("error_message", "Error_Message", "Last_Error", "error"),
        "request_error": ("request_error", "Request_Error", "error_message", "last_error"),
        "original_capability": (
            "original_capability",
            "originalcapability",
            "source_capability",
            "sourcecapability",
            "failed_capability",
            "failedcapability",
        ),
        "source_capability": (
            "source_capability",
            "sourcecapability",
            "original_capability",
            "originalcapability",
            "failed_capability",
            "failedcapability",
        ),
        "failed_capability": (
            "failed_capability",
            "failedcapability",
            "source_capability",
            "sourcecapability",
            "original_capability",
            "originalcapability",
        ),
        "target_capability": ("target_capability", "targetcapability", "Mapped_Capability"),
        "incident_record_id": ("incident_record_id", "incidentrecordid", "Incident_Record_ID"),
        "next_retry_at": ("next_retry_at", "Next_Retry_At"),
        "max_depth": ("max_depth", "Max_Depth"),
    }

    for target_key, aliases in field_alias_map.items():
        if target_key in base and base.get(target_key) not in (None, "", {}, []):
            continue

        for alias in aliases:
            value = fields.get(alias)
            if value is not None and str(value).strip() != "":
                base[target_key] = value
                break

    if base.get("target_capability") in (None, "", {}, []):
        cap_value = fields.get("Capability")
        if cap_value is not None and str(cap_value).strip():
            base["target_capability"] = str(cap_value).strip()

    if base.get("retry_reason") in (None, "", {}, []):
        http_status = base.get("http_status")
        try:
            http_status_int = int(http_status) if http_status not in (None, "") else None
        except Exception:
            http_status_int = None

        if http_status_int is not None and 500 <= http_status_int <= 599:
            base["retry_reason"] = "http_status_error"

    if base.get("error") in (None, "", {}, []) and base.get("retry_reason") not in (None, "", {}, []):
        base["error"] = base.get("retry_reason")

    if base.get("reason") in (None, "", {}, []) and base.get("retry_reason") not in (None, "", {}, []):
        base["reason"] = base.get("retry_reason")

    for legacy_key in (
        "flowid",
        "flowId",
        "Flow_ID",
        "rooteventid",
        "rootEventId",
        "Root_Event_ID",
        "sourceeventid",
        "sourceEventId",
        "Source_Event_ID",
        "eventid",
        "eventId",
        "Event_ID",
        "workspaceid",
        "workspaceId",
        "Workspace_ID",
        "runrecordid",
        "Run_RecordId",
        "Run_Record_ID",
        "linkedrun",
        "Linked_Run",
        "parentcommandid",
        "parentCommandId",
        "Parent_Command_ID",
        "commandid",
        "commandId",
        "Command_ID",
        "stepindex",
        "stepIndex",
        "Step_Index",
        "depth",
        "httptarget",
        "Http_Target",
        "HTTP_Target",
        "HTTPMethod",
        "Http_Method",
    ):
        base.pop(legacy_key, None)

    base = _sanitize_payload_for_airtable(base)

    if parse_errors:
        print(
            f"[compose_command_input] parse_errors={json.dumps(parse_errors, ensure_ascii=False)}",
            flush=True,
        )

    print(
        f"[compose_command_input] final_base={json.dumps(base, ensure_ascii=False)}",
        flush=True,
    )
    return base
    
def airtable_create(table_name: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise RuntimeError("Airtable is not configured")

    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{quote(table_name)}"
    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {"fields": fields}

    resp = requests.post(url, headers=headers, json=payload, timeout=20)

    if resp.status_code >= 400:
        raise RuntimeError(
            f"Airtable create failed table={table_name} status={resp.status_code} body={resp.text[:500]}"
        )

    data = resp.json()
    print(f"[AIRTABLE] create = {table_name} ({resp.status_code})")
    return data


def airtable_update_by_field(
    table: str,
    field: str,
    value: Any,
    fields: Dict[str, Any],
) -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        raise RuntimeError("Airtable is not configured")

    safe_value = str(value).replace("'", "\\'")
    formula = f"{{{field}}}='{safe_value}'"

    records = airtable_list_filtered(
        table,
        formula=formula,
        max_records=1,
    )

    if not records:
        raise RuntimeError(
            f"Airtable update_by_field target not found table={table} field={field} value={value}"
        )

    record_id = str(records[0].get("id") or "").strip()
    if not record_id:
        raise RuntimeError(
            f"Airtable update_by_field missing record id table={table} field={field} value={value}"
        )

    safe_fields = dict(fields or {})

    # SAFE PATCH ciblé uniquement pour Monitored_Endpoints
    if table == "Monitored_Endpoints":
        safe_fields = _normalize_monitored_endpoints_fields(safe_fields)

    print(
        f"[airtable_update_by_field] table={table} field={field} value={value} safe_fields={safe_fields}",
        flush=True,
    )

    return airtable_update(table, record_id, safe_fields)
    
def _normalize_monitored_endpoints_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(fields, dict):
        return {}

    mapping = {
        "last_check_at": "last_check_at",
        "last_error": "last_error",
        "last_status": "Last_Status",
        "last_response_time_ms": "Last_Response_Time_ms",
        "last_run_id": "Last_Run_ID",
        "last_incident_id": "Last_Incident_ID",

        # tolérance si un autre bloc envoie déjà une autre casse
        "Last_Check_At": "last_check_at",
        "Last_Error": "last_error",
        "Last_Status": "Last_Status",
        "Last_Response_Time_ms": "Last_Response_Time_ms",
        "Last_Run_ID": "Last_Run_ID",
        "Last_Incident_ID": "Last_Incident_ID",
    }

    normalized: Dict[str, Any] = {}
    for k, v in fields.items():
        key = str(k).strip()
        normalized[mapping.get(key, key)] = v

    return normalized
    
def _monitoring_endpoint_to_api(record: Dict[str, Any]) -> Dict[str, Any]:
    fields = record.get("fields", {}) if isinstance(record, dict) else {}
    if not isinstance(fields, dict):
        fields = {}

    return {
        "record_id": str(record.get("id") or "").strip(),
        "name": str(fields.get("Name") or "").strip(),
        "workspace_id": str(fields.get("Workspace_ID") or "").strip(),
        "url": str(fields.get("URL") or "").strip(),
        "method": str(fields.get("Method") or "").strip().upper(),
        "expected_status": fields.get("Expected_Status"),
        "timeout_ms": fields.get("Timeout_ms"),
        "enabled": bool(fields.get("Enabled") in (True, 1, "1", "true", "True", "yes", "on")),
        "last_status": fields.get("Last_Status"),
        "last_error": str(fields.get("Last_Error") or "").strip(),
        "last_incident_id": str(fields.get("Last_Incident_ID") or "").strip(),
        "last_check_at": str(fields.get("Last_Check_At") or "").strip(),
        "last_response_time_ms": fields.get("Last_Response_Time_ms"),
        "last_run_id": str(fields.get("Last_Run_ID") or "").strip(),
    }
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

def resolve_workspace_from_headers(headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    api_key = (
        headers.get("x-bosai-key")
        or headers.get("x-api-key")
        or headers.get("x_api_key")
        or ""
    ).strip()

    if not api_key:
        return None

    try:
        records = airtable_list_filtered(
            WORKSPACES_TABLE_NAME,
            formula=f"{{API_Key}}='{api_key}'",
            max_records=1,
        )
    except Exception:
        return None

    if not records:
        return None

    return records[0]
    
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

def _compact_key_name(key: Any) -> str:
    text = str(key or "")
    return "".join(ch for ch in text if ch.isalnum()).lower()


def _has_meaningful_value(value: Any) -> bool:
    if value is None:
        return False
    if value == "":
        return False
    if value == []:
        return False
    if value == {}:
        return False
    return True


def _normalize_keys_deep(value: Any) -> Any:
    mapping = {
        "commandinput": "command_input",
        "targetcapability": "target_capability",
        "originalinput": "original_input",
        "retrycount": "retry_count",
        "retrymax": "retry_max",
        "stepindex": "step_index",
        "maxdepth": "max_depth",
        "workspaceid": "workspace_id",
        "rooteventid": "root_event_id",
        "sourceeventid": "source_event_id",
        "eventid": "event_id",
        "flowid": "flow_id",
        "incidentrecordid": "incident_record_id",
        "requesterror": "request_error",
        "httptarget": "http_target",
        "httpstatus": "http_status",
        "retryreason": "retry_reason",
        "errortype": "error_type",
        "parentcommandid": "parent_command_id",
        "statuscode": "status_code",
        "failedurl": "failed_url",
        "failedmethod": "failed_method",
        "failedgoal": "failed_goal",
        "originalcapability": "original_capability",
        "sourcecapability": "source_capability",
        "failedcapability": "failed_capability",
        "runrecordid": "run_record_id",
        "linkedrun": "linked_run",
        "commandid": "command_id",
        "decisionstatus": "decision_status",
        "decisionreason": "decision_reason",
        "nextaction": "next_action",
        "autoexecutable": "auto_executable",
        "priorityscore": "priority_score",
        "finalfailure": "final_failure",
        "incidentmessage": "incident_message",
        "incidentcode": "incident_code",
        "endpointname": "endpoint_name",
        "appname": "app_name",
        "tenantid": "tenant_id",
        "deduplicateaction": "deduplicate_action",
        "contenttype": "content_type",
        "bodytext": "body_text",
        "bodyjson": "body_json",
        "elapsedms": "elapsed_ms",
        "timeoutseconds": "timeout_seconds",
        "followredirects": "follow_redirects",
        "verifytls": "verify_tls",
        "urldebug": "url_debug",
        "resolvedips": "resolved_ips",
    }

    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}

        for k, v in value.items():
            raw_key = str(k)
            normalized_key = mapping.get(_compact_key_name(raw_key), raw_key)
            normalized_value = _normalize_keys_deep(v)

            if normalized_key not in normalized:
                normalized[normalized_key] = normalized_value
                continue

            existing_value = normalized[normalized_key]

            if isinstance(existing_value, dict) and isinstance(normalized_value, dict):
                merged: Dict[str, Any] = dict(existing_value)
                for mk, mv in normalized_value.items():
                    if mk not in merged:
                        merged[mk] = mv
                    elif not _has_meaningful_value(merged[mk]) and _has_meaningful_value(mv):
                        merged[mk] = mv
                normalized[normalized_key] = merged
                continue

            if not _has_meaningful_value(existing_value) and _has_meaningful_value(normalized_value):
                normalized[normalized_key] = normalized_value

        return normalized

    if isinstance(value, list):
        return [_normalize_keys_deep(item) for item in value]

    return value


def _sanitize_payload_for_airtable(value: Any) -> Any:
    cleaned = _normalize_keys_deep(value)

    if isinstance(cleaned, dict):
        cleaned = _unwrap_command_payload(cleaned)
        cleaned = _normalize_flow_keys(cleaned)

        for legacy_key in (
            "flowid",
            "flowId",
            "Flow_ID",
            "rooteventid",
            "rootEventId",
            "Root_Event_ID",
            "sourceeventid",
            "sourceEventId",
            "Source_Event_ID",
            "eventid",
            "eventId",
            "Event_ID",
            "workspaceid",
            "workspaceId",
            "Workspace_ID",
            "runrecordid",
            "runRecordId",
            "Run_Record_ID",
            "linkedrun",
            "Linked_Run",
            "parentcommandid",
            "parentCommandId",
            "Parent_Command_ID",
            "commandid",
            "commandId",
            "Command_ID",
            "stepindex",
            "stepIndex",
            "Step_Index",
            "httptarget",
            "Http_Target",
            "HTTP_Target",
            "httpstatus",
            "statuscode",
            "retryreason",
            "retrycount",
            "retrymax",
            "failedurl",
            "failedmethod",
            "failedgoal",
            "originalcapability",
            "originalinput",
        ):
            cleaned.pop(legacy_key, None)

        return {
            str(k): _sanitize_payload_for_airtable(v)
            for k, v in cleaned.items()
        }

    if isinstance(cleaned, list):
        return [_sanitize_payload_for_airtable(v) for v in cleaned]

    if isinstance(cleaned, tuple):
        return [_sanitize_payload_for_airtable(v) for v in cleaned]

    if isinstance(cleaned, datetime):
        return cleaned.isoformat()

    if isinstance(cleaned, (str, int, float, bool)) or cleaned is None:
        return cleaned

    try:
        json.dumps(cleaned, ensure_ascii=False)
        return cleaned
    except Exception:
        return str(cleaned)

def _unwrap_command_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    for nested_key in ("command_input", "commandinput", "input"):
        nested = payload.get(nested_key)
        if isinstance(nested, dict):
            merged = dict(nested)
            for k, v in payload.items():
                if k != nested_key and k not in merged:
                    merged[k] = v
            return merged

    return payload


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

def send_email_smtp(to_email: str, subject: str, body: str) -> dict:
    try:
        smtp_host = os.getenv("SMTP_HOST", "").strip()
        smtp_port = int(os.getenv("SMTP_PORT", "587").strip())
        smtp_user = os.getenv("SMTP_USERNAME", "").strip()
        smtp_pass = os.getenv("SMTP_PASSWORD", "").strip()
        smtp_from_email = os.getenv("SMTP_FROM_EMAIL", "").strip() or smtp_user

        msg = MIMEMultipart()
        msg["From"] = smtp_from_email
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain", "utf-8"))

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=20)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()

        return {"ok": True}

    except Exception as e:
        return {"ok": False, "error": str(e)}
        
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

            record_id = _airtable_create(table_name, fields)

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

    raw_input_payload = req.input if isinstance(req.input, dict) else {}
    input_payload = _sanitize_payload_for_airtable(raw_input_payload)

    workspace_id = str(
        input_payload.get("workspace_id")
        or _resolve_workspace_id(req=req)
        or "production"
    ).strip() or "production"

    flow_id = str(
        input_payload.get("flow_id")
        or ""
    ).strip()

    root_event_id = str(
        input_payload.get("root_event_id")
        or input_payload.get("event_id")
        or flow_id
        or ""
    ).strip()

    source_event_id = str(
        input_payload.get("source_event_id")
        or input_payload.get("event_id")
        or root_event_id
        or flow_id
        or ""
    ).strip()

    fields = {
        "Run_ID": run_uuid,
        "Worker": req.worker,
        "Capability": req.capability,
        "Idempotency_Key": req.idempotency_key,
        "Status_select": "Running",
        "Started_At": utc_now_iso(),
        "Priority": req.priority,
        "Dry_Run": bool(req.dry_run),
        "Input_JSON": json.dumps(input_payload, ensure_ascii=False),
        "App_Name": APP_NAME,
        "App_Version": APP_VERSION,
        "Workspace_ID": workspace_id,
    }

    if flow_id:
        fields["Flow_ID"] = flow_id

    if root_event_id:
        fields["Root_Event_ID"] = root_event_id

    if source_event_id:
        fields["Source_Event_ID"] = source_event_id

    record_id = _airtable_create(SYSTEM_RUNS_TABLE_NAME, fields)
    return record_id, run_uuid

def _extract_system_run_link_fields(result_obj: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(result_obj, dict):
        return {}

    incident_result = (
        result_obj.get("incident_result")
        if isinstance(result_obj.get("incident_result"), dict)
        else {}
    )

    def _pick(*values: Any) -> str:
        for value in values:
            text = str(value or "").strip()
            if text:
                return text
        return ""

    fields: Dict[str, Any] = {}

    workspace_id = _pick(
        result_obj.get("workspace_id"),
        result_obj.get("workspaceId"),
        result_obj.get("Workspace_ID"),
    )
    flow_id = _pick(
        result_obj.get("flow_id"),
        result_obj.get("flowId"),
        result_obj.get("Flow_ID"),
    )
    root_event_id = _pick(
        result_obj.get("root_event_id"),
        result_obj.get("rootEventId"),
        result_obj.get("Root_Event_ID"),
    )
    source_event_id = _pick(
        result_obj.get("source_event_id"),
        result_obj.get("sourceEventId"),
        result_obj.get("Source_Event_ID"),
        result_obj.get("event_id"),
        result_obj.get("eventId"),
    )
    linked_command = _pick(
        result_obj.get("linked_command"),
        result_obj.get("command_id"),
        incident_result.get("linked_command"),
        incident_result.get("command_id"),
    )
    linked_incident = _pick(
        result_obj.get("linked_incident"),
        result_obj.get("incident_id"),
        incident_result.get("linked_incident"),
        incident_result.get("incident_id"),
    )

    if workspace_id:
        fields["Workspace_ID"] = workspace_id
    if flow_id:
        fields["Flow_ID"] = flow_id
    if root_event_id:
        fields["Root_Event_ID"] = root_event_id
    if source_event_id:
        fields["Source_Event_ID"] = source_event_id
    if linked_command:
        fields["Linked_Command"] = linked_command
    if linked_incident:
        fields["Linked_Incident"] = linked_incident

    return fields


def finish_system_run(record_id: str, status: str, result_obj: Dict[str, Any]) -> None:
    base_fields = {
        "Status_select": status,
        "Finished_At": utc_now_iso(),
        "Result_JSON": json.dumps(result_obj, ensure_ascii=False),
    }

    linked_fields = _extract_system_run_link_fields(result_obj)
    enriched_fields = {
        **base_fields,
        **linked_fields,
    }

    try:
        airtable_update(
            SYSTEM_RUNS_TABLE_NAME,
            record_id,
            enriched_fields,
        )
    except Exception as e:
        print("[finish_system_run] enriched update fallback =", repr(e), flush=True)
        airtable_update(
            SYSTEM_RUNS_TABLE_NAME,
            record_id,
            base_fields,
        )


def fail_system_run(
    record_id: str,
    error_message: str,
    error_obj: Optional[Dict[str, Any]] = None,
) -> None:
    result_payload: Dict[str, Any] = (
        dict(error_obj) if isinstance(error_obj, dict) else {}
    )
    result_payload.setdefault("error", error_message)

    base_fields = {
        "Status_select": "Error",
        "Finished_At": utc_now_iso(),
        "Result_JSON": json.dumps(result_payload, ensure_ascii=False),
    }

    linked_fields = _extract_system_run_link_fields(result_payload)
    enriched_fields = {
        **base_fields,
        **linked_fields,
    }

    try:
        airtable_update(
            SYSTEM_RUNS_TABLE_NAME,
            record_id,
            enriched_fields,
        )
    except Exception as e:
        print("[fail_system_run] enriched update fallback =", repr(e), flush=True)
        airtable_update(
            SYSTEM_RUNS_TABLE_NAME,
            record_id,
            base_fields,
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

    rid = _airtable_create(STATE_TABLE_NAME, fields)
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
def _resolve_flow_context_from_command_input(command_input, fallback_command_id=""):
    if not isinstance(command_input, dict):
        command_input = {}

    flow_id = (
        _coerce_non_empty_str(command_input.get("flow_id"))
        or _coerce_non_empty_str(command_input.get("flowid"))
    )

    root_event_id = (
        _coerce_non_empty_str(command_input.get("root_event_id"))
        or _coerce_non_empty_str(command_input.get("rooteventid"))
    )

    if not flow_id and root_event_id:
        flow_id = root_event_id

    if not root_event_id and flow_id:
        root_event_id = flow_id

    if not flow_id:
        flow_id = fallback_command_id

    if not root_event_id:
        root_event_id = flow_id

    return flow_id, root_event_id


def _coerce_non_empty_str(value):
    if value is None:
        return ""
    return str(value).strip()

def process_events() -> Dict[str, Any]:
    fetched = fetch_events_source()  # garde ton appel existant
    source_meta = fetched.get("meta", {}) if isinstance(fetched, dict) else {}
    records = fetched.get("records", []) if isinstance(fetched, dict) else []

    scanned = 0
    created = 0
    failed = 0
    skipped = 0
    event_record_ids: List[str] = []
    errors: List[Any] = []

    for event_record in records:
        fields = event_record.get("fields", {}) or {}
        event_record_id = str(event_record.get("id") or "").strip()

        status = str(
            fields.get("Status_select")
            or fields.get("Status")
            or ""
        ).strip()

        mapped_capability = str(
            fields.get("Mapped_Capability")
            or fields.get("mapped_capability")
            or ""
        ).strip()

        print(
            f"[events/process] handling event_id={event_record_id} "
            f"status={status.lower() if status else ''} "
            f"mapped={mapped_capability or 'None'}"
        )

        if not event_record_id:
            skipped += 1
            continue

        if status not in ("New", "Queued"):
            skipped += 1
            continue

        scanned += 1

        try:
            res = _create_command_from_event(event_record)

            if res.get("ok"):
                created += 1
                event_record_ids.append(event_record_id)
            else:
                failed += 1
                errors.append(
                    {
                        "event_id": event_record_id,
                        "error": res.get("error"),
                        "res": res,
                    }
                )

        except Exception as e:
            failed += 1
            errors.append(
                {
                    "event_id": event_record_id,
                    "error": repr(e),
                }
            )
            print(f"[events/process][ERROR] event_id={event_record_id} error={repr(e)}")

    return {
        "ok": True,
        "source": source_meta,
        "scanned": scanned,
        "created": created,
        "failed": failed,
        "skipped": skipped,
        "event_record_ids": event_record_ids,
        "errors": errors,
        "ts": utc_now_iso() if "utc_now_iso" in globals() else datetime.now(timezone.utc).isoformat(),
    }
        
def _resolve_flow_context_from_event(event_record_id, fields, payload_obj):
    event_id = (
        _coerce_non_empty_str(payload_obj.get("event_id"))
        or _coerce_non_empty_str(payload_obj.get("eventid"))
        or _coerce_non_empty_str(payload_obj.get("eventId"))
        or _coerce_non_empty_str(fields.get("Event_ID"))
        or _coerce_non_empty_str(fields.get("event_id"))
        or _coerce_non_empty_str(fields.get("eventid"))
    )

    flow_id = (
        _coerce_non_empty_str(payload_obj.get("flow_id"))
        or _coerce_non_empty_str(payload_obj.get("flowid"))
        or _coerce_non_empty_str(payload_obj.get("flowId"))
        or _coerce_non_empty_str(fields.get("Flow_ID"))
        or _coerce_non_empty_str(fields.get("flow_id"))
        or _coerce_non_empty_str(fields.get("flowid"))
    )

    root_event_id = (
        _coerce_non_empty_str(payload_obj.get("root_event_id"))
        or _coerce_non_empty_str(payload_obj.get("rooteventid"))
        or _coerce_non_empty_str(payload_obj.get("rootEventId"))
        or _coerce_non_empty_str(fields.get("Root_Event_ID"))
        or _coerce_non_empty_str(fields.get("root_event_id"))
        or _coerce_non_empty_str(fields.get("rooteventid"))
        or event_id
        or _coerce_non_empty_str(event_record_id)
    )

    if not flow_id:
        flow_id = root_event_id or _coerce_non_empty_str(event_record_id)

    if not root_event_id:
        root_event_id = event_id or _coerce_non_empty_str(event_record_id)

    return flow_id, root_event_id
    
def _resolve_flow_ids(payload: Dict[str, Any]) -> Tuple[str, str]:
    if not isinstance(payload, dict):
        payload = {}

    flow_id = str(
        payload.get("flow_id")
        or payload.get("source_flow_id")
        or payload.get("flowId")
        or payload.get("flowid")
        or payload.get("Flow_ID")
        or ""
    ).strip()

    root_event_id = str(
        payload.get("root_event_id")
        or payload.get("rootEventId")
        or payload.get("rooteventid")
        or payload.get("Root_Event_ID")
        or payload.get("event_id")
        or payload.get("eventId")
        or payload.get("eventid")
        or payload.get("Event_ID")
        or payload.get("source_event_id")
        or payload.get("sourceEventId")
        or payload.get("sourceeventid")
        or payload.get("Source_Event_ID")
        or ""
    ).strip()

    if not flow_id and root_event_id:
        flow_id = root_event_id

    if not root_event_id and flow_id:
        root_event_id = flow_id

    return flow_id, root_event_id

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

    rid = _airtable_create(
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

    record_id = _airtable_create(FLOWS_TABLE_NAME, fields)

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

    forced_url = str(payload.get("force_url") or "").strip()

    if http_exec_done_count == 0:
        decision = "send_first_probe"
        reason = "no_http_exec_done_yet"

        first_url = forced_url or "https://httpbin.org/get"

        next_commands = [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": first_url,
                    "http_target": first_url,
                    "method": "GET",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "workspace_id": workspace_id,
                    "step_index": step_index + 1,
                    "goal": "first_probe",
                },
                "terminal": False,
            }
        ]
        terminal = False

    elif http_exec_done_count == 1:
        decision = "send_second_probe"
        reason = "one_http_exec_done"

        second_url = "https://httpbin.org/uuid"

        next_commands = [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "url": second_url,
                    "http_target": second_url,
                    "method": "GET",
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "workspace_id": workspace_id,
                    "step_index": step_index + 1,
                    "goal": "second_probe",
                },
                "terminal": False,
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
                    "workspace_id": workspace_id,
                    "step_index": step_index + 1,
                    "goal": "complete_flow",
                },
                "terminal": False,
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
            "force_url": forced_url,
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
            "force_url": forced_url,
        },
        result_obj={
            "last_decision_result": {
                "decision": decision,
                "reason": reason,
                "force_url": forced_url,
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
        "force_url": forced_url,
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

    print("[AIRTABLE CREATE DEBUG PRE] entering create")
    print("[AIRTABLE CREATE DEBUG PRE] table_name =", table_name)
    print("[AIRTABLE CREATE DEBUG PRE] AIRTABLE_API_URL =", AIRTABLE_API_URL)
    print("[AIRTABLE CREATE DEBUG PRE] fields keys =", list(fields.keys()) if isinstance(fields, dict) else type(fields))
    print("[AIRTABLE CREATE DEBUG PRE] AIRTABLE_BASE_ID =", AIRTABLE_BASE_ID)
    
    url = f"{AIRTABLE_API_URL}/{AIRTABLE_BASE_ID}/{quote(table_name)}"
    headers = airtable_headers()

    print("[AIRTABLE CREATE DEBUG] table_name =", table_name)
    print("[AIRTABLE CREATE DEBUG] url =", url)
    print("[AIRTABLE CREATE DEBUG] fields =", fields)
    
    resp = requests.post(
        url,
        headers=headers,
        json={"fields": fields},
        timeout=20,
    )

    print("[AIRTABLE CREATE DEBUG] status_code =", resp.status_code)
    print("[AIRTABLE CREATE DEBUG] response_text =", resp.text)
    
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

def _command_mark_retry_or_dead_from_result_best_effort(
    command_id: str,
    run_record_id: str,
    fields: Dict[str, Any],
    result_obj: Dict[str, Any],
) -> Dict[str, Any]:
    result_obj = result_obj if isinstance(result_obj, dict) else {}

    message = str(
        result_obj.get("error_message")
        or result_obj.get("error")
        or result_obj.get("message")
        or "capability_failed"
    ).strip() or "capability_failed"

    retry_fields = dict(fields or {})

    retry_max = _to_int(
        result_obj.get("retry_max"),
        _to_int(retry_fields.get("Retry_Max"), 0),
    )
    if POLICY_RETRY_LIMIT > 0:
        retry_max = POLICY_RETRY_LIMIT
    elif retry_max <= 0:
        retry_max = 3

    retry_count_after_failure = _to_int(
        result_obj.get("retry_count"),
        _to_int(retry_fields.get("Retry_Count"), 0) + 1,
    )

    retry_delay_seconds = _to_int(
        result_obj.get("retry_delay_seconds"),
        _to_int(retry_fields.get("Retry_Backoff_Sec"), 60),
    )
    if retry_delay_seconds <= 0:
        retry_delay_seconds = 60

    retryable = _is_truthy(result_obj.get("retryable"))
    final_failure = _is_truthy(result_obj.get("final_failure"))

    retry_fields["Retry_Max"] = retry_max
    retry_fields["Retry_Backoff_Sec"] = retry_delay_seconds

    if retryable and not final_failure:
        # helper existant incrémente déjà de +1
        retry_fields["Retry_Count"] = max(0, retry_count_after_failure - 1)
    else:
        # forcer le Dead
        retry_fields["Retry_Count"] = max(retry_count_after_failure, retry_max)

    return _command_mark_retry_or_dead_best_effort(
        command_id=command_id,
        run_record_id=run_record_id,
        fields=retry_fields,
        message=message,
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
            

        print("[ORCH] capability =", capability, flush=True)
        print("[ORCH] allowlisted =", capability in EXECUTABLE_CAPABILITY_ALLOWLIST, flush=True)
        print("[ORCH] allowlist =", EXECUTABLE_CAPABILITY_ALLOWLIST, flush=True)
        
        if capability not in EXECUTABLE_CAPABILITY_ALLOWLIST:
            skipped += 1
            errors.append(f"next_commands[{idx}] disallowed_capability:{capability}")
            continue

        if not isinstance(cmd_input, dict):
            skipped += 1
            errors.append(f"next_commands[{idx}] invalid_input")
            continue

        cmd_input = dict(cmd_input)

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

    ORCHESTRATION_CAPABILITIES = {
        "retry_router",
        "decision_router",
        "incident_router",
        "incident_router_v2",
        "incident_deduplicate",
        "incident_create",
        "incident_update",
        "internal_escalate",
        "resolve_incident",
        "close_incident",
        "smart_resolve",
        "complete_flow_incident",
        "complete_flow",
        "complete_flow_demo",
        "event_engine",
        "command_orchestrator",
        "lock_recovery",
        "retry_queue",
        "sla_router",
    }

    def _as_text(value: Any) -> str:
        if isinstance(value, list):
            for item in value:
                txt = _as_text(item)
                if txt:
                    return txt
            return ""
        if value is None:
            return ""
        try:
            return str(value).strip()
        except Exception:
            return ""

    def _pick(*values: Any) -> str:
        for v in values:
            txt = _as_text(v)
            if txt:
                return txt
        return ""

    def _to_int_local(value: Any, default: int) -> int:
        try:
            if value is None or value == "":
                return default
            return int(value)
        except Exception:
            return default

    def _unwrap_command_input(value: Any) -> Dict[str, Any]:
        if not isinstance(value, dict):
            return {}

        current = dict(value)

        for _ in range(4):
            changed = False
            for nested_key in ("command_input", "commandinput", "input", "body"):
                nested = current.get(nested_key)
                if isinstance(nested, dict):
                    merged = dict(nested)
                    for k, v in current.items():
                        if k != nested_key and k not in merged:
                            merged[k] = v
                    current = merged
                    changed = True
            if not changed:
                break

        return current

    def _resolve_command_priority(fields: Dict[str, Any]) -> int:
        return max(
            1,
            _to_int_local(
                fields.get("Priority"),
                _to_int_local(fields.get("priority"), _to_int_local(req.priority, 1)),
            ),
        )

    def _normalize_command_context(
        *,
        command_id: str,
        fields: Dict[str, Any],
        cmd_input: Dict[str, Any],
        fallback_workspace: str = "production",
        fallback_run_record_id: str = "",
    ) -> Dict[str, str]:
        flow_id = _pick(
            cmd_input.get("flow_id"),
            cmd_input.get("flowid"),
            cmd_input.get("flowId"),
            fields.get("Flow_ID"),
            fields.get("flow_id"),
            fields.get("flowid"),
        )

        root_event_id = _pick(
            cmd_input.get("root_event_id"),
            cmd_input.get("rooteventid"),
            cmd_input.get("rootEventId"),
            fields.get("Root_Event_ID"),
            fields.get("root_event_id"),
            fields.get("rooteventid"),
            cmd_input.get("event_id"),
            cmd_input.get("eventid"),
            cmd_input.get("eventId"),
        )

        source_event_id = _pick(
            cmd_input.get("source_event_id"),
            cmd_input.get("sourceeventid"),
            cmd_input.get("sourceEventId"),
            fields.get("Source_Event_ID"),
            fields.get("source_event_id"),
            fields.get("sourceeventid"),
            cmd_input.get("event_id"),
            cmd_input.get("eventid"),
            cmd_input.get("eventId"),
            root_event_id,
            flow_id,
        )

        workspace_id = _pick(
            cmd_input.get("workspace_id"),
            cmd_input.get("workspaceid"),
            cmd_input.get("workspaceId"),
            cmd_input.get("workspace"),
            fields.get("Workspace_ID"),
            fields.get("workspace_id"),
            fields.get("workspaceid"),
            fallback_workspace,
            "production",
        )

        linked_run = _pick(
            cmd_input.get("linked_run"),
            cmd_input.get("linkedrun"),
            cmd_input.get("run_record_id"),
            cmd_input.get("runrecordid"),
            cmd_input.get("runRecordId"),
            fields.get("Linked_Run"),
            fields.get("Run_Record_ID"),
            fields.get("run_record_id"),
            fallback_run_record_id,
        )

        parent_command_id = _pick(
            cmd_input.get("parent_command_id"),
            cmd_input.get("parentcommandid"),
            cmd_input.get("parentCommandId"),
            fields.get("Parent_Command_ID"),
            fields.get("parent_command_id"),
            fields.get("parentcommandid"),
        )

        current_command_id = _pick(
            cmd_input.get("command_id"),
            cmd_input.get("commandid"),
            cmd_input.get("commandId"),
            fields.get("Command_ID"),
            fields.get("command_id"),
            fields.get("commandid"),
            command_id,
        )

        if not flow_id and root_event_id:
            flow_id = root_event_id
        if not root_event_id and flow_id:
            root_event_id = flow_id
        if not source_event_id:
            source_event_id = root_event_id or flow_id

        return {
            "flow_id": flow_id or "",
            "root_event_id": root_event_id or "",
            "source_event_id": source_event_id or "",
            "event_id": source_event_id or root_event_id or flow_id or "",
            "workspace_id": workspace_id or "production",
            "run_record_id": linked_run or fallback_run_record_id or "",
            "linked_run": linked_run or fallback_run_record_id or "",
            "parent_command_id": parent_command_id or "",
            "command_id": current_command_id or command_id or "",
        }

    def _inject_context_into_input(
        input_obj: Dict[str, Any],
        ctx: Dict[str, str],
    ) -> Dict[str, Any]:
        out = dict(input_obj or {})

        if ctx.get("flow_id"):
            out["flow_id"] = ctx["flow_id"]
            out["flowid"] = ctx["flow_id"]

        if ctx.get("root_event_id"):
            out["root_event_id"] = ctx["root_event_id"]
            out["rooteventid"] = ctx["root_event_id"]

        if ctx.get("source_event_id"):
            out["source_event_id"] = ctx["source_event_id"]
            out["sourceeventid"] = ctx["source_event_id"]

        if ctx.get("event_id"):
            out["event_id"] = ctx["event_id"]
            out["eventid"] = ctx["event_id"]

        if ctx.get("workspace_id"):
            out["workspace_id"] = ctx["workspace_id"]
            out["workspaceid"] = ctx["workspace_id"]
            out["workspace"] = ctx["workspace_id"]

        if ctx.get("run_record_id"):
            out["run_record_id"] = ctx["run_record_id"]
            out["runrecordid"] = ctx["run_record_id"]

        if ctx.get("linked_run"):
            out["linked_run"] = ctx["linked_run"]
            out["linkedrun"] = ctx["linked_run"]

        if ctx.get("parent_command_id"):
            out["parent_command_id"] = ctx["parent_command_id"]
            out["parentcommandid"] = ctx["parent_command_id"]

        if ctx.get("command_id"):
            out["command_id"] = ctx["command_id"]
            out["commandid"] = ctx["command_id"]

        return out

    def _inject_context_into_result(
        result_obj: Dict[str, Any],
        ctx: Dict[str, str],
    ) -> Dict[str, Any]:
        out = dict(result_obj or {})

        if not _pick(out.get("flow_id"), out.get("flowid"), out.get("flowId")) and ctx.get("flow_id"):
            out["flow_id"] = ctx["flow_id"]

        if not _pick(out.get("root_event_id"), out.get("rooteventid"), out.get("rootEventId")) and ctx.get("root_event_id"):
            out["root_event_id"] = ctx["root_event_id"]

        if not _pick(out.get("source_event_id"), out.get("sourceeventid"), out.get("sourceEventId")) and ctx.get("source_event_id"):
            out["source_event_id"] = ctx["source_event_id"]

        if not _pick(out.get("workspace_id"), out.get("workspaceid"), out.get("workspaceId"), out.get("workspace")) and ctx.get("workspace_id"):
            out["workspace_id"] = ctx["workspace_id"]

        if not _pick(out.get("run_record_id"), out.get("runrecordid"), out.get("runRecordId")) and ctx.get("run_record_id"):
            out["run_record_id"] = ctx["run_record_id"]

        if not _pick(out.get("linked_run"), out.get("linkedrun")) and ctx.get("linked_run"):
            out["linked_run"] = ctx["linked_run"]

        if not _pick(out.get("command_id"), out.get("commandid"), out.get("commandId")) and ctx.get("command_id"):
            out["command_id"] = ctx["command_id"]

        return out

    def _inject_context_into_next_commands(
        next_commands: Any,
        parent_ctx: Dict[str, str],
        current_command_id: str,
    ) -> List[Dict[str, Any]]:
        fixed: List[Dict[str, Any]] = []

        if not isinstance(next_commands, list):
            return fixed

        for child in next_commands:
            if not isinstance(child, dict):
                continue

            child_copy = dict(child)
            child_input = child_copy.get("input") or child_copy.get("command_input") or {}
            if not isinstance(child_input, dict):
                child_input = {}

            child_input = _unwrap_command_input(dict(child_input))

            if not _pick(
                child_input.get("parent_command_id"),
                child_input.get("parentcommandid"),
                child_input.get("parentCommandId"),
            ):
                child_input["parent_command_id"] = current_command_id
                child_input["parentcommandid"] = current_command_id

            child_ctx = _normalize_command_context(
                command_id=_pick(
                    child_input.get("command_id"),
                    child_input.get("commandid"),
                    "",
                ),
                fields={},
                cmd_input={**parent_ctx, **child_input},
                fallback_workspace=parent_ctx.get("workspace_id") or "production",
                fallback_run_record_id=parent_ctx.get("run_record_id") or run_record_id,
            )

            if not child_ctx.get("parent_command_id"):
                child_ctx["parent_command_id"] = current_command_id

            child_input = _inject_context_into_input(child_input, child_ctx)
            child_copy["input"] = child_input

            if not _pick(
                child_copy.get("parent_command_id"),
                child_copy.get("parentcommandid"),
            ):
                child_copy["parent_command_id"] = current_command_id

            fixed.append(child_copy)

        return fixed

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

        print("[command_orchestrator] capability =", capability, flush=True)
        print("[command_orchestrator] fn =", fn, flush=True)

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
        command_priority = _resolve_command_priority(fields)

        raw_cmd_input = _compose_command_input(fields)
        if not isinstance(raw_cmd_input, dict):
            raw_cmd_input = {}

        raw_cmd_input = _normalize_keys_deep(raw_cmd_input)
        raw_cmd_input = _unwrap_command_input(raw_cmd_input)
        preserved_raw_cmd_input = dict(raw_cmd_input)

        cmd_ctx = _normalize_command_context(
            command_id=cid,
            fields=fields,
            cmd_input=raw_cmd_input,
            fallback_workspace=_pick(
                fields.get("Workspace_ID"),
                fields.get("workspace_id"),
                "production",
            ),
            fallback_run_record_id=run_record_id,
        )
        cmd_input = _inject_context_into_input(raw_cmd_input, cmd_ctx)

        print("[command_orchestrator] cmd_input capability =", capability, flush=True)
        print("[command_orchestrator] cmd_input payload =", cmd_input, flush=True)

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

        is_valid, validated_cmd_input, validation_error = _validate_command_input(capability, cmd_input)
        if not isinstance(validated_cmd_input, dict):
            validated_cmd_input = {}

        validated_cmd_input = _normalize_keys_deep(validated_cmd_input)
        validated_cmd_input = _unwrap_command_input(validated_cmd_input)

        if capability in ORCHESTRATION_CAPABILITIES:
            merged_cmd_input = dict(preserved_raw_cmd_input)
            merged_cmd_input.update(validated_cmd_input)
            cmd_input = merged_cmd_input
        else:
            cmd_input = validated_cmd_input

        cmd_ctx = _normalize_command_context(
            command_id=cid,
            fields=fields,
            cmd_input=cmd_input,
            fallback_workspace=cmd_ctx.get("workspace_id") or "production",
            fallback_run_record_id=cmd_ctx.get("run_record_id") or run_record_id,
        )
        cmd_input = _inject_context_into_input(cmd_input, cmd_ctx)

        if not is_valid:
            if capability in ORCHESTRATION_CAPABILITIES and preserved_raw_cmd_input:
                cmd_input = _inject_context_into_input(preserved_raw_cmd_input, cmd_ctx)
            else:
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
                    "priority": command_priority,
                    "dry_run": bool(req.dry_run),
                }
            )

            _command_lock_heartbeat(cid, lock_token)

            print("DISPATCH CAPABILITY:", capability)
            print("DISPATCH FN:", fn)
            print("DISPATCH CMD_CTX:", cmd_ctx, flush=True)
            print("DISPATCH CMD_INPUT:", cmd_input, flush=True)

            result_obj = fn(cmd_req, run_record_id)
            if not isinstance(result_obj, dict):
                result_obj = {
                    "ok": False,
                    "error": "capability_returned_non_dict",
                    "error_message": "capability_returned_non_dict",
                    "capability": capability,
                    "retryable": False,
                    "final_failure": True,
                    "next_commands": [],
                }

            result_obj = _inject_context_into_result(result_obj, cmd_ctx)

            result_obj["next_commands"] = _inject_context_into_next_commands(
                result_obj.get("next_commands"),
                cmd_ctx,
                cid,
            )

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

            workspace_id = _pick(
                result_obj.get("workspace_id"),
                result_obj.get("workspaceid"),
                cmd_ctx.get("workspace_id"),
                fields.get("Workspace_ID"),
                "production",
            )
            root_event_id = _pick(
                result_obj.get("root_event_id"),
                result_obj.get("rooteventid"),
                result_obj.get("flow_id"),
                result_obj.get("flowid"),
                cmd_ctx.get("root_event_id"),
                cmd_ctx.get("flow_id"),
                _infer_root_event_id(fields, idem),
            )
            flow_id = _pick(
                result_obj.get("flow_id"),
                result_obj.get("flowid"),
                cmd_ctx.get("flow_id"),
                root_event_id,
            )
            source_event_id = _pick(
                result_obj.get("source_event_id"),
                result_obj.get("sourceeventid"),
                cmd_ctx.get("source_event_id"),
                root_event_id,
                flow_id,
            )

            if isinstance(result_obj, dict):
                result_obj["flow_id"] = flow_id or ""
                result_obj["root_event_id"] = root_event_id or ""
                result_obj["source_event_id"] = source_event_id or ""
                result_obj["workspace_id"] = workspace_id or "production"
                result_obj["linked_run"] = _pick(
                    result_obj.get("linked_run"),
                    cmd_ctx.get("linked_run"),
                    run_record_id,
                )
                result_obj["run_record_id"] = _pick(
                    result_obj.get("run_record_id"),
                    cmd_ctx.get("run_record_id"),
                    run_record_id,
                )
                result_obj["command_id"] = _pick(result_obj.get("command_id"), cid)

            result_is_ok = not (result_obj.get("ok") is False)

            allow_spawn = (
                result_is_ok
                or _is_truthy(result_obj.get("final_failure"))
                or _is_truthy(result_obj.get("spawn_on_error"))
            )

            spawn_res = {
                "ok": True,
                "spawned": 0,
                "skipped": 0,
                "errors": [],
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "max_depth": CHAIN_MAX_DEPTH,
            }

            if allow_spawn:
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
                        or flow_id
                        or root_event_id
                    )

                if not result_obj.get("root_event_id"):
                    result_obj["root_event_id"] = (
                        spawn_res.get("root_event_id")
                        or root_event_id
                        or flow_id
                    )

                if not result_obj.get("source_event_id"):
                    result_obj["source_event_id"] = (
                        source_event_id
                        or result_obj.get("root_event_id")
                        or result_obj.get("flow_id")
                        or ""
                    )

                if not result_obj.get("workspace_id"):
                    result_obj["workspace_id"] = workspace_id or "production"

                if not result_obj.get("linked_run"):
                    result_obj["linked_run"] = run_record_id

                if not result_obj.get("run_record_id"):
                    result_obj["run_record_id"] = run_record_id

                if not result_obj.get("command_id"):
                    result_obj["command_id"] = cid

            if result_is_ok:
                _command_mark_done_best_effort(cid, run_record_id, result_obj)
                succeeded += 1
            else:
                error_message = _pick(
                    result_obj.get("error_message"),
                    result_obj.get("error"),
                    result_obj.get("message"),
                    "capability_failed",
                )
                _command_mark_retry_or_dead_from_result_best_effort(
                    command_id=cid,
                    run_record_id=run_record_id,
                    fields=fields,
                    result_obj=result_obj,
                )
                failed += 1
                errors.append(f"{cid}: {error_message}")
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
        incidents_table_name=INCIDENTS_TABLE_NAME,
        airtable_create=airtable_create,
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


def capability_retry_router(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    raw_input = dict(req.input or {}) if isinstance(req.input, dict) else {}

    print("[retry_router wrapper] raw req.input =", repr(raw_input), flush=True)

    normalized = _normalize_flow_keys(dict(raw_input))
    if not isinstance(normalized, dict):
        normalized = {}

    # SAFE:
    # on part du payload brut, puis on ajoute uniquement
    # les clés normalisées manquantes/vide.
    payload = dict(raw_input)
    for k, v in normalized.items():
        if k not in payload or payload.get(k) in (None, "", {}, []):
            payload[k] = v

    workspace_id = _resolve_workspace_id(req=req)
    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = _resolve_flow_step_index(payload, 0)

    source_event_id = str(
        payload.get("source_event_id")
        or payload.get("sourceEventId")
        or payload.get("event_id")
        or payload.get("eventId")
        or root_event_id
        or flow_id
        or ""
    ).strip()

    # SAFE:
    # on complète sans écraser la matière utile déjà présente
    if not str(payload.get("flow_id") or "").strip():
        payload["flow_id"] = flow_id
    if not str(payload.get("root_event_id") or "").strip():
        payload["root_event_id"] = root_event_id
    if not str(payload.get("source_event_id") or "").strip():
        payload["source_event_id"] = source_event_id
    if not str(payload.get("event_id") or "").strip():
        payload["event_id"] = source_event_id
    if not str(payload.get("workspace_id") or "").strip():
        payload["workspace_id"] = workspace_id
    if not str(payload.get("workspace") or "").strip():
        payload["workspace"] = workspace_id
    if not str(payload.get("run_record_id") or "").strip():
        payload["run_record_id"] = run_record_id
    if not str(payload.get("linked_run") or "").strip():
        payload["linked_run"] = run_record_id

    print("[retry_router wrapper] merged payload =", repr(payload), flush=True)

    try:
        result = capability_retry_router_run(payload=payload)

    except Exception as e:
        return {
            "ok": False,
            "capability": "retry_router",
            "status": "error",
            "error": "retry_router_wrapper_exception",
            "error_message": str(e),
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "source_event_id": source_event_id,
            "workspace_id": workspace_id,
            "run_record_id": run_record_id,
            "linked_run": run_record_id,
            "next_commands": [],
            "terminal": True,
        }

    if not isinstance(result, dict):
        result = {
            "ok": False,
            "capability": "retry_router",
            "status": "error",
            "error": "retry_router_non_dict_result",
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "source_event_id": source_event_id,
            "workspace_id": workspace_id,
            "run_record_id": run_record_id,
            "linked_run": run_record_id,
            "next_commands": [],
            "terminal": True,
        }

    result.setdefault("capability", "retry_router")
    result.setdefault("flow_id", flow_id)
    result.setdefault("root_event_id", root_event_id)
    result.setdefault("source_event_id", source_event_id)
    result.setdefault("workspace_id", workspace_id)
    result.setdefault("run_record_id", run_record_id)
    result.setdefault("linked_run", run_record_id)
    result.setdefault("step_index", step_index)

    if "next_commands" not in result or not isinstance(result.get("next_commands"), list):
        result["next_commands"] = []

    if "terminal" not in result:
        result["terminal"] = not bool(result["next_commands"])

    try:
        _append_flow_step_safe(
            flow_id=result.get("flow_id") or flow_id,
            workspace_id=workspace_id,
            step_obj={
                "step_index": step_index,
                "capability": "retry_router",
                "status": result.get("status"),
                "decision": result.get("decision"),
                "reason": result.get("reason"),
                "retry_reason": result.get("retry_reason"),
                "retry_count": result.get("retry_count"),
                "retry_max": result.get("retry_max"),
                "run_record_id": run_record_id,
            },
        )
    except Exception:
        pass

    try:
        _update_flow_registry_safe(
            flow_id=result.get("flow_id") or flow_id,
            workspace_id=workspace_id,
            status="Running" if not result.get("terminal") else "Completed",
            current_step=step_index,
            last_decision=result.get("decision", ""),
            memory_obj={
                "retry_reason": result.get("retry_reason"),
                "retry_count": result.get("retry_count"),
                "retry_max": result.get("retry_max"),
                "status": result.get("status"),
            },
            result_obj=result,
            linked_run=[run_record_id],
        )
    except Exception:
        pass

    return result
    
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
    raw_input = fields.get("Input_JSON")
    command_input = _json_load_maybe(raw_input)

    if not command_input:
        raw_input = fields.get("Command_Input_JSON")
        command_input = _json_load_maybe(raw_input)

    if not command_input:
        raw_input = fields.get("Payload_JSON")
        command_input = _json_load_maybe(raw_input)

    if not isinstance(command_input, dict):
        command_input = {}

    command_input = _normalize_keys_deep(command_input)
    command_input = _unwrap_command_payload(command_input)
    command_input = _normalize_flow_keys(command_input)

    # ------------------------------------------------------------
    # Event / Root / Flow stabilization
    # ------------------------------------------------------------
    event_id = str(
        command_input.get("event_id")
        or fields.get("event_id")
        or fields.get("eventid")
        or fields.get("eventId")
        or fields.get("Event_ID")
        or ""
    ).strip()

    root_event_id = str(
        command_input.get("root_event_id")
        or fields.get("root_event_id")
        or fields.get("rooteventid")
        or fields.get("rootEventId")
        or fields.get("Root_Event_ID")
        or event_id
        or ""
    ).strip()

    source_event_id = str(
        command_input.get("source_event_id")
        or fields.get("source_event_id")
        or fields.get("sourceeventid")
        or fields.get("sourceEventId")
        or event_id
        or root_event_id
        or ""
    ).strip()

    flow_id = str(
        command_input.get("flow_id")
        or fields.get("flow_id")
        or fields.get("flowid")
        or fields.get("flowId")
        or fields.get("Flow_ID")
        or root_event_id
        or ""
    ).strip()

    workspace_id = str(
        command_input.get("workspace_id")
        or command_input.get("workspace")
        or fields.get("workspace_id")
        or fields.get("workspaceid")
        or fields.get("workspaceId")
        or fields.get("Workspace_ID")
        or ""
    ).strip()

    if event_id and not str(command_input.get("event_id") or "").strip():
        command_input["event_id"] = event_id

    if root_event_id and not str(command_input.get("root_event_id") or "").strip():
        command_input["root_event_id"] = root_event_id

    if source_event_id and not str(command_input.get("source_event_id") or "").strip():
        command_input["source_event_id"] = source_event_id

    if flow_id and not str(command_input.get("flow_id") or "").strip():
        command_input["flow_id"] = flow_id

    if workspace_id and not str(command_input.get("workspace_id") or "").strip():
        command_input["workspace_id"] = workspace_id
        command_input["workspace"] = workspace_id

    # ------------------------------------------------------------
    # HTTP normalization
    # ------------------------------------------------------------
    http_target = str(
        fields.get("http_target")
        or fields.get("URL")
        or fields.get("Http_Target")
        or command_input.get("http_target")
        or command_input.get("url")
        or ""
    ).strip()

    if http_target and not str(command_input.get("url") or "").strip():
        command_input["url"] = http_target

    if http_target and not str(command_input.get("http_target") or "").strip():
        command_input["http_target"] = http_target

    http_method = str(
        fields.get("HTTP_Method")
        or fields.get("Http_Method")
        or fields.get("method")
        or command_input.get("method")
        or ""
    ).strip().upper()

    if http_method and not str(command_input.get("method") or "").strip():
        command_input["method"] = http_method

    print("[event_build_command_input] final_input=", json.dumps(command_input, ensure_ascii=False))
    return command_input
    
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
            {
                "Status_select": "Ignored",
            },
            {
                "Status": "Ignored",
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
    workspace_id: Optional[str],
    event_record_id: Optional[str],
    idempotency_key: Optional[str] = None,
    priority: int = 1,
) -> List[Dict[str, Any]]:
    command_input = _normalize_keys_deep(dict(command_input or {}))
    command_input = _unwrap_command_payload(command_input)
    command_input = _normalize_flow_keys(command_input)

    idem = str(
        idempotency_key
        or f"evt:{str(event_record_id or '').strip()}:{capability}"
    ).strip()

    flow_id = str(
        command_input.get("flow_id")
        or command_input.get("flowId")
        or command_input.get("flowid")
        or ""
    ).strip()

    root_event_id = str(
        command_input.get("root_event_id")
        or command_input.get("rootEventId")
        or command_input.get("rooteventid")
        or command_input.get("event_id")
        or command_input.get("eventId")
        or command_input.get("eventid")
        or flow_id
        or str(event_record_id or "").strip()
        or ""
    ).strip()

    source_event_id = str(
        command_input.get("source_event_id")
        or command_input.get("sourceEventId")
        or command_input.get("sourceeventid")
        or command_input.get("event_id")
        or command_input.get("eventId")
        or command_input.get("eventid")
        or root_event_id
        or flow_id
        or ""
    ).strip()

    workspace_value = str(
        workspace_id
        or command_input.get("workspace_id")
        or command_input.get("workspaceId")
        or command_input.get("workspaceid")
        or command_input.get("workspace")
        or ""
    ).strip()

    parent_command_id = str(
        command_input.get("parent_command_id")
        or command_input.get("parentCommandId")
        or command_input.get("parentcommandid")
        or ""
    ).strip()

    linked_run = str(
        command_input.get("linked_run")
        or command_input.get("linkedrun")
        or command_input.get("run_record_id")
        or command_input.get("runRecordId")
        or command_input.get("runrecordid")
        or ""
    ).strip()

    step_index = _to_int(
        command_input.get("step_index")
        if command_input.get("step_index") is not None
        else command_input.get("stepIndex")
        if command_input.get("stepIndex") is not None
        else command_input.get("stepindex"),
        0,
    )

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
    ).strip().upper() or "GET"

    if flow_id:
        command_input["flow_id"] = flow_id
    if root_event_id:
        command_input["root_event_id"] = root_event_id
    if source_event_id:
        command_input["source_event_id"] = source_event_id
        if not str(command_input.get("event_id") or "").strip():
            command_input["event_id"] = source_event_id
    if workspace_value:
        command_input["workspace_id"] = workspace_value
    if parent_command_id:
        command_input["parent_command_id"] = parent_command_id
    if linked_run:
        command_input["linked_run"] = linked_run
        if not str(command_input.get("run_record_id") or "").strip():
            command_input["run_record_id"] = linked_run

    if url_value:
        command_input["url"] = url_value
        if not str(command_input.get("http_target") or "").strip():
            command_input["http_target"] = url_value
        if not str(command_input.get("URL") or "").strip():
            command_input["URL"] = url_value

    command_input["method"] = method_value
    if not str(command_input.get("HTTP_Method") or "").strip():
        command_input["HTTP_Method"] = method_value

    input_json = json.dumps(command_input, ensure_ascii=False)

    minimal_fields: Dict[str, Any] = {
        "Capability": capability,
        "Status_select": "Queued",
        "Priority": priority,
        "Input_JSON": input_json,
        "Idempotency_Key": idem,
    }

    rich_fields: Dict[str, Any] = {
        **minimal_fields,
        "http_target": url_value,
        "URL": url_value,
        "HTTP_Method": method_value,
    }

    if workspace_value:
        rich_fields["Workspace_ID"] = workspace_value
    if flow_id:
        rich_fields["Flow_ID"] = flow_id
    if root_event_id:
        rich_fields["Root_Event_ID"] = root_event_id
    if parent_command_id:
        rich_fields["Parent_Command_ID"] = parent_command_id
    if step_index is not None:
        rich_fields["Step_Index"] = step_index
    if linked_run and linked_run.startswith("rec"):
        rich_fields["Linked_Run"] = [linked_run]

    candidates: List[Dict[str, Any]] = []

    # richest first
    candidates.append(dict(rich_fields))

    if "Linked_Run" in rich_fields:
        no_linked_run = dict(rich_fields)
        no_linked_run.pop("Linked_Run", None)
        candidates.append(no_linked_run)

    if "Parent_Command_ID" in rich_fields or "Step_Index" in rich_fields:
        no_parent_step = dict(rich_fields)
        no_parent_step.pop("Parent_Command_ID", None)
        no_parent_step.pop("Step_Index", None)
        candidates.append(no_parent_step)

    if workspace_value or flow_id or root_event_id:
        mid_fields = dict(minimal_fields)
        if workspace_value:
            mid_fields["Workspace_ID"] = workspace_value
        if flow_id:
            mid_fields["Flow_ID"] = flow_id
        if root_event_id:
            mid_fields["Root_Event_ID"] = root_event_id
        candidates.append(mid_fields)

    if workspace_value:
        candidates.append(
            {
                **minimal_fields,
                "Workspace_ID": workspace_value,
            }
        )

    candidates.append(dict(minimal_fields))

    # dedupe exact duplicates while preserving order
    unique_candidates: List[Dict[str, Any]] = []
    seen = set()

    for candidate in candidates:
        signature = json.dumps(candidate, sort_keys=True, ensure_ascii=False)
        if signature in seen:
            continue
        seen.add(signature)
        unique_candidates.append(candidate)

    return unique_candidates
    
def _event_mark_processed(
    event_record_id: str,
    *,
    command_record_id: str = "",
    command_created: bool = False,
    idempotency_key: str = "",
):
    attempts = []

    linked_command_value = [command_record_id] if command_record_id else None
    processed_at_value = utc_now_iso()

    candidate_fields_list = [
        {
            "Status_select": "Processed",
            "Processed_At": processed_at_value,
        },
        {
            "Status_select": "Processed",
            "Processed_At": processed_at_value,
            "Command_Created": True if command_created else False,
        },
        {
            "Status_select": "Processed",
            "Processed_At": processed_at_value,
            "Idempotency_Key": idempotency_key,
        },
        {
            "Status_select": "Processed",
            "Processed_At": processed_at_value,
            "Command_Created": True if command_created else False,
            "Idempotency_Key": idempotency_key,
        },
        {
            "Status_select": "Processed",
            "Processed_At": processed_at_value,
            "Linked_Command": linked_command_value,
        } if linked_command_value else {
            "Status_select": "Processed",
            "Processed_At": processed_at_value,
        },
        {
            "Status_select": "Processed",
            "Processed_At": processed_at_value,
            "Linked_Command": linked_command_value,
            "Command_Created": True if command_created else False,
            "Idempotency_Key": idempotency_key,
        } if linked_command_value else {
            "Status_select": "Processed",
            "Processed_At": processed_at_value,
            "Command_Created": True if command_created else False,
            "Idempotency_Key": idempotency_key,
        },
    ]

    for fields in candidate_fields_list:
        clean_fields = {
            k: v for k, v in fields.items()
            if v not in ("", None)
        }

        try:
            airtable_update(EVENTS_TABLE_NAME, event_record_id, clean_fields)
            print("[event_mark_processed]", event_record_id, clean_fields)
            return {"ok": True, "fields": clean_fields}
        except Exception as e:
            attempts.append(
                {
                    "ok": False,
                    "fields": clean_fields,
                    "error": repr(e),
                }
            )
            print("[event_mark_processed][ERROR]", repr(e))

    return {
        "ok": False,
        "event_record_id": event_record_id,
        "attempts": attempts,
    }
    
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

    # ------------------------------------------------------------
    # stable flow context from event
    # ------------------------------------------------------------
    payload_obj = payload_guess if isinstance(payload_guess, dict) else {}

    flow_id, root_event_id = _resolve_flow_context_from_event(
        event_record_id=event_record_id,
        fields=fields,
        payload_obj=payload_obj,
    )

    source_event_id = str(
        payload_obj.get("event_id")
        or payload_obj.get("eventid")
        or payload_obj.get("eventId")
        or payload_obj.get("Event_ID")
        or fields.get("event_id")
        or fields.get("eventid")
        or fields.get("eventId")
        or fields.get("Event_ID")
        or event_record_id
        or ""
    ).strip()

    # si le root actuel est vide OU égal au flow, on préfère le vrai event_id
    if source_event_id and (
        not root_event_id or str(root_event_id).strip() == str(flow_id).strip()
    ):
        root_event_id = source_event_id

    # ------------------------------------------------------------
    # build command input
    # ------------------------------------------------------------
    command_input = _event_build_command_input(fields)

    if not isinstance(command_input, dict):
        command_input = {}

    if flow_id:
        command_input["flow_id"] = flow_id

    if root_event_id:
        command_input["root_event_id"] = root_event_id

    if source_event_id:
        command_input["event_id"] = source_event_id

    # Remove alternate legacy keys if present
    command_input.pop("flowid", None)
    command_input.pop("rooteventid", None)
    command_input.pop("eventid", None)

    # ------------------------------------------------------------
    # deep payload extraction for http_exec
    # ------------------------------------------------------------
    try:
        payload = payload_obj
        deep_payload = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}

        final_url = (
            payload.get("url")
            or deep_payload.get("url")
            or command_input.get("url")
            or command_input.get("http_target")
            or command_input.get("URL")
        )

        final_method = (
            payload.get("method")
            or deep_payload.get("method")
            or command_input.get("method")
            or command_input.get("HTTP_Method")
            or "GET"
        )

        if mapped_capability == "http_exec":
            if final_url and not str(command_input.get("url") or "").strip():
                command_input["url"] = final_url

            if final_url and not str(command_input.get("http_target") or "").strip():
                command_input["http_target"] = final_url

            if final_url and not str(command_input.get("URL") or "").strip():
                command_input["URL"] = final_url

            if not str(command_input.get("method") or "").strip():
                command_input["method"] = str(final_method).strip().upper() or "GET"

            if not str(command_input.get("HTTP_Method") or "").strip():
                command_input["HTTP_Method"] = str(final_method).strip().upper() or "GET"

    except Exception as _e:
        print("[SAFE_PATCH][deep_payload_injection] error:", repr(_e))

    command_input = _normalize_keys_deep(command_input)
    command_input = _unwrap_command_payload(command_input)
    command_input = _normalize_flow_keys(command_input)

    # ------------------------------------------------------------
    # Re-assert flow context after normalization/unwrapping
    # ------------------------------------------------------------
    if not str(command_input.get("event_id") or "").strip() and source_event_id:
        command_input["event_id"] = source_event_id

    if not str(command_input.get("root_event_id") or "").strip() or (
        str(command_input.get("root_event_id") or "").strip()
        == str(command_input.get("flow_id") or "").strip()
        and str(command_input.get("event_id") or "").strip()
    ):
        command_input["root_event_id"] = (
            str(command_input.get("event_id") or "").strip()
            or root_event_id
        )

    if not str(command_input.get("flow_id") or "").strip() and flow_id:
        command_input["flow_id"] = flow_id

    if mapped_capability == "http_exec":
        command_input = _normalize_http_exec_input(command_input)

    # ------------------------------------------------------------
    # idempotency / existing command logic
    # ------------------------------------------------------------
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
        if not str(command_input.get("event_id") or "").strip() and source_event_id:
            command_input["event_id"] = source_event_id

        if not str(command_input.get("root_event_id") or "").strip() or (
            str(command_input.get("root_event_id") or "").strip()
            == str(command_input.get("flow_id") or "").strip()
            and str(command_input.get("event_id") or "").strip()
        ):
            command_input["root_event_id"] = (
                str(command_input.get("event_id") or "").strip()
                or root_event_id
            )

        if not str(command_input.get("flow_id") or "").strip() and flow_id:
            command_input["flow_id"] = flow_id

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
            "flow_id": command_input.get("flow_id"),
            "root_event_id": command_input.get("root_event_id"),
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
        "flow_id": command_input.get("flow_id"),
        "root_event_id": command_input.get("root_event_id"),
    }


def _first_non_empty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue

        if isinstance(value, list):
            for item in value:
                text = str(item or "").strip()
                if text:
                    return text
            continue

        text = str(value).strip()
        if text:
            return text

    return ""


def _command_context_from_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    input_obj = _json_load_maybe(
        fields.get("Input_JSON")
        or fields.get("Command_Input_JSON")
        or fields.get("Payload_JSON")
    )
    result_obj = _json_load_maybe(fields.get("Result_JSON"))
    payload_obj = _json_load_maybe(fields.get("Payload_JSON"))

    flow_id = _first_non_empty(
        fields.get("Flow_ID"),
        fields.get("flow_id"),
        input_obj.get("flow_id"),
        input_obj.get("flowId"),
        input_obj.get("flowid"),
        result_obj.get("flow_id"),
        result_obj.get("flowId"),
        result_obj.get("flowid"),
        payload_obj.get("flow_id"),
        payload_obj.get("flowId"),
        payload_obj.get("flowid"),
    )

    root_event_id = _first_non_empty(
        fields.get("Root_Event_ID"),
        fields.get("root_event_id"),
        input_obj.get("root_event_id"),
        input_obj.get("rootEventId"),
        input_obj.get("rooteventid"),
        result_obj.get("root_event_id"),
        result_obj.get("rootEventId"),
        result_obj.get("rooteventid"),
        payload_obj.get("root_event_id"),
        payload_obj.get("rootEventId"),
        payload_obj.get("rooteventid"),
    )

    workspace_id = _first_non_empty(
        fields.get("Workspace_ID"),
        fields.get("workspace_id"),
        fields.get("Workspace"),
        input_obj.get("workspace_id"),
        input_obj.get("workspaceId"),
        result_obj.get("workspace_id"),
        result_obj.get("workspaceId"),
        payload_obj.get("workspace_id"),
        payload_obj.get("workspaceId"),
    )

    parent_command_id = _first_non_empty(
        fields.get("Parent_Command_ID"),
        fields.get("parent_command_id"),
        input_obj.get("parent_command_id"),
        input_obj.get("parent_id"),
        result_obj.get("parent_command_id"),
        result_obj.get("parent_id"),
    )

    linked_run = _first_non_empty(
        fields.get("Linked_Run"),
        fields.get("Run_Record_ID"),
        input_obj.get("run_record_id"),
        input_obj.get("run_id"),
        result_obj.get("run_record_id"),
        result_obj.get("run_id"),
        payload_obj.get("run_record_id"),
        payload_obj.get("run_id"),
    )

    run_record_id = _first_non_empty(
        fields.get("Run_Record_ID"),
        fields.get("Linked_Run"),
        input_obj.get("run_record_id"),
        result_obj.get("run_record_id"),
        payload_obj.get("run_record_id"),
    )

    step_index_raw = (
        fields.get("Step_Index")
        if fields.get("Step_Index") is not None
        else fields.get("step_index")
    )
    if step_index_raw is None:
        step_index_raw = input_obj.get("step_index")
    if step_index_raw is None:
        step_index_raw = result_obj.get("step_index")

    try:
        step_index = int(step_index_raw) if step_index_raw is not None else None
    except Exception:
        step_index = None

    return {
        "flow_id": flow_id or None,
        "root_event_id": root_event_id or None,
        "workspace_id": workspace_id or None,
        "parent_command_id": parent_command_id or None,
        "linked_run": linked_run or None,
        "run_record_id": run_record_id or None,
        "step_index": step_index,
        "input_obj": input_obj if isinstance(input_obj, dict) else {},
        "result_obj": result_obj if isinstance(result_obj, dict) else {},
        "payload_obj": payload_obj if isinstance(payload_obj, dict) else {},
    }
    
def _create_command_from_next_command(
    next_cmd: Dict[str, Any],
    parent_run_id: str,
    workspace_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(next_cmd, dict):
        return {"ok": False, "error": "invalid_next_command"}

    next_cmd = _normalize_keys_deep(next_cmd)

    capability = str(
        next_cmd.get("capability")
        or next_cmd.get("target_capability")
        or ""
    ).strip()

    capability_aliases = {
        "httpexec": "http_exec",
        "retryrouter": "retry_router",
        "incidentrouter": "incident_router",
        "decisionrouter": "decision_router",
        "incidentcreate": "incident_create",
    }
    capability = capability_aliases.get(capability, capability)

    if not capability:
        return {"ok": False, "error": "missing_capability"}

    raw_input = (
        next_cmd.get("command_input")
        or next_cmd.get("input")
        or {}
    )

    if not isinstance(raw_input, dict):
        return {"ok": False, "error": "invalid_input"}

    parent_command_id = str(
        next_cmd.get("parent_command_id")
        or raw_input.get("parent_command_id")
        or raw_input.get("parentcommandid")
        or ""
    ).strip()

    command_input = dict(raw_input)
    command_input = _normalize_keys_deep(command_input)
    command_input = _unwrap_command_payload(command_input)
    command_input = _normalize_flow_keys(command_input)

    priority = _to_int(next_cmd.get("priority"), 1)

    flow_id, root_event_id = _resolve_flow_context_from_command_input(
        command_input,
        fallback_command_id=parent_run_id,
    )

    source_event_id = str(
        command_input.get("source_event_id")
        or command_input.get("sourceEventId")
        or command_input.get("sourceeventid")
        or command_input.get("event_id")
        or command_input.get("eventId")
        or command_input.get("eventid")
        or root_event_id
        or flow_id
        or ""
    ).strip()

    retry_count = _to_int(command_input.get("retry_count"), 0)
    step_index = _to_int(command_input.get("step_index"), 0)

    effective_workspace_id = str(
        workspace_id
        or command_input.get("workspace_id")
        or command_input.get("workspaceId")
        or command_input.get("workspaceid")
        or command_input.get("workspace")
        or ""
    ).strip() or None

    if not flow_id:
        flow_id = parent_run_id

    if not root_event_id:
        root_event_id = flow_id or parent_run_id

    if not source_event_id:
        source_event_id = root_event_id or flow_id or parent_run_id

    # ------------------------------------------------------------
    # Canonical context propagation
    # ------------------------------------------------------------
    command_input["flow_id"] = flow_id
    command_input["root_event_id"] = root_event_id
    command_input["source_event_id"] = source_event_id
    command_input["event_id"] = source_event_id

    if parent_command_id:
        command_input["parent_command_id"] = parent_command_id

    if effective_workspace_id:
        command_input["workspace_id"] = effective_workspace_id
        command_input["workspace"] = effective_workspace_id

    if not str(command_input.get("run_record_id") or "").strip():
        command_input["run_record_id"] = parent_run_id

    if not str(command_input.get("linked_run") or "").strip():
        command_input["linked_run"] = parent_run_id

    # remove legacy compact aliases to keep Input_JSON clean
    command_input.pop("flowid", None)
    command_input.pop("rooteventid", None)
    command_input.pop("eventid", None)
    command_input.pop("sourceeventid", None)
    command_input.pop("workspaceid", None)

    if capability == "http_exec":
        command_input = _normalize_http_exec_input(command_input)

        resolved_url = _resolve_http_exec_url_from_command_input(command_input)
        if not resolved_url:
            return {
                "ok": False,
                "error": "spawn_http_exec_missing_url",
                "capability": capability,
                "parent_run_id": parent_run_id,
                "command_input": command_input,
            }

    # re-assert after capability-specific normalization
    if not str(command_input.get("flow_id") or "").strip():
        command_input["flow_id"] = flow_id or parent_run_id

    if not str(command_input.get("root_event_id") or "").strip():
        command_input["root_event_id"] = root_event_id or flow_id or parent_run_id

    if not str(command_input.get("source_event_id") or "").strip():
        command_input["source_event_id"] = source_event_id or root_event_id or flow_id or parent_run_id

    if not str(command_input.get("event_id") or "").strip():
        command_input["event_id"] = command_input["source_event_id"]

    inherited_input_idem = str(command_input.get("idempotency_key") or "").strip()
    explicit_next_cmd_idem = str(next_cmd.get("idempotency_key") or "").strip()

    if capability == "http_exec" and inherited_input_idem:
        inherited_input_idem = f"{inherited_input_idem}:http_exec"

    effective_idempotency_key = (
        explicit_next_cmd_idem
        or inherited_input_idem
        or f"spawn:{capability}:{flow_id or parent_run_id}:step{step_index}:retry{retry_count}:{uuid.uuid4().hex[:10]}"
    ).strip()

    print(
        "[worker.spawn] idem check",
        {
            "capability": capability,
            "effective_idempotency_key": effective_idempotency_key,
            "explicit_next_cmd_idem": explicit_next_cmd_idem,
            "inherited_input_idem": inherited_input_idem,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "source_event_id": source_event_id,
            "parent_command_id": parent_command_id,
            "retry_count": retry_count,
            "step_index": step_index,
            "workspace_id": effective_workspace_id,
        },
        flush=True,
    )

    existing = find_command_by_idem(effective_idempotency_key)
    if existing:
        existing_record_id = str(existing.get("id") or "").strip()

        print(
            "[worker.spawn] existing_command hit",
            {
                "capability": capability,
                "effective_idempotency_key": effective_idempotency_key,
                "existing_record_id": existing_record_id,
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "source_event_id": source_event_id,
                "parent_command_id": parent_command_id,
                "retry_count": retry_count,
                "step_index": step_index,
                "workspace_id": effective_workspace_id,
            },
            flush=True,
        )

        return {
            "ok": True,
            "mode": "existing_command",
            "command_record_id": existing_record_id,
            "capability": capability,
            "workspace_id": effective_workspace_id,
            "idempotency_key": effective_idempotency_key,
            "parent_run_id": parent_run_id,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "source_event_id": source_event_id,
            "parent_command_id": parent_command_id,
        }

    print(
        "[worker.spawn] create_command payload",
        {
            "capability": capability,
            "priority": priority,
            "workspace_id": effective_workspace_id,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "source_event_id": source_event_id,
            "parent_command_id": parent_command_id,
            "retry_count": retry_count,
            "step_index": step_index,
            "command_input": command_input,
        },
        flush=True,
    )

    candidates = _build_command_fields_candidates(
        capability=capability,
        command_input=command_input,
        workspace_id=effective_workspace_id,
        event_record_id=source_event_id or root_event_id or parent_run_id,
        idempotency_key=effective_idempotency_key,
        priority=priority,
    )

    print("[worker.spawn] candidates =", candidates, flush=True)

    create_res = _airtable_create_best_effort(COMMANDS_TABLE_NAME, candidates)
    if not create_res.get("ok"):
        return {
            "ok": False,
            "error": f"command_create_failed:{create_res.get('error')}",
            "capability": capability,
            "parent_run_id": parent_run_id,
            "create_res": create_res,
        }

    return {
        "ok": True,
        "mode": "created_command",
        "command_record_id": str(create_res.get("record_id") or "").strip(),
        "capability": capability,
        "workspace_id": effective_workspace_id,
        "idempotency_key": effective_idempotency_key,
        "parent_run_id": parent_run_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "parent_command_id": parent_command_id,
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

        record_name = goal or reason or error_text or "incident"

        payload_redacted = {
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "goal": goal,
            "reason": reason,
            "error": error_text,
            "original_capability": original_capability,
            "failed_url": failed_url,
            "failed_method": failed_method,
            "workspace_id": workspace_id,
            "run_record_id": run_record_id,
            "incident_key": incident_key,
            "http_status": http_status,
            "retry_count": retry_count,
            "retry_max": retry_max,
            "ts": utc_now_iso(),
        }

        notes_parts = [
            f"Goal: {goal}" if goal else "",
            f"Reason: {reason}" if reason else "",
            f"Error: {error_text}" if error_text else "",
            f"Capability: {original_capability}" if original_capability else "",
            f"URL: {failed_url}" if failed_url else "",
            f"Method: {failed_method}" if failed_method else "",
            f"HTTP status: {http_status}" if http_status is not None else "",
            f"Retry: {retry_count}/{retry_max}",
            f"Flow ID: {flow_id}" if flow_id else "",
            f"Root event ID: {root_event_id}" if root_event_id else "",
            f"Workspace: {workspace_id}" if workspace_id else "",
            f"Run record: {run_record_id}" if run_record_id else "",
        ]
        notes_value = "\n".join([x for x in notes_parts if x])

        candidates = [
            {
                "Name": record_name,
                "Notes": notes_value,
                "Statut_incident": "Nouveau",
                "Error_Message": error_text or reason or "incident_error",
                "Payload_Redacted": json.dumps(payload_redacted, ensure_ascii=False),
                "Escalation_Sent": False,
                "Escalation_Queued": True,
                "Escalation_Queued_At": utc_now_iso(),
                "Linked_Run": [run_record_id] if run_record_id else [],
            },
            {
                "Name": record_name,
                "Notes": notes_value,
                "Statut_incident": "Nouveau",
                "Error_Message": error_text or reason or "incident_error",
                "Payload_Redacted": json.dumps(payload_redacted, ensure_ascii=False),
                "Escalation_Sent": False,
                "Escalation_Queued": True,
                "Escalation_Queued_At": utc_now_iso(),
            },
            {
                "Name": record_name,
                "Statut_incident": "Nouveau",
                "Error_Message": error_text or reason or "incident_error",
                "Escalation_Sent": False,
                "Escalation_Queued": True,
            },
            {
                "Name": record_name,
            },
        ]

        print("[AIRTABLE CREATE] table =", LOGS_ERREURS_TABLE_NAME)
        print("[AIRTABLE CREATE] trying fields =", json.dumps(candidates[0], ensure_ascii=False))

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
                    "workspace_id": workspace_id,
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
                    "workspace_id": workspace_id,
                    "step_index": 2,
                    "goal": "confirm_probe",
                },
            },
            {
                "capability": "decision_demo",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "workspace_id": workspace_id,
                    "step_index": 3,
                    "goal": "final_decision",
                },
            },
        ],
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "run_record_id": run_record_id,
    }
def capability_lead_decision(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})

    workspace_id = _resolve_workspace_id(req=req)
    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = _resolve_flow_step_index(payload, 0)

    lead_id = str(payload.get("lead_id") or "").strip()
    lead_status = str(payload.get("lead_status") or "New").strip()
    lead_email = str(payload.get("lead_email") or "").strip()
    lead_name = str(payload.get("lead_name") or "").strip()

    if not flow_id:
        raise HTTPException(status_code=400, detail="lead_decision missing flow_id")

    if not lead_id:
        raise HTTPException(status_code=400, detail="lead_decision missing lead_id")

    if not root_event_id:
        root_event_id = flow_id

    decision = ""
    reason = ""
    next_commands: List[Dict[str, Any]] = []

    if lead_status == "New":
        decision = "send_first_contact"
        reason = "lead_is_new"

        http_input = {
            "url": "https://bosai-worker.onrender.com/send-lead-email",
            "method": "POST",
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "workspace_id": workspace_id,
            "step_index": step_index + 1,
            "goal": "send_lead_email",
            "json": {
                "lead_id": lead_id,
                "lead_name": lead_name,
                "lead_email": lead_email,
                "lead_status": lead_status,
                "action": "first_contact_attempt",
                "run_record_id": run_record_id,
            },
        }

        next_commands = [
            {
                "capability": "http_exec",
                "priority": 1,
                "input": http_input,
            }
        ]
    else:
        decision = "complete_flow"
        reason = "lead_not_new"

        next_commands = [
            {
                "capability": "complete_flow_demo",
                "priority": 1,
                "input": {
                    "workspace_id": workspace_id,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "lead_flow_complete",
                    "lead_id": lead_id,
                    "lead_status": lead_status,
                },
            }
        ]

    return {
        "ok": True,
        "message": "lead_decision_executed",
        "decision": decision,
        "reason": reason,
        "lead_id": lead_id,
        "lead_status": lead_status,
        "lead_email": lead_email,
        "lead_name": lead_name,
        "workspace_id": workspace_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "next_commands": next_commands,
        "terminal": False,
        "run_record_id": run_record_id,
    }

def capability_lead_machine_demo(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})

    workspace_id = _resolve_workspace_id(req=req)
    lead_id = str(payload.get("lead_id") or "").strip()

    if not workspace_id:
        raise HTTPException(status_code=400, detail="lead_machine_demo missing workspace_id")

    if not lead_id:
        raise HTTPException(status_code=400, detail="lead_machine_demo missing lead_id")

    lead_record = airtable_find_first(
        LEADS_TABLE_NAME,
        f"{{Lead_ID}}='{lead_id}'",
    )

    if not lead_record:
        raise HTTPException(status_code=404, detail=f"Lead not found for Lead_ID={lead_id}")

    fields = lead_record.get("fields", {})

    lead_name = str(fields.get("Name") or "").strip()
    lead_email = str(fields.get("Email") or "").strip()
    lead_phone = str(fields.get("Phone") or "").strip()
    lead_source = str(fields.get("Source") or "").strip()
    lead_status = str(fields.get("Status_select") or "New").strip()

    flow_id = f"lead-flow-{lead_id}"
    root_event_id = flow_id

    next_commands = [
        {
            "capability": "state_put",
            "priority": 1,
            "input": {
                "workspace_id": workspace_id,
                "app_key": f"lead:{lead_id}",
                "value": {
                    "lead_id": lead_id,
                    "lead_record_id": lead_record.get("id"),
                    "name": lead_name,
                    "email": lead_email,
                    "phone": lead_phone,
                    "source": lead_source,
                    "status": lead_status,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                },
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "step_index": 1,
                "goal": "store_lead_snapshot",
            },
        },
        {
            "capability": "lead_decision",
            "priority": 1,
            "input": {
                "workspace_id": workspace_id,
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "step_index": 2,
                "goal": "lead_followup_decision",
                "lead_id": lead_id,
                "lead_status": lead_status,
                "lead_name": lead_name,
                "lead_email": lead_email,
            },
        },
    ]

    return {
        "ok": True,
        "message": "lead_machine_demo_executed",
        "lead_id": lead_id,
        "lead_record_id": lead_record.get("id"),
        "lead": {
            "name": lead_name,
            "email": lead_email,
            "phone": lead_phone,
            "source": lead_source,
            "status": lead_status,
        },
        "plan": [
            {
                "step": 1,
                "capability": "state_put",
                "goal": "store_lead_snapshot",
            },
            {
                "step": 2,
                "capability": "lead_decision",
                "goal": "lead_followup_decision",
            },
        ],
        "next_commands": next_commands,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "run_record_id": run_record_id,
    }
    
def capability_send_lead_email(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})

    workspace_id = _resolve_workspace_id(req=req)
    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = _resolve_flow_step_index(payload, 0)

    lead_id = str(payload.get("lead_id") or "").strip()
    lead_name = str(payload.get("lead_name") or "").strip()
    lead_email = str(payload.get("lead_email") or "").strip()
    lead_status = str(payload.get("lead_status") or "").strip()
    action = str(payload.get("action") or "first_contact_attempt").strip()

    if not lead_id:
        raise HTTPException(status_code=400, detail="send_lead_email missing lead_id")

    if not lead_email:
        raise HTTPException(status_code=400, detail="send_lead_email missing lead_email")

    from_name = os.getenv("SMTP_FROM_NAME", "").strip() or "Ferrera"

    subject = "Nous avons bien reçu votre demande"
    body = (
        f"Bonjour {lead_name or ''},\n\n"
        f"Nous avons bien reçu votre demande.\n"
        f"Notre équipe reviendra vers vous rapidement.\n\n"
        f"Cordialement,\n"
        f"{from_name}"
    )

    # ===== Envoi SMTP =====
    smtp_result = send_email_smtp(lead_email, subject, body)

    attempted_at = utc_now_iso()

    # ===== SUCCÈS =====
    if smtp_result.get("ok"):
        try:
            airtable_update_lead_by_lead_id(
                lead_id,
                {
                    "Contact_Status": "Contacted",
                    "Last_Contact_Attempt_At": attempted_at,
                    "Last_Contact_Error": "",
                    "Last_Contact_Run_ID": run_record_id,
                },
            )
        except Exception as e:
            return {
                "ok": False,
                "message": "email_sent_but_lead_update_failed",
                "error": str(e),
                "lead_id": lead_id,
                "lead_email": lead_email,
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "step_index": step_index,
                "terminal": True,
                "run_record_id": run_record_id,
            }

        return {
            "ok": True,
            "message": "email_sent_real",
            "lead_id": lead_id,
            "lead_email": lead_email,
            "contact_status": "Contacted",
            "action": action,
            "workspace_id": workspace_id,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "step_index": step_index,
            "terminal": True,
            "run_record_id": run_record_id,
        }

    # ===== ÉCHEC =====
    error_text = str(smtp_result.get("error") or "unknown_email_error")

    try:
        airtable_update_lead_by_lead_id(
            lead_id,
            {
                "Contact_Status": "Email Failed",
                "Last_Contact_Attempt_At": attempted_at,
                "Last_Contact_Error": error_text,
                "Last_Contact_Run_ID": run_record_id,
            },
        )
    except Exception:
        pass

    return {
        "ok": False,
        "message": "email_failed",
        "error": error_text,
        "lead_id": lead_id,
        "lead_email": lead_email,
        "contact_status": "Email Failed",
        "action": action,
        "workspace_id": workspace_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "step_index": step_index,
        "terminal": True,
        "run_record_id": run_record_id,
    }
    
def capability_planner_monitoring(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    workspace_id = _resolve_workspace_id(req=req)
    payload = _normalize_flow_keys(req.input or {})

    view_name = str(payload.get("view") or "Active").strip() or "Active"

    try:
        endpoints = airtable_list_view("Monitored_Endpoints", view_name, max_records=100)
    except Exception as e:
        return {
            "ok": False,
            "error": "monitored_endpoints_read_failed",
            "error_message": repr(e),
            "next_commands": [],
            "terminal": True,
            "run_record_id": run_record_id,
        }

    next_commands: List[Dict[str, Any]] = []
    planned: List[Dict[str, Any]] = []

    for record in endpoints:
        fields = record.get("fields", {}) or {}

        endpoint_workspace = str(fields.get("Workspace_ID") or "").strip()
        if endpoint_workspace and endpoint_workspace != workspace_id:
            continue

        enabled = fields.get("Enabled")
        if enabled not in (True, 1, "1", "true", "True", "yes", "on"):
            continue

        name = str(fields.get("Name") or "Unnamed endpoint").strip()
        url = str(fields.get("URL") or "").strip()
        method = str(fields.get("Method") or "GET").strip().upper()

        if not url:
            continue

        expected_status = fields.get("Expected_Status")
        timeout_ms = fields.get("Timeout_ms")

        flow_id = f"flow-monitor-{uuid.uuid4().hex[:10]}"
        root_event_id = flow_id

        planned.append(
            {
                "name": name,
                "url": url,
                "method": method,
                "expected_status": expected_status,
                "timeout_ms": timeout_ms,
                "flow_id": flow_id,
            }
        )

        # Step 1: probe
        next_commands.append(
            {
                "capability": "http_exec",
                "priority": 1,
                "input": {
                    "workspace_id": workspace_id,
                    "url": url,
                    "method": method,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": 1,
                    "goal": "monitor_probe",
                    "endpoint_name": name,
                    "expected_status": expected_status,
                    "timeout_ms": timeout_ms,
                },
            }
        )

        # Step 2: decision after probe
        next_commands.append(
            {
                "capability": "decision_monitoring",
                "priority": 1,
                "input": {
                    "workspace_id": workspace_id,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": 2,
                    "goal": "monitor_decision",
                    "endpoint_name": name,
                    "url": url,
                    "method": method,
                    "expected_status": expected_status,
                    "timeout_ms": timeout_ms,
                },
            }
        )

    return {
        "ok": True,
        "message": "planner_monitoring_executed",
        "planned_count": len(planned),
        "planned": planned,
        "next_commands": next_commands,
        "terminal": False,
        "run_record_id": run_record_id,
    }

def capability_http_exec_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    print("HTTP_EXEC_WRAPPER_V7_ENTERED", flush=True)

    payload = _normalize_flow_keys(req.input or {})
    workspace_id = _resolve_workspace_id(req=req)

    goal = str(
        payload.get("goal")
        or payload.get("Goal")
        or payload.get("failed_goal")
        or ""
    ).strip()

    flow_id, root_event_id = _resolve_flow_ids(payload)
    step_index = _resolve_flow_step_index(payload, 0)

    source_event_id = str(
        payload.get("source_event_id")
        or payload.get("sourceEventId")
        or payload.get("event_id")
        or payload.get("eventId")
        or ""
    ).strip()

    if not flow_id:
        flow_id = str(
            payload.get("flow_id")
            or payload.get("event_id")
            or payload.get("source_event_id")
            or f"flow_run_{run_record_id}"
        ).strip()

    if not root_event_id:
        root_event_id = str(
            payload.get("root_event_id")
            or payload.get("event_id")
            or source_event_id
            or flow_id
        ).strip()

    if not source_event_id:
        source_event_id = str(
            payload.get("source_event_id")
            or payload.get("event_id")
            or root_event_id
            or flow_id
        ).strip()

    payload = dict(payload)
    payload["flow_id"] = flow_id
    payload["root_event_id"] = root_event_id
    payload["source_event_id"] = source_event_id
    payload["event_id"] = source_event_id
    payload["workspace_id"] = workspace_id
    payload["workspace"] = workspace_id

    try:
        result = capability_http_exec(
            input_data=payload,
            run_record_id=run_record_id,
            airtable_update_by_field=airtable_update_by_field,
            airtable_update=airtable_update,
        )
        print("[HTTP_EXEC_WRAPPED] raw result =", repr(result), flush=True)
    except Exception as e:
        print("[HTTP_EXEC_WRAPPED] EXCEPTION =", str(e), flush=True)
        result = {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error": "exception_in_http_exec",
            "error_message": str(e),
            "retryable": False,
            "final_failure": True,
            "next_commands": [],
            "terminal": True,
        }

    if not isinstance(result, dict):
        result = {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error": "http_exec_returned_non_dict",
            "error_message": "http_exec_returned_non_dict",
            "retryable": False,
            "final_failure": True,
            "next_commands": [],
            "terminal": True,
        }

    status_code = (
        result.get("http_status")
        or result.get("status_code")
        or (
            result.get("response", {}).get("status_code")
            if isinstance(result.get("response"), dict)
            else None
        )
    )
    try:
        status_code = int(status_code) if status_code is not None else None
    except Exception:
        status_code = None

    result.setdefault("workspace_id", workspace_id)
    result.setdefault("flow_id", flow_id)
    result.setdefault("root_event_id", root_event_id)
    result.setdefault("source_event_id", source_event_id)
    result.setdefault("event_id", source_event_id)
    result.setdefault("step_index", step_index)
    result.setdefault("linked_run", run_record_id)
    result["run_record_id"] = run_record_id
    result["goal"] = goal or result.get("goal") or ""

    if "next_commands" not in result or not isinstance(result.get("next_commands"), list):
        result["next_commands"] = []

    if "terminal" not in result:
        result["terminal"] = not bool(result["next_commands"])

    result_ok = not (result.get("ok") is False)
    retryable = _is_truthy(result.get("retryable"))
    final_failure = _is_truthy(result.get("final_failure"))

    if result_ok:
        step_status = "done"
        last_decision = "http_exec_done"
    elif retryable and not final_failure:
        step_status = "retry"
        last_decision = "http_exec_retryable_error"
    else:
        step_status = "error"
        last_decision = "http_exec_final_error"

    try:
        _append_flow_step_safe(
            flow_id=flow_id,
            workspace_id=workspace_id,
            step_obj={
                "step_index": step_index,
                "capability": "http_exec",
                "status": step_status,
                "http_status": status_code,
                "goal": goal,
                "error": result.get("error"),
                "error_message": result.get("error_message"),
                "retryable": retryable,
                "final_failure": final_failure,
                "run_record_id": run_record_id,
            },
        )
    except Exception as e:
        print("[worker.wrapper] append_flow_step_safe error =", str(e), flush=True)

    try:
        _update_flow_registry_safe(
            flow_id=flow_id,
            workspace_id=workspace_id,
            status="Running",
            current_step=step_index,
            last_decision=last_decision,
            memory_obj={
                "last_http_status": status_code,
                "last_goal": goal,
                "last_error": result.get("error"),
                "retryable": retryable,
                "final_failure": final_failure,
            },
            result_obj=result,
            linked_run=[run_record_id],
        )
    except Exception as e:
        print("[worker.wrapper] update_flow_registry_safe error =", str(e), flush=True)

    print("[worker.wrapper] returning result =", result, flush=True)
    return result
    
def capability_incident_create_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return capability_incident_create(
        req,
        run_record_id,
        airtable_create=_airtable_create,
        airtable_update_by_field=airtable_update_by_field,
        incidents_table_name=INCIDENTS_TABLE_NAME,
    )


def capability_resolve_incident_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return capability_resolve_incident(
        req,
        run_record_id,
        airtable_update=airtable_update,
        incidents_table_name=INCIDENTS_TABLE_NAME,
    )


def capability_close_incident_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return capability_close_incident(
        req,
        run_record_id,
        airtable_update=airtable_update,
        incidents_table_name=INCIDENTS_TABLE_NAME,
    )
    
EVENT_CAPABILITY_ALLOWLIST = {
    "http_exec",
    "escalation_engine",
    "internal_escalate",
    "chain_demo",
    "planner_demo",
    "decision_demo",
    "incident_router_v2",
    "retry_router",
    "sla_router",
    "complete_flow_demo",
    "complete_flow",
    "incident_create",
    "complete_flow_incident",
    "incident_deduplicate",
    "resolve_incident",
    "smart_resolve",
    "close_incident",
    "planner_monitoring",
    "decision_monitoring",
    "lead_machine_demo",
    "lead_decision",
    "send_lead_email",
    
}

EXECUTABLE_CAPABILITY_ALLOWLIST = {
    "http_exec",
    "escalation_engine",
    "internal_escalate",
    "chain_demo",
    "planner_demo",
    "decision_demo",
    "incident_router_v2",
    "retry_router",
    "sla_router",
    "complete_flow",
    "complete_flow_demo",
    "flow_state_get",
    "flow_state_put",
    "flow_state_append_step",
    "incident_create",
    "complete_flow_incident",
    "incident_deduplicate",
    "resolve_incident",
    "smart_resolve",
    "close_incident",
    "planner_monitoring",
    "decision_monitoring",
    "lead_machine_demo",
    "lead_decision",
    "send_lead_email",
}

def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default
        

def capability_incident_deduplicate_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return capability_incident_deduplicate(
        req,
        run_record_id,
        airtable_list_filtered=airtable_list_filtered,
        airtable_update=airtable_update,
        incidents_table_name=INCIDENTS_TABLE_NAME,
    )

def capability_incident_update_wrapped(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return capability_incident_update(
        req,
        run_record_id,
        airtable_update=airtable_update,
        incidents_table_name=INCIDENTS_TABLE_NAME,
    )

def capability_smart_resolve_wrapped(req, run_record_id: str, **kwargs):
    return capability_smart_resolve(
        req=req,
        run_record_id=run_record_id,
        **kwargs,
    )
    
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

def capability_decision_monitoring(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    payload = _normalize_flow_keys(req.input or {})
    workspace_id = _resolve_workspace_id(req=req)

    flow_id = str(
        payload.get("flow_id")
        or payload.get("root_event_id")
        or ""
    ).strip()

    root_event_id = str(
        payload.get("root_event_id")
        or flow_id
        or ""
    ).strip()

    step_index = _resolve_flow_step_index(payload, 0)

    endpoint_name = str(payload.get("endpoint_name") or "Unnamed endpoint").strip()
    expected_status = payload.get("expected_status")
    url = str(payload.get("url") or "").strip()
    method = str(payload.get("method") or "GET").strip().upper()

    try:
        expected_status_int = int(expected_status) if expected_status is not None else 200
    except Exception:
        expected_status_int = 200

    if not flow_id:
        return {
            "ok": False,
            "error": "missing_flow_id",
            "run_record_id": run_record_id,
            "next_commands": [],
            "terminal": True,
        }

    actual_status = None
    matched_command_id = ""

    # ------------------------------------------------------------
    # 1) Lookup Commands
    # ------------------------------------------------------------
    try:
        records = airtable_list_filtered(
            COMMANDS_TABLE_NAME,
            formula=f"AND({{Flow_ID}}='{flow_id}',{{Capability}}='http_exec',{{Status_select}}='Done')",
            max_records=10,
        )
    except Exception as e:
        records = []
        print("[decision_monitoring] commands lookup failed =", repr(e), flush=True)

    for record in records:
        fields = record.get("fields", {}) or {}
        result_json = _json_load_maybe(fields.get("Result_JSON"))

        if not isinstance(result_json, dict):
            continue

        candidate_status = (
            result_json.get("http_status")
            or result_json.get("status_code")
            or (
                result_json.get("response", {}).get("status_code")
                if isinstance(result_json.get("response"), dict)
                else None
            )
        )

        try:
            candidate_status = int(candidate_status) if candidate_status is not None else None
        except Exception:
            candidate_status = None

        if candidate_status is not None:
            actual_status = candidate_status
            matched_command_id = str(record.get("id") or "").strip()
            break

    # ------------------------------------------------------------
    # 2) Fallback System_Runs
    # ------------------------------------------------------------
    if actual_status is None:
        try:
            run_records = airtable_list_filtered(
                SYSTEM_RUNS_TABLE_NAME,
                formula=f"AND({{Capability}}='http_exec',{{Status_select}}='Done')",
                max_records=20,
            )
        except Exception as e:
            run_records = []
            print("[decision_monitoring] system_runs lookup failed =", repr(e), flush=True)

        for record in run_records:
            fields = record.get("fields", {}) or {}

            result_json = _json_load_maybe(fields.get("Result_JSON"))
            input_json = _json_load_maybe(fields.get("Input_JSON"))

            if not isinstance(result_json, dict):
                continue

            run_flow_id = str(
                result_json.get("flow_id")
                or input_json.get("flow_id")
                or ""
            ).strip()

            if run_flow_id != flow_id:
                continue

            candidate_status = (
                result_json.get("http_status")
                or result_json.get("status_code")
                or (
                    result_json.get("response", {}).get("status_code")
                    if isinstance(result_json.get("response"), dict)
                    else None
                )
            )

            try:
                candidate_status = int(candidate_status) if candidate_status is not None else None
            except Exception:
                candidate_status = None

            if candidate_status is not None:
                actual_status = candidate_status
                matched_command_id = str(record.get("id") or "").strip()
                break

    # ------------------------------------------------------------
    # MONITORING WRITEBACK (CRITIQUE)
    # ------------------------------------------------------------
    try:
        if endpoint_name:
            airtable_update_by_field(
                table="Monitored_Endpoints",
                field="Name",
                value=endpoint_name,
                fields={
                    "Last_Status": actual_status,
                    "Last_Error": "" if actual_status == expected_status_int else "expected_status_mismatch",
                },
            )
    except Exception as e:
        print("[decision_monitoring] endpoint update failed =", repr(e), flush=True)

    # ------------------------------------------------------------
    # DECISION
    # ------------------------------------------------------------
    if actual_status == expected_status_int:
        return {
            "ok": True,
            "decision": "close_monitoring_flow",
            "reason": "expected_status_matched",
            "endpoint_name": endpoint_name,
            "url": url,
            "method": method,
            "expected_status": expected_status_int,
            "actual_status": actual_status,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "run_record_id": run_record_id,
            "matched_command_id": matched_command_id,
            "next_commands": [
                {
                    "capability": "complete_flow_demo",
                    "priority": 1,
                    "input": {
                        "workspace_id": workspace_id,
                        "flow_id": flow_id,
                        "root_event_id": root_event_id,
                        "step_index": step_index + 1,
                        "goal": "monitoring_completed",
                    },
                }
            ],
            "terminal": False,
        }

    return {
        "ok": True,
        "decision": "create_incident",
        "reason": "expected_status_mismatch",
        "endpoint_name": endpoint_name,
        "url": url,
        "method": method,
        "expected_status": expected_status_int,
        "actual_status": actual_status,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "run_record_id": run_record_id,
        "matched_command_id": matched_command_id,
        "next_commands": [
            {
                "capability": "incident_create",
                "priority": 1,
                "input": {
                    "workspace_id": workspace_id,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "monitoring_incident",
                    "reason": "expected_status_mismatch",
                    "endpoint_name": endpoint_name,
                    "url": url,
                    "method": method,
                    "expected_status": expected_status_int,
                    "actual_status": actual_status,
                },
            }
        ],
        "terminal": False,
    }
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
    "lead_machine_demo": capability_lead_machine_demo,
    "decision_demo": capability_decision_demo,
    "complete_flow": capability_complete_flow,
    "complete_flow_demo": capability_complete_flow_demo,
    "sla_router": capability_sla_router,
    "retry_router": capability_retry_router,
    "incident_router_v2": capability_incident_router_v2,
    "incident_create": capability_incident_create_wrapped,
    "complete_flow_incident": capability_complete_flow_incident,
    "incident_deduplicate": capability_incident_deduplicate_wrapped,
    "incident_update": capability_incident_update_wrapped,
    "resolve_incident": capability_resolve_incident_wrapped,
    "close_incident": capability_close_incident_wrapped,
    "smart_resolve": capability_smart_resolve_wrapped,
    "planner_monitoring": capability_planner_monitoring,
    "decision_monitoring": capability_decision_monitoring,
    "lead_decision": capability_lead_decision,
    "send_lead_email": capability_send_lead_email,

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

def _coerce_json_obj(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    return {}
    
def _extract_flow_metadata_from_command_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    input_json = _coerce_json_obj(
        fields.get("Input_JSON")
        or fields.get("input_json")
    )

    result_json = _coerce_json_obj(
        fields.get("Result_JSON")
        or fields.get("result_json")
    )

    def pick(*values):
        for v in values:
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None

    flow_id = pick(
        fields.get("Flow_ID"),
        fields.get("flow_id"),
        fields.get("flowid"),
        input_json.get("flow_id"),
        input_json.get("flowid"),
        input_json.get("flowId"),
        result_json.get("flow_id"),
        result_json.get("flowid"),
        result_json.get("flowId"),
    )

    root_event_id = pick(
        fields.get("Root_Event_ID"),
        fields.get("root_event_id"),
        fields.get("rooteventid"),
        fields.get("Event_ID"),
        fields.get("event_id"),
        input_json.get("root_event_id"),
        input_json.get("rooteventid"),
        input_json.get("event_id"),
        result_json.get("root_event_id"),
        result_json.get("rooteventid"),
        result_json.get("event_id"),
    )

    parent_command_id = pick(
        fields.get("Parent_Command_ID"),
        fields.get("parent_command_id"),
        fields.get("parentcommand_id"),
        input_json.get("parent_command_id"),
        input_json.get("parentcommand_id"),
        result_json.get("parent_command_id"),
        result_json.get("parentcommand_id"),
    )

    step_index_raw = (
        fields.get("Step_Index")
        or fields.get("step_index")
        or fields.get("stepindex")
        or input_json.get("step_index")
        or input_json.get("stepindex")
        or result_json.get("step_index")
        or result_json.get("stepindex")
    )

    try:
        step_index = int(step_index_raw) if step_index_raw is not None and str(step_index_raw).strip() != "" else None
    except Exception:
        step_index = None

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "parent_command_id": parent_command_id,
        "step_index": step_index,
        "input_json": input_json if input_json else None,
        "result_json": result_json if result_json else None,
    }

def _flow_status_from_commands(commands: List[Dict[str, Any]]) -> str:
    statuses = [str(c.get("status") or "").lower() for c in commands]

    has_error = any(s in ("error", "failed", "dead") for s in statuses)
    has_running = any(s == "running" for s in statuses)
    has_retry = any(s == "retry" for s in statuses)
    has_queued = any(s in ("queued", "queue") for s in statuses)
    all_done = len(statuses) > 0 and all(s == "done" for s in statuses)
    has_done = any(s == "done" for s in statuses)

    if all_done:
        return "completed"
    if has_error:
        return "failed"
    if has_running or has_retry or has_queued:
        return "running"
    if has_done:
        return "partial"
    return "unknown"


def _flow_summary_from_commands(commands: List[Dict[str, Any]]) -> Dict[str, int]:
    done = sum(1 for c in commands if str(c.get("status") or "").lower() == "done")
    running = sum(1 for c in commands if str(c.get("status") or "").lower() == "running")
    retry = sum(1 for c in commands if str(c.get("status") or "").lower() == "retry")
    failed = sum(
        1
        for c in commands
        if str(c.get("status") or "").lower() in ("error", "failed", "dead")
    )

    return {
        "done": done,
        "running": running,
        "retry": retry,
        "failed": failed,
    }


def _sort_flow_commands(commands: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def _key(c: Dict[str, Any]):
        step_index = c.get("step_index")
        try:
            step_value = int(step_index) if step_index is not None else 10**9
        except Exception:
            step_value = 10**9

        created_at = c.get("created_at") or ""
        return (step_value, str(created_at))

    return sorted(commands, key=_key)


def _build_flows_from_command_items(commands: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}

    for cmd in commands:
        flow_id = cmd.get("flow_id")
        root_event_id = cmd.get("root_event_id")

        if isinstance(flow_id, str) and flow_id.strip():
            resolved_flow_id = flow_id.strip()
            is_synthetic = False
        elif isinstance(root_event_id, str) and root_event_id.strip():
            resolved_flow_id = f"root:{root_event_id.strip()}"
            is_synthetic = True
        else:
            resolved_flow_id = f"no-flow:{cmd.get('id')}"
            is_synthetic = True

        if resolved_flow_id not in grouped:
            grouped[resolved_flow_id] = {
                "flow_id": resolved_flow_id,
                "root_event_id": root_event_id if isinstance(root_event_id, str) and root_event_id.strip() else None,
                "is_synthetic": is_synthetic,
                "commands": [],
            }

        group = grouped[resolved_flow_id]

        if not group.get("root_event_id") and isinstance(root_event_id, str) and root_event_id.strip():
            group["root_event_id"] = root_event_id.strip()

        group["commands"].append(cmd)

    flows: List[Dict[str, Any]] = []

    for _, group in grouped.items():
        steps = _sort_flow_commands(group["commands"])
        summary = _flow_summary_from_commands(steps)
        status = _flow_status_from_commands(steps)

        first_created_at = steps[0].get("created_at") if steps else None
        last_finished_at = None
        if steps:
            last_finished_at = steps[-1].get("finished_at") or steps[-1].get("created_at")

        flows.append(
            {
                "flow_id": group["flow_id"],
                "root_event_id": group.get("root_event_id"),
                "status": status,
                "is_synthetic": bool(group.get("is_synthetic")),
                "commands_count": len(steps),
                "done": summary["done"],
                "running": summary["running"],
                "retry": summary["retry"],
                "failed": summary["failed"],
                "first_created_at": first_created_at,
                "last_finished_at": last_finished_at,
                "steps": steps,
            }
        )

    flows.sort(
        key=lambda f: str(f.get("last_finished_at") or f.get("first_created_at") or ""),
        reverse=True,
    )

    return flows

@app.get("/monitoring/endpoints")
def get_monitoring_endpoints(
    workspace_id: Optional[str] = None,
    view: str = "Grid view",
    max_records: int = 100,
) -> Dict[str, Any]:
    try:
        records = airtable_list_records(
            "Monitored_Endpoints",
            view=view,
            max_records=max_records,
        )

        items = [_monitoring_endpoint_to_api(r) for r in records]

        if workspace_id:
            workspace_id = str(workspace_id).strip()
            items = [x for x in items if x.get("workspace_id") == workspace_id]

        return {
            "ok": True,
            "count": len(items),
            "items": items,
        }

    except Exception as e:
        return {
            "ok": False,
            "count": 0,
            "items": [],
            "error": repr(e),
        }

@app.get("/commands")
def get_commands(limit: int = 30) -> Dict[str, Any]:
    limit = _safe_limit(limit, default=30, minimum=1, maximum=300)
    records, meta = _safe_records_from_view(
        COMMANDS_TABLE_NAME,
        COMMANDS_DASHBOARD_VIEW_NAME,
        limit,
    )

    commands: List[Dict[str, Any]] = []
    stats = {
        "queue": 0,
        "queued": 0,
        "running": 0,
        "retry": 0,
        "dead": 0,
        "done": 0,
        "error": 0,
        "unsupported": 0,
        "other": 0,
    }

    for r in records:
        f = r.get("fields", {}) or {}
        status = str(f.get("Status_select", f.get("Status", "")) or "").strip()
        key = status.lower()

        if key in ("queue", "queued"):
            stats["queue"] += 1
            stats["queued"] += 1
        elif key == "running":
            stats["running"] += 1
        elif key == "retry":
            stats["retry"] += 1
        elif key == "dead":
            stats["dead"] += 1
        elif key == "done":
            stats["done"] += 1
        elif key == "error":
            stats["error"] += 1
        elif key == "unsupported":
            stats["unsupported"] += 1
        else:
            stats["other"] += 1

        ctx = _command_context_from_fields(f)

        commands.append(
            {
                "id": r.get("id"),
                "name": f.get("Name") or f.get("Capability"),
                "capability": f.get("Capability"),
                "status": status,
                "tool_key": f.get("Tool_Key"),
                "tool_mode": f.get("Tool_Mode"),
                "workspace_id": ctx["workspace_id"],
                "flow_id": ctx["flow_id"],
                "root_event_id": ctx["root_event_id"],
                "linked_run": ctx["linked_run"],
                "run_record_id": ctx["run_record_id"],
                "created_at": f.get("Created_At"),
                "updated_at": f.get("Updated_At"),
                "started_at": f.get("Started_At"),
                "finished_at": f.get("Finished_At"),
                "parent_command_id": ctx["parent_command_id"],
                "step_index": ctx["step_index"],
                "worker": f.get("Worker"),
                "error": f.get("Last_Error") or f.get("Error"),
                "input_json": ctx["input_obj"],
                "result_json": ctx["result_obj"],
                "input": ctx["input_obj"],
                "result": ctx["result_obj"],
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
    
@app.get("/flows")
def get_flows(limit: int = 50) -> Dict[str, Any]:
    limit = _safe_limit(limit, default=50, minimum=1, maximum=200)
    records, meta = _safe_records_from_view(
        COMMANDS_TABLE_NAME,
        COMMANDS_DASHBOARD_VIEW_NAME,
        limit,
    )

    commands: List[Dict[str, Any]] = []

    for r in records:
        f = r.get("fields", {}) or {}
        status = _read_command_status(f)
        flow_meta = _extract_flow_metadata_from_command_fields(f)

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
                "flow_id": flow_meta["flow_id"],
                "root_event_id": flow_meta["root_event_id"],
                "parent_command_id": flow_meta["parent_command_id"],
                "step_index": flow_meta["step_index"],
                "input_json": flow_meta["input_json"],
                "result_json": flow_meta["result_json"],
                "worker": f.get("Locked_By") or f.get("Worker"),
                "workspace_id": f.get("Workspace_ID") or f.get("workspace_id"),
                "started_at": f.get("Started_At"),
                "finished_at": f.get("Finished_At"),
                "created_at": f.get("Created_At") or f.get("created_at"),
            }
        )

    flows = _build_flows_from_command_items(commands)

    linked_count = sum(1 for flow in flows if not flow.get("is_synthetic"))
    synthetic_count = sum(1 for flow in flows if flow.get("is_synthetic"))

    return {
        "ok": bool(meta.get("ok")),
        "source": meta,
        "count": len(flows),
        "stats": {
            "linked": linked_count,
            "synthetic": synthetic_count,
        },
        "flows": flows,
        "ts": utc_now_iso(),
    }

@app.get("/flows/{flow_id}")
def get_flow_by_id(flow_id: str) -> Dict[str, Any]:
    try:
        if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
            raise HTTPException(status_code=500, detail="missing_airtable_env")

        limit = 200
        records, meta = _safe_records_from_view(
            COMMANDS_TABLE_NAME,
            COMMANDS_DASHBOARD_VIEW_NAME,
            limit,
        )

        commands: List[Dict[str, Any]] = []

        for r in records:
            f = r.get("fields", {}) or {}
            status = _read_command_status(f)
            flow_meta = _extract_flow_metadata_from_command_fields(f) or {}

            current_flow_id = (
                flow_meta.get("flow_id")
                or f.get("Flow_ID")
                or f.get("flow_id")
                or ""
            )

            root_event_id = (
                flow_meta.get("root_event_id")
                or f.get("Root_Event_ID")
                or f.get("root_event_id")
                or ""
            )

            parent_command_id = (
                flow_meta.get("parent_command_id")
                or f.get("Parent_Command_ID")
                or f.get("parent_command_id")
                or ""
            )

            step_index = flow_meta.get("step_index")
            try:
                step_index = int(step_index) if step_index not in (None, "") else None
            except Exception:
                step_index = None

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
                    "flow_id": current_flow_id,
                    "root_event_id": root_event_id,
                    "parent_command_id": parent_command_id,
                    "step_index": step_index,
                    "input_json": flow_meta.get("input_json"),
                    "result_json": flow_meta.get("result_json"),
                    "worker": f.get("Locked_By") or f.get("Worker"),
                    "workspace_id": f.get("Workspace_ID") or f.get("workspace_id"),
                    "started_at": f.get("Started_At"),
                    "finished_at": f.get("Finished_At"),
                    "created_at": f.get("Created_At") or f.get("created_at"),
                }
            )

        filtered = [
            c for c in commands
            if str(c.get("flow_id") or "").strip() == flow_id
        ]

        filtered.sort(
            key=lambda c: (
                c.get("step_index") is None,
                c.get("step_index") if c.get("step_index") is not None else 999999,
                str(c.get("created_at") or ""),
            )
        )

        if not filtered:
            raise HTTPException(status_code=404, detail="flow_not_found")

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

        for c in filtered:
            s = str(c.get("status") or "").lower()
            if s in ("queued", "queue"):
                stats["queued"] += 1
            elif s == "running":
                stats["running"] += 1
            elif s == "retry":
                stats["retry"] += 1
            elif s == "done":
                stats["done"] += 1
            elif s == "dead":
                stats["dead"] += 1
            elif s == "blocked":
                stats["blocked"] += 1
            elif s == "unsupported":
                stats["unsupported"] += 1
            elif s == "error":
                stats["error"] += 1
            else:
                stats["other"] += 1

        workspace_id = next(
            (c.get("workspace_id") for c in filtered if c.get("workspace_id")),
            "",
        )
        root_event_id = next(
            (c.get("root_event_id") for c in filtered if c.get("root_event_id")),
            "",
        )

        return {
            "ok": bool(meta.get("ok")),
            "source": meta,
            "flow": {
                "id": flow_id,
                "count": len(filtered),
                "root_event_id": root_event_id,
                "workspace_id": workspace_id,
                "stats": stats,
                "commands": filtered,
            },
            "ts": utc_now_iso(),
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"detail": "Internal error", "error": repr(exc)},
        )
        
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
    records, meta = _safe_records_from_view(
        EVENTS_TABLE_NAME,
        EVENTS_DASHBOARD_VIEW_NAME,
        limit,
    )

    def _pick_first_text(*values: Any) -> str:
        for value in values:
            if value is None:
                continue

            if isinstance(value, list):
                for item in value:
                    text = str(item or "").strip()
                    if text:
                        return text
                continue

            text = str(value or "").strip()
            if text:
                return text

        return ""

    events: List[Dict[str, Any]] = []
    stats = {
        "new": 0,
        "queued": 0,
        "processed": 0,
        "ignored": 0,
        "error": 0,
        "other": 0,
    }

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

        linked_command = f.get("Linked_Command")
        if linked_command is None:
            linked_command = []

        if not isinstance(linked_command, list):
            linked_command = [linked_command]

        command_record_id = _pick_first_text(
            f.get("Command_Record_ID"),
            f.get("Command_ID"),
            linked_command,
            payload.get("command_id") if isinstance(payload, dict) else "",
            payload.get("command_record_id") if isinstance(payload, dict) else "",
        )

        flow_id = _pick_first_text(
            f.get("Flow_ID"),
            f.get("Flow"),
            payload.get("flow_id") if isinstance(payload, dict) else "",
            payload.get("flowid") if isinstance(payload, dict) else "",
        )

        root_event_id = _pick_first_text(
            f.get("Root_Event_ID"),
            f.get("Root_Event"),
            payload.get("root_event_id") if isinstance(payload, dict) else "",
            payload.get("rootEventId") if isinstance(payload, dict) else "",
            payload.get("rooteventid") if isinstance(payload, dict) else "",
            payload.get("event_id") if isinstance(payload, dict) else "",
        )

        workspace_id = _pick_first_text(
            f.get("Workspace_ID"),
            f.get("Workspace"),
            payload.get("workspace_id") if isinstance(payload, dict) else "",
            payload.get("workspaceId") if isinstance(payload, dict) else "",
            payload.get("workspace") if isinstance(payload, dict) else "",
        )

        created_at = _pick_first_text(
            f.get("Created_At"),
            f.get("Created"),
            f.get("created_at"),
        )

        updated_at = _pick_first_text(
            f.get("Updated_At"),
            f.get("Last_Updated_At"),
            f.get("updated_at"),
            f.get("Processed_At"),
            created_at,
        )

        processed_at = _pick_first_text(
            f.get("Processed_At"),
            f.get("processed_at"),
        )

        source_value = _pick_first_text(
            f.get("Source"),
            payload.get("source") if isinstance(payload, dict) else "",
        )

        run_id = _pick_first_text(
            f.get("Run_ID"),
            f.get("Run_Record_ID"),
            payload.get("run_id") if isinstance(payload, dict) else "",
            payload.get("runRecordId") if isinstance(payload, dict) else "",
        )

        event_type = _pick_first_text(
            f.get("Event_Type"),
            f.get("Type"),
            f.get("Name"),
        )

        mapped_capability = _pick_first_text(
            f.get("Mapped_Capability"),
            payload.get("mapped_capability") if isinstance(payload, dict) else "",
        )

        events.append(
            {
                "id": r.get("id"),
                "event_type": event_type,
                "status": status,
                "command_created": _is_truthy(f.get("Command_Created")),
                "linked_command": linked_command,
                "mapped_capability": mapped_capability,
                "processed_at": processed_at or None,
                "created_at": created_at or None,
                "updated_at": updated_at or None,
                "workspace_id": workspace_id or None,
                "flow_id": flow_id or None,
                "root_event_id": root_event_id or None,
                "source": source_value or None,
                "run_id": run_id or None,
                "command_id": command_record_id or None,
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

    event_id = _airtable_create(EVENTS_TABLE_NAME, event_fields)

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

    event_id = _airtable_create(EVENTS_TABLE_NAME, event_fields)

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

    event_id = _airtable_create(EVENTS_TABLE_NAME, fields)

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

    # Source de vérité = Status_select
    formula = "OR({Status_select}='New',{Status_select}='Queued')"
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

        status = str(
            fields.get("Status_select")
            or fields.get("Status")
            or ""
        ).strip().lower()

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

        try:
            res = _create_command_from_event(event_record)
        except Exception as e:
            failed += 1
            errors.append(f"{event_id}: {repr(e)}")
            print(f"[events/process] exception event_id={event_id} error={repr(e)}")
            _event_mark_error(event_id, repr(e))
            continue

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
@app.post("/workspace/create")
async def create_workspace(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    name = _safe_str(body.get("name"))
    if not name:
        raise HTTPException(status_code=400, detail="name is required")

    workspace_id = _normalize_workspace_id(
        body.get("workspace_id") or _generate_workspace_id_from_name(name)
    )

    existing = _get_workspace_record_by_id(workspace_id)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"workspace already exists: {workspace_id}",
        )

    plan = _safe_str(body.get("plan") or "monitor").lower()
    if plan not in ("monitor", "control", "orchestrate"):
        plan = "monitor"

    allowed_capabilities = body.get("allowed_capabilities")
    if not allowed_capabilities:
        if plan == "monitor":
            allowed_capabilities = ["health_tick"]
        elif plan == "control":
            allowed_capabilities = [
                "health_tick",
                "incident_router_v2",
                "incident_deduplicate",
                "incident_create",
            ]
        else:
            allowed_capabilities = [
                "decision_router",
                "http_exec",
                "incident_router_v2",
                "incident_deduplicate",
                "incident_create",
                "internal_escalate",
                "resolve_incident",
                "complete_flow_incident",
                "health_tick",
            ]

    api_key = _generate_workspace_api_key()
    created_at = datetime.now(timezone.utc).isoformat()

    fields = {
        "Name": name,
        "Workspace_ID": workspace_id,
        "Status_select": "active",
        "API_Key": api_key,
        "Owner_Email": _safe_str(body.get("owner_email")),
        "Plan": plan,
        "Allowed_Capabilities": json.dumps(
            allowed_capabilities,
            ensure_ascii=False,
        ),
    }

    record = airtable_create(WORKSPACES_TABLE_NAME, fields)

    return {
        "ok": True,
        "workspace": {
            "record_id": record.get("id", "") if isinstance(record, dict) else "",
            "name": name,
            "workspace_id": workspace_id,
            "status": "active",
            "plan": plan,
            "owner_email": _safe_str(body.get("owner_email")),
            "allowed_capabilities": allowed_capabilities,
            "created_at": created_at,
        },
        "api_key": api_key,
    }
    
@app.post("/run", response_model=RunResponse)
async def run(request: Request, response: Response) -> RunResponse:
    started = time.time()
    raw = await request.body()

    headers_lc = {k.lower(): v for k, v in request.headers.items()}
    print("[RUN DEBUG] headers_lc =", headers_lc, flush=True)

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            payload = {}

    if not isinstance(payload, dict):
        payload = {}

    # ------------------------------------------------------------
    # Workspace auth (multi-tenant) OR fallback legacy auth
    # ------------------------------------------------------------
    workspace_record = resolve_workspace_from_headers(headers_lc)
    print("[RUN DEBUG] workspace_record =", workspace_record, flush=True)

    if workspace_record:
        payload_input_for_auth = payload.get("input") or {}
        if isinstance(payload_input_for_auth, str):
            try:
                payload_input_for_auth = json.loads(payload_input_for_auth)
            except Exception:
                payload_input_for_auth = {}
        if not isinstance(payload_input_for_auth, dict):
            payload_input_for_auth = {}

        req_workspace_id = str(
            payload_input_for_auth.get("workspace_id")
            or payload.get("workspace_id")
            or ""
        ).strip()

        workspace_id = str(
            workspace_record.get("fields", {}).get("Workspace_ID") or ""
        ).strip()

        if req_workspace_id and req_workspace_id != workspace_id:
            raise HTTPException(status_code=403, detail="workspace_mismatch")
    else:
        verify_request_auth_or_401(raw, headers_lc)
        workspace_id = _extract_workspace_id(payload=payload, request=request)

    # ------------------------------------------------------------
    # Normalize / inject workspace ONLY inside input
    # ------------------------------------------------------------
    payload_input = payload.get("input") or {}

    if isinstance(payload_input, str):
        try:
            payload_input = json.loads(payload_input)
        except Exception:
            payload_input = {}

    if not isinstance(payload_input, dict):
        payload_input = {}

    payload_input = _inject_workspace(payload_input, workspace_id)
    payload["input"] = payload_input

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be a JSON object")

    if "input" in payload and not isinstance(payload.get("input"), dict):
        try:
            payload["input"] = json.loads(payload["input"])
        except Exception:
            payload["input"] = {}

    # ------------------------------------------------------------
    # Auto idempotency_key if missing
    # ------------------------------------------------------------
    capability_name = str(payload.get("capability") or "").strip()
    if not payload.get("idempotency_key"):
        flow_id = str(payload_input.get("flow_id") or "").strip()
        root_event_id = str(payload_input.get("root_event_id") or "").strip()
        payload["idempotency_key"] = (
            f"{workspace_id}:{capability_name}:{flow_id or root_event_id or uuid.uuid4().hex}"
        )

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

        print("[RUN] capability requested =", req.capability, flush=True)
        print("[RUN] resolved fn =", getattr(fn, "__name__", str(fn)), flush=True)
        print("[RUN] about to execute function", flush=True)

        result_obj = fn(req, run_record_id)

        print("[RUN] result_obj type =", type(result_obj).__name__, flush=True)
        print("[RUN] result_obj repr =", repr(result_obj), flush=True)

        # ------------------------------------------------------------
        # GUARD CRITIQUE
        # ------------------------------------------------------------
        if not isinstance(result_obj, dict):
            print(
                "[RUN WARNING] capability returned non-dict -> forcing safe result",
                flush=True,
            )
            result_obj = {
                "ok": False,
                "error": "capability_returned_none_or_invalid",
                "capability": req.capability,
                "run_record_id": run_record_id,
            }

        next_cmds = result_obj.get("next_commands")

        if isinstance(next_cmds, list) and next_cmds:
            spawned_results = []

            for cmd in next_cmds:
                try:
                    cmd = _normalize_keys_deep(cmd)

                    spawn_res = _create_command_from_next_command(
                        next_cmd=cmd,
                        parent_run_id=run_record_id,
                        workspace_id=(req.input or {}).get("workspace_id")
                        if isinstance(req.input, dict)
                        else None,
                    )
                    spawned_results.append(spawn_res)

                    print(
                        "[worker.spawn] next_command -> command",
                        {
                            "capability": cmd.get("capability") if isinstance(cmd, dict) else None,
                            "ok": spawn_res.get("ok"),
                            "mode": spawn_res.get("mode"),
                            "command_record_id": spawn_res.get("command_record_id"),
                        },
                        flush=True,
                    )
                except Exception as e:
                    err = {
                        "ok": False,
                        "error": repr(e),
                        "capability": cmd.get("capability") if isinstance(cmd, dict) else None,
                    }
                    spawned_results.append(err)
                    print("[worker.spawn] failed to create command:", err, flush=True)

            result_obj["spawn_summary"] = {
                "ok": all(bool(x.get("ok")) for x in spawned_results) if spawned_results else True,
                "spawned": len([x for x in spawned_results if x.get("ok")]),
                "failed": len([x for x in spawned_results if not x.get("ok")]),
                "results": spawned_results,
            }

        if "run_record_id" not in result_obj:
            result_obj["run_record_id"] = run_record_id

        finish_system_run(run_record_id, "Done", result_obj)

        try:
            _touch_workspace_last_seen(workspace_id)
        except Exception as touch_err:
            print(f"[workspace] touch skipped err={repr(touch_err)}", flush=True)

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
        try:
            fail_system_run(run_record_id, str(e.detail))
        except Exception as fail_err:
            print("[RUN ERROR] fail_system_run failed =", repr(fail_err), flush=True)
            traceback.print_exc()
        raise

    except Exception as e:
        print("[RUN ERROR] repr =", repr(e), flush=True)
        traceback.print_exc()

        try:
            fail_system_run(run_record_id, repr(e))
        except Exception as fail_err:
            print("[RUN ERROR] fail_system_run failed =", repr(fail_err), flush=True)
            traceback.print_exc()

        raise HTTPException(status_code=500, detail=repr(e))
# ============================================================
# Incidents / graphs / details
# ============================================================
def _airtable_scalar(value):
    if value is None:
        return ""

    if isinstance(value, list):
        for item in value:
            picked = _airtable_scalar(item)
            if picked != "":
                return picked
        return ""

    if isinstance(value, dict):
        for key in ("id", "name", "value", "text"):
            if key in value:
                picked = _airtable_scalar(value.get(key))
                if picked != "":
                    return picked
        return ""

    if isinstance(value, str):
        return value.strip()

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)

    if isinstance(value, bool):
        return "true" if value else "false"

    return str(value).strip()


def _airtable_number(value):
    if value is None or value == "":
        return None

    if isinstance(value, list):
        for item in value:
            num = _airtable_number(item)
            if num is not None:
                return num
        return None

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value

    text_value = _airtable_scalar(value)
    if not text_value:
        return None

    try:
        if "." in text_value:
            return float(text_value)
        return int(text_value)
    except Exception:
        try:
            return float(text_value.replace(",", "."))
        except Exception:
            return None


def _pick_field(fields: dict, *names: str):
    for name in names:
        if name in fields:
            value = fields.get(name)
            picked = _airtable_scalar(value)
            if picked != "":
                return picked
    return ""


def _is_resolved_incident(status: str, resolved_at: str) -> bool:
    normalized_status = str(status or "").strip().lower()
    return bool(resolved_at) or normalized_status in {
        "resolved",
        "closed",
        "done",
        "résolu",
        "resolve",
    }


@app.get("/incidents")
def get_incidents(flow_id: str = Query(default="")):
    try:
        if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
            return {
                "ok": True,
                "source": {"ok": False, "reason": "missing_airtable_env"},
                "count": 0,
                "stats": {
                    "open": 0,
                    "critical": 0,
                    "warning": 0,
                    "resolved": 0,
                    "other": 0,
                },
                "incidents": [],
                "ts": datetime.now(timezone.utc).isoformat(),
            }

        effective_table = INCIDENTS_TABLE_NAME
        effective_view = INCIDENTS_VIEW_NAME or "Active"
        requested_flow_id = str(flow_id or "").strip()

        print("[AIRTABLE GET] table =", effective_table)
        print("[AIRTABLE GET] view =", effective_view)
        print("[AIRTABLE GET] flow_id =", requested_flow_id or "(none)")
        print("[AIRTABLE GET] url =", _airtable_url(effective_table))

        response = requests.get(
            _airtable_url(effective_table),
            headers={
                "Authorization": f"Bearer {AIRTABLE_API_KEY}",
                "Accept": "application/json",
            },
            params={
                "maxRecords": 100,
                "view": effective_view,
            },
            timeout=20,
        )
        response.raise_for_status()

        payload = response.json()
        records = payload.get("records", []) or []

        incidents = []
        stats = {
            "open": 0,
            "critical": 0,
            "warning": 0,
            "resolved": 0,
            "other": 0,
        }

        for r in records:
            f = r.get("fields", {}) or {}

            record_id = str(r.get("id") or "").strip()

            status = _pick_field(
                f,
                "Status_select",
                "Statut incident",
                "status_select",
                "status",
                "Status",
            )

            severity = _pick_field(
                f,
                "Severity",
                "Urgence IA",
                "severity",
            )

            raw_sla_status = _pick_field(
                f,
                "SLA_Status",
                "SLA status",
                "sla_status",
                "SLA",
            )

            title = _pick_field(
                f,
                "Name",
                "Title",
                "Incident_Title",
                "Error_Message",
                "Résumé",
            ) or "Untitled incident"

            workspace_id = _pick_field(
                f,
                "Workspace_ID",
                "workspace_id",
                "Workspace",
                "workspace",
            )

            linked_run = _pick_field(
                f,
                "Linked_Run",
                "Run_Record_ID",
                "run_record_id",
                "run_id",
                "Run_ID",
                "Linked run",
            )

            linked_command = _pick_field(
                f,
                "Linked_Command",
                "Command_ID",
                "command_id",
                "Linked command",
            )

            created_at = _pick_field(
                f,
                "Created time",
                "Created_Time",
                "created_at",
                "Created_At",
            )

            updated_at = _pick_field(
                f,
                "Last modified time",
                "Updated_At",
                "updated_at",
                "Last_Seen_At",
            )

            opened_at = _pick_field(
                f,
                "Opened_At",
                "opened_at",
            ) or created_at

            resolved_at = _pick_field(
                f,
                "Resolved_At",
                "resolved_at",
            )

            current_flow_id = _pick_field(
                f,
                "Flow_ID",
                "flow_id",
            )

            root_event_id = _pick_field(
                f,
                "Root_Event_ID",
                "root_event_id",
            )

            command_id = _pick_field(
                f,
                "Command_ID",
                "command_id",
            )

            run_record_id = _pick_field(
                f,
                "Run_Record_ID",
                "run_record_id",
                "Linked_Run",
                "run_id",
                "Run_ID",
            )

            category = _pick_field(
                f,
                "Category",
                "category",
            )

            reason = _pick_field(
                f,
                "Reason",
                "reason",
            )

            resolution_note = _pick_field(
                f,
                "Resolution_Note",
                "resolution_note",
                "resolutionNote",
                "Resolution Note",
            )

            last_action = _pick_field(
                f,
                "Last_Action",
                "last_action",
                "lastAction",
                "Last Action",
            )

            error_id = _pick_field(
                f,
                "Error_ID",
                "error_id",
                "Incident_Code",
                "incident_code",
                "Error Code",
                "Incident_Record_ID",
                "incident_record_id",
            )

            worker = _pick_field(
                f,
                "Worker",
                "worker",
            )

            sla_remaining_minutes = _airtable_number(
                f.get("SLA_Remaining_Minutes")
                or f.get("SLA remaining minutes")
                or f.get("Temps restant SLA")
            )

            normalized_status = status.lower().strip()
            normalized_severity = severity.lower().strip()
            resolved_like = _is_resolved_incident(status, resolved_at)

            if resolved_like:
                sla_status = "resolved"
            elif raw_sla_status:
                sla_status = str(raw_sla_status).strip().lower()
            else:
                if isinstance(sla_remaining_minutes, (int, float)):
                    if sla_remaining_minutes < 0:
                        sla_status = "breached"
                    elif sla_remaining_minutes <= 15:
                        sla_status = "warning"
                    else:
                        sla_status = "open"
                else:
                    sla_status = "open"

            if requested_flow_id:
                allowed_values = {
                    str(current_flow_id or "").strip(),
                    str(root_event_id or "").strip(),
                    str(record_id or "").strip(),
                }
                if requested_flow_id not in allowed_values:
                    continue

            incidents.append(
                {
                    "id": record_id,
                    "title": title,
                    "name": title,
                    "status": status,
                    "severity": severity,
                    "sla_status": sla_status,
                    "sla_remaining_minutes": sla_remaining_minutes,
                    "workspace_id": workspace_id,
                    "workspace": workspace_id,
                    "linked_run": linked_run,
                    "linked_command": linked_command,
                    "command_id": command_id or linked_command,
                    "run_record_id": run_record_id or linked_run,
                    "flow_id": current_flow_id,
                    "root_event_id": root_event_id,
                    "category": category,
                    "reason": reason,
                    "error_id": error_id,
                    "resolution_note": resolution_note,
                    "last_action": last_action,
                    "created_at": created_at,
                    "updated_at": updated_at,
                    "opened_at": opened_at,
                    "resolved_at": resolved_at or None,
                    "source": "Incidents",
                    "worker": worker,
                    "fields": f,
                }
            )

            if resolved_like:
                stats["resolved"] += 1
            elif normalized_status in {"escalated", "escalade", "escaladé"}:
                stats["warning"] += 1
            elif normalized_severity in {"critical", "critique"}:
                stats["critical"] += 1
            elif normalized_status in {"open", "opened", "new", "active", "en cours"}:
                stats["open"] += 1
            elif normalized_severity in {
                "high",
                "warning",
                "warn",
                "medium",
                "surveillance",
                "moyen",
            }:
                stats["warning"] += 1
            else:
                stats["other"] += 1

        return {
            "ok": True,
            "source": {
                "ok": True,
                "table": effective_table,
                "view": effective_view,
                "flow_id": requested_flow_id or None,
            },
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

@app.get("/commands/{command_id}")
def get_command_by_id(command_id: str) -> Dict[str, Any]:
    try:
        if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
            raise HTTPException(status_code=500, detail="missing_airtable_env")

        response = requests.get(
            _airtable_url(COMMANDS_TABLE_NAME),
            headers={
                "Authorization": f"Bearer {AIRTABLE_API_KEY}",
                "Accept": "application/json",
            },
            params={
                "filterByFormula": f"RECORD_ID()='{command_id}'",
                "maxRecords": 1,
            },
            timeout=20,
        )

        response.raise_for_status()
        payload = response.json()
        records = payload.get("records", [])

        if not records:
            raise HTTPException(status_code=404, detail="command_not_found")

        r = records[0]
        f = r.get("fields", {}) or {}

        flow_meta = _extract_flow_metadata_from_command_fields(f)

        command = {
            "id": r.get("id"),
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
            "flow_id": flow_meta.get("flow_id"),
            "root_event_id": flow_meta.get("root_event_id"),
            "parent_command_id": flow_meta.get("parent_command_id"),
            "step_index": flow_meta.get("step_index"),
            "input_json": flow_meta.get("input_json"),
            "result_json": flow_meta.get("result_json"),
            "worker": f.get("Locked_By") or f.get("Worker"),
            "workspace_id": f.get("Workspace_ID") or f.get("workspace_id"),
            "started_at": f.get("Started_At"),
            "finished_at": f.get("Finished_At"),
            "created_at": f.get("Created_At") or f.get("created_at"),
        }

        return {
            "ok": True,
            "command": command,
            "ts": utc_now_iso(),
        }

    except HTTPException:
        raise
    except requests.HTTPError as exc:
        detail = exc.response.text if getattr(exc, "response", None) is not None else str(exc)
        raise HTTPException(
            status_code=502,
            detail=f"Airtable command request failed: {detail}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"detail": "Internal error", "error": repr(exc)},
        )
        
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

