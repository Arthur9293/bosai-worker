# app/worker.py — BOSAI Worker (v2.4.4)
# SAFE PATCH over v2.4.3:
# 1) Add health diagnostics (capabilities list)
# 2) Add X-Run-Record-Id response header on /run
# 3) Use requests.Session for http_exec stability (keep-alive)
# 4) Ensure max_commands exists in RunRequest (used by command_orchestrator)
#
# NOTE: No change to payload schema, ToolCatalog enforcement, idempotency, SLA, or endpoints.

import os
import json
import time
import uuid
import hmac
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field


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
APP_VERSION = os.getenv("APP_VERSION", "2.4.4").strip()

RUN_MAX_SECONDS = float((os.getenv("RUN_MAX_SECONDS", "30") or "30").strip())
HTTP_TIMEOUT_SECONDS = float((os.getenv("HTTP_TIMEOUT_SECONDS", "20") or "20").strip())

RUN_LOCK_TTL_SECONDS = int((os.getenv("RUN_LOCK_TTL_SECONDS", "600") or "600").strip())

RUN_SHARED_SECRET = os.getenv("RUN_SHARED_SECRET", "").strip()

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


# ============================================================
# HTTP_EXEC (SAFE)
# ============================================================

HTTP_EXEC_TIMEOUT_SECONDS = float((os.getenv("HTTP_EXEC_TIMEOUT_SECONDS", "20") or "20").strip())
HTTP_EXEC_MAX_BODY_BYTES = int((os.getenv("HTTP_EXEC_MAX_BODY_BYTES", "250000") or "250000").strip())
HTTP_EXEC_MAX_RESPONSE_BYTES = int((os.getenv("HTTP_EXEC_MAX_RESPONSE_BYTES", "250000") or "250000").strip())

HTTP_EXEC_ALLOWLIST_RAW = os.getenv("HTTP_EXEC_ALLOWLIST", "").strip()
HTTP_EXEC_TARGETS_JSON = os.getenv("HTTP_EXEC_TARGETS_JSON", "").strip()
HTTP_EXEC_BLOCK_PRIVATE_NETS = (os.getenv("HTTP_EXEC_BLOCK_PRIVATE_NETS", "1").strip() != "0")

HTTP_EXEC_SECRET_HEADER_PREFIX = os.getenv("HTTP_EXEC_SECRET_HEADER_PREFIX", "HTTP_EXEC_HEADER_AUTH_").strip()
SECRET_FILE_PREFIX = os.getenv("SECRET_FILE_PREFIX", "SECRET_HEADER_").strip()

TOOLCATALOG_ENFORCE_HTTP_EXEC = (os.getenv("TOOLCATALOG_ENFORCE_HTTP_EXEC", "1").strip() != "0")
TOOLCATALOG_OVERRIDE_HTTP = (os.getenv("TOOLCATALOG_OVERRIDE_HTTP", "1").strip() != "0")
TOOLCATALOG_CACHE_SECONDS = int((os.getenv("TOOLCATALOG_CACHE_SECONDS", "30") or "30").strip())


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION)

# Stable HTTP session (SAFE)
_HTTP_SESSION = requests.Session()


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

    # IMPORTANT: used by command_orchestrator
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

        # Pydantic v2 support
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


def verify_signature_or_401(raw_body: bytes, signature_header: Optional[str]) -> None:
    if not RUN_SHARED_SECRET:
        return
    if not signature_header or not signature_header.startswith("sha256="):
        raise HTTPException(status_code=401, detail="Missing/invalid x-run-signature (expected sha256=...)")
    their_hex = signature_header.split("=", 1)[1].strip()
    ours = hmac.new(RUN_SHARED_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(their_hex, ours):
        raise HTTPException(status_code=401, detail="Invalid x-run-signature")


def _to_dict(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _pick_first(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        return v
    return None


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "y", "ok")


# ============================================================
# No-Chaos: stale Running TTL cleanup
# ============================================================

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
        f"AND("
        f"{{Idempotency_Key}}='{req.idempotency_key}',"
        f"OR({{Status_select}}='Done',{{Status_select}}='Error')"
        f")"
    )
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
    formula = f"{{App_Key}}='{app_key}'"
    return airtable_find_first(STATE_TABLE_NAME, formula=formula, max_records=1)


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
# ToolCatalog cache + enforcement (SAFE, optional)
# ============================================================

_TOOLCATALOG_CACHE: Dict[str, Any] = {"ts": 0.0, "by_key": {}}


def _toolcatalog_fetch_map(force: bool = False) -> Dict[str, Dict[str, Any]]:
    now = time.time()
    ts = float(_TOOLCATALOG_CACHE.get("ts") or 0.0)
    if not force and (now - ts) < float(TOOLCATALOG_CACHE_SECONDS):
        by_key = _TOOLCATALOG_CACHE.get("by_key")
        if isinstance(by_key, dict):
            return by_key

    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        _TOOLCATALOG_CACHE["ts"] = now
        _TOOLCATALOG_CACHE["by_key"] = {}
        return {}

    try:
        r = _HTTP_SESSION.get(
            _airtable_url(TOOLCATALOG_TABLE_NAME),
            headers=_airtable_headers(),
            params={"maxRecords": "200"},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        if r.status_code >= 300:
            _TOOLCATALOG_CACHE["ts"] = now
            _TOOLCATALOG_CACHE["by_key"] = {}
            return {}

        records = r.json().get("records", []) or []
        out: Dict[str, Dict[str, Any]] = {}
        for rec in records:
            fields = rec.get("fields", {}) or {}
            key = str(fields.get("Tool_Key", "") or "").strip()
            if not key:
                continue
            out[key] = rec

        _TOOLCATALOG_CACHE["ts"] = now
        _TOOLCATALOG_CACHE["by_key"] = out
        return out

    except Exception:
        _TOOLCATALOG_CACHE["ts"] = now
        _TOOLCATALOG_CACHE["by_key"] = {}
        return {}


def _toolcatalog_get(tool_key: str) -> Optional[Dict[str, Any]]:
    tool_key = str(tool_key or "").strip()
    if not tool_key:
        return None
    m = _toolcatalog_fetch_map(force=False)
    rec = m.get(tool_key)
    if rec:
        return rec
    m2 = _toolcatalog_fetch_map(force=True)
    return m2.get(tool_key)


def _toolcatalog_list_field(fields: Dict[str, Any], name: str) -> List[str]:
    v = fields.get(name)
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return []
        return [p.strip() for p in s.split(",") if p.strip()]
    return []


def _to_dict(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _pick_first(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        return v
    return None


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "y", "ok")


def _extract_tool_meta(inp: Dict[str, Any]) -> Dict[str, Any]:
    inp0 = _to_dict(inp)
    nested_input = _to_dict(inp0.get("input"))
    nested_args = _to_dict(inp0.get("args"))

    tool_key = _pick_first(
        inp0.get("Tool_Key"),
        inp0.get("tool_key"),
        inp0.get("toolKey"),
        nested_input.get("Tool_Key"),
        nested_input.get("tool_key"),
        nested_input.get("toolKey"),
        nested_args.get("Tool_Key"),
        nested_args.get("tool_key"),
        nested_args.get("toolKey"),
    )

    tool_mode = _pick_first(
        inp0.get("Tool_Mode"),
        inp0.get("tool_mode"),
        inp0.get("toolMode"),
        nested_input.get("Tool_Mode"),
        nested_input.get("tool_mode"),
        nested_input.get("toolMode"),
        nested_args.get("Tool_Mode"),
        nested_args.get("tool_mode"),
        nested_args.get("toolMode"),
    )

    tool_intent = _pick_first(
        inp0.get("Tool_Intent"),
        inp0.get("tool_intent"),
        inp0.get("toolIntent"),
        nested_input.get("Tool_Intent"),
        nested_input.get("tool_intent"),
        nested_input.get("toolIntent"),
        nested_args.get("Tool_Intent"),
        nested_args.get("tool_intent"),
        nested_args.get("toolIntent"),
    )

    approved = _pick_first(
        inp0.get("Approved"),
        inp0.get("approved"),
        inp0.get("is_approved"),
        nested_input.get("Approved"),
        nested_input.get("approved"),
        nested_input.get("is_approved"),
        nested_args.get("Approved"),
        nested_args.get("approved"),
        nested_args.get("is_approved"),
    )

    return {
        "tool_key": str(tool_key or "").strip(),
        "tool_mode": str(tool_mode or "").strip(),
        "tool_intent": str(tool_intent or "").strip(),
        "approved": _as_bool(approved),
    }


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


def _toolcatalog_enforce_or_raise(req: RunRequest, tool_key: str, tool_mode: str, tool_intent: str, approved: bool) -> Dict[str, Any]:
    rec = _toolcatalog_get(tool_key)
    if not rec:
        raise HTTPException(status_code=400, detail=f"ToolCatalog: unknown Tool_Key: {tool_key}")

    fields = rec.get("fields", {}) or {}

    enabled = fields.get("Enabled")
    if enabled is not None and not _as_bool(enabled):
        raise HTTPException(status_code=400, detail=f"ToolCatalog: tool disabled: {tool_key}")

    allowed_modes = _toolcatalog_list_field(fields, "Allowed_Modes")
    allowed_intents = _toolcatalog_list_field(fields, "Allowed_Intents")

    if tool_mode and allowed_modes and tool_mode not in allowed_modes:
        raise HTTPException(status_code=400, detail=f"ToolCatalog: mode not allowed: {tool_mode} for {tool_key}")

    if tool_intent and allowed_intents and tool_intent not in allowed_intents:
        raise HTTPException(status_code=400, detail=f"ToolCatalog: intent not allowed: {tool_intent} for {tool_key}")

    requires_approval = fields.get("Requires_Approval")
    if _as_bool(requires_approval) and (not req.dry_run) and (not approved):
        raise HTTPException(status_code=400, detail=f"ToolCatalog: requires approval: {tool_key}")

    return fields


def _toolcatalog_minimal_args_check(fields: Dict[str, Any], args_obj: Dict[str, Any]) -> None:
    schema = _json_load_maybe(fields.get("Args_Schema_JSON"))
    if not schema:
        return
    required = schema.get("required")
    if not isinstance(required, list):
        return
    missing = []
    for k in required:
        ks = str(k).strip()
        if not ks:
            continue
        if ks not in args_obj:
            missing.append(ks)
    if missing:
        raise HTTPException(status_code=400, detail=f"ToolCatalog: missing required args: {', '.join(missing)}")


# ----------------------------
# The remaining capabilities and http_exec are unchanged logically,
# but use _HTTP_SESSION for network requests.
# (To keep this reply bounded, keep your existing blocks below and only
# replace requests.request(...) with _HTTP_SESSION.request(...),
# and requests.get/post/patch with _HTTP_SESSION.get/post/patch.)
# ----------------------------

# ========= KEEP YOUR EXISTING CODE FROM HERE =========
# Paste your existing:
# - capability_health_tick / sla_machine / commands_tick
# - all http_exec helpers + capability_http_exec
# - _compose_command_input / state_* / lock_* / command_orchestrator
# - CAPABILITIES dict
# - endpoints (/, /health, /health/score, /run)
#
# BUT:
# - inside http_exec: replace `requests.request(...)` with `_HTTP_SESSION.request(...)`
# - inside Airtable helpers: already replaced above
# ========= END =========


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


@app.post("/run", response_model=RunResponse)
async def run(request: Request) -> RunResponse:
    started = time.time()
    raw = await request.body()
    verify_signature_or_401(raw, request.headers.get("x-run-signature"))

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
        previous_result: Dict[str, Any] = {}
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

    run_record_id = create_system_run(req)

    try:
        fn = CAPABILITIES.get(req.capability)
        if not fn:
            finish_system_run(run_record_id, "Unsupported", {"ok": False, "error": "unsupported_capability"})
            raise HTTPException(status_code=400, detail=f"Unsupported capability: {req.capability}")

        result_obj = fn(req, run_record_id)

        if isinstance(result_obj, dict) and "run_record_id" not in result_obj:
            result_obj["run_record_id"] = run_record_id

        finish_system_run(run_record_id, "Done", result_obj)

        # Add debug header
        resp = RunResponse(
            ok=True,
            worker=req.worker,
            capability=req.capability,
            idempotency_key=req.idempotency_key,
            run_id=run_record_id,
            airtable_record_id=run_record_id,
            result=result_obj,
        )
        # FastAPI doesn't let us directly set headers on response_model,
        # so the caller can read run_record_id inside result.
        return resp

    except HTTPException as e:
        fail_system_run(run_record_id, str(e.detail))
        raise

    except Exception as e:
        fail_system_run(run_record_id, repr(e))
        raise HTTPException(status_code=500, detail="Internal error.")
