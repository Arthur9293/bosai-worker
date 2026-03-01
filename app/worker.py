# app/worker.py — BOSAI Worker (v2.4.2)
# Base: your v2.4.1 (as pasted)
#
# FIXES (SAFE):
# 1) /run dry_run: DO NOT short-circuit. We call the capability so http_exec returns full dry_run details.
# 2) http_exec secrets: support BOTH env-var style and Render "Secret Files" style.
#    - env var:    HTTP_EXEC_HEADER_AUTH_<KEY>
#    - secret file: /etc/secrets/SECRET_HEADER_<KEY>
#    - legacy env: SECRET_HEADER_<KEY> (optional)
#    - convenience: MAKE_API_TOKEN (when KEY=="MAKE")
# 3) http_exec ToolCatalog: can read optional fields:
#    - Secret_Header_Keys (list or "A,B,C")
#    - Authorization_Mode ("token"|"bearer"|"raw")  # optional
#    If present, merges with request secret_header_keys.
#
# NOTE for Make API:
# - Make v2 API typically expects: Authorization: Token <MAKE_API_TOKEN>
# - If you stored only the token, we will auto-format to "Token <token>" (configurable by Authorization_Mode).

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
APP_VERSION = os.getenv("APP_VERSION", "2.4.2").strip()

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

# Prefix used for env-var secret headers (you already use this)
HTTP_EXEC_SECRET_HEADER_PREFIX = os.getenv("HTTP_EXEC_SECRET_HEADER_PREFIX", "HTTP_EXEC_HEADER_AUTH_").strip()

# Additional secret file prefix (Render Secret Files)
SECRET_FILE_PREFIX = os.getenv("SECRET_FILE_PREFIX", "SECRET_HEADER_").strip()

# ToolCatalog behavior toggles (SAFE defaults)
TOOLCATALOG_ENFORCE_HTTP_EXEC = (os.getenv("TOOLCATALOG_ENFORCE_HTTP_EXEC", "1").strip() != "0")
TOOLCATALOG_OVERRIDE_HTTP = (os.getenv("TOOLCATALOG_OVERRIDE_HTTP", "1").strip() != "0")  # URL/Method/Headers/Timeout
TOOLCATALOG_CACHE_SECONDS = int((os.getenv("TOOLCATALOG_CACHE_SECONDS", "30") or "30").strip())


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION)


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

        # compat keys (SAFE): map + remove aliases to satisfy extra="forbid"
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

        # Pydantic v1 support
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
        r = requests.get(
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

    if tool_mode:
        if allowed_modes and tool_mode not in allowed_modes:
            raise HTTPException(status_code=400, detail=f"ToolCatalog: mode not allowed: {tool_mode} for {tool_key}")

    if tool_intent:
        if allowed_intents and tool_intent not in allowed_intents:
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


# ============================================================
# Capabilities
# ============================================================

def capability_health_tick(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    return {"ok": True, "probe": "airtable_ok", "ts": utc_now_iso(), "run_record_id": run_record_id}


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


# ----------------------------
# Commands Tick (SAFE)
# ----------------------------

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
            {
                "Is_Locked": True,
                "Locked_At": now,
                "Locked_By": req.worker,
                "Last_Status": "Running",
                "Last_Error": "",
                "Linked_Run": [run_record_id],
            },
            {
                "Is_Locked": True,
                "Locked_At": now,
                "Locked_By": req.worker,
                "Last_Status": "Running",
            },
            {
                "Is_Locked": True,
                "Locked_By": req.worker,
            },
            {
                "Status_select": "Running",
                "Linked_Run": [run_record_id],
                "Error_Message": "",
            },
            {
                "Status_select": "Running",
            },
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


# ----------------------------
# HTTP_EXEC helpers (SAFE)
# ----------------------------

def _normalize_allowlist_hosts(raw: str) -> List[str]:
    raw = (raw or "").strip()
    if not raw:
        return []
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    out: List[str] = []
    seen = set()

    for p in parts:
        pl = p.strip().lower()
        if not pl:
            continue

        if pl.startswith("*.") and "/" not in pl and "://" not in pl:
            if pl not in seen:
                seen.add(pl)
                out.append(pl)
            continue

        if "://" in pl:
            try:
                pu = urlparse(pl)
                h = (pu.hostname or "").strip().lower()
                if h and h not in seen:
                    seen.add(h)
                    out.append(h)
                continue
            except Exception:
                pass

        if "/" in pl:
            pl = pl.split("/", 1)[0].strip()

        if pl and pl not in seen:
            seen.add(pl)
            out.append(pl)

    return out


HTTP_EXEC_ALLOWLIST = _normalize_allowlist_hosts(HTTP_EXEC_ALLOWLIST_RAW)

_PRIVATE_HOST_PATTERNS = [
    r"^localhost$",
    r"^127\.",
    r"^10\.",
    r"^192\.168\.",
    r"^172\.(1[6-9]|2\d|3[0-1])\.",
    r"^\[::1\]$",
]


def _is_private_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if not h:
        return True
    for p in _PRIVATE_HOST_PATTERNS:
        if re.search(p, h):
            return True
    return False


def _host_matches_allowlist(host: str, allowlist: List[str]) -> bool:
    if not allowlist:
        return False
    host = host.lower()
    for rule in allowlist:
        rule_l = (rule or "").lower()
        if not rule_l:
            continue
        if rule_l.startswith("*."):
            suffix = rule_l[1:]  # ".example.com"
            if host.endswith(suffix):
                return True
        else:
            if host == rule_l:
                return True
    return False


def _safe_headers_for_log(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk in ("authorization", "cookie", "x-api-key", "set-cookie"):
            out[k] = "***redacted***"
        else:
            out[k] = v
    return out


def _truncate_bytes(b: bytes, max_bytes: int) -> bytes:
    if b is None:
        return b
    if len(b) <= max_bytes:
        return b
    return b[:max_bytes]


def _http_exec_targets() -> Dict[str, str]:
    if not HTTP_EXEC_TARGETS_JSON:
        return {}
    try:
        obj = json.loads(HTTP_EXEC_TARGETS_JSON)
        if isinstance(obj, dict):
            out: Dict[str, str] = {}
            for k, v in obj.items():
                ks = str(k).strip()
                vs = str(v).strip()
                if ks and vs:
                    out[ks] = vs
            return out
        return {}
    except Exception:
        return {}


def _resolve_http_target(maybe_url_or_alias: str) -> str:
    s = (maybe_url_or_alias or "").strip()
    if not s:
        return ""
    if s.startswith("http://") or s.startswith("https://"):
        return s
    return _http_exec_targets().get(s, "")


def _validate_http_exec_url(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="HTTP_EXEC invalid url scheme (must be http/https).")

    host = (parsed.hostname or "").strip().lower()
    if HTTP_EXEC_BLOCK_PRIVATE_NETS and _is_private_host(host):
        raise HTTPException(status_code=400, detail=f"HTTP_EXEC blocked private host: {host}")

    if not _host_matches_allowlist(host, HTTP_EXEC_ALLOWLIST):
        raise HTTPException(status_code=400, detail=f"HTTP_EXEC host not in allowlist: {host}")

    return {"host": host, "scheme": parsed.scheme}


def _read_secret_file(name: str) -> str:
    # Render Secret Files are available at:
    # - /etc/secrets/<filename>
    # - or app root sometimes (but /etc/secrets is canonical)
    for base in ("/etc/secrets", "."):
        path = f"{base}/{name}"
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return (f.read() or "").strip()
        except Exception:
            continue
    return ""


def _format_authorization(raw: str, mode: str) -> str:
    """
    mode:
      - raw:    use as-is
      - token:  "Token <raw>" if raw has no space
      - bearer: "Bearer <raw>" if raw has no space
    """
    s = (raw or "").strip()
    if not s:
        return ""
    if mode == "raw":
        return s
    # already formatted
    if " " in s:
        return s
    if mode == "bearer":
        return f"Bearer {s}"
    # default: token
    return f"Token {s}"


def _build_secret_headers(header_keys: List[str], auth_mode: str = "token") -> Dict[str, str]:
    """
    For each KEY in secret_header_keys:
      1) env var: HTTP_EXEC_HEADER_AUTH_<KEY>
      2) env var: SECRET_HEADER_<KEY> (legacy)
      3) secret file: /etc/secrets/SECRET_HEADER_<KEY>
      4) if KEY=="MAKE": MAKE_API_TOKEN
    Sets Authorization header from the first found.
    """
    out: Dict[str, str] = {}
    for key in header_keys or []:
        k = str(key).strip()
        if not k:
            continue

        # 1) env var prefix (your current pattern)
        v = os.getenv(f"{HTTP_EXEC_SECRET_HEADER_PREFIX}{k}", "").strip()

        # 2) legacy env var
        if not v:
            v = os.getenv(f"{SECRET_FILE_PREFIX}{k}", "").strip()

        # 3) secret file
        if not v:
            v = _read_secret_file(f"{SECRET_FILE_PREFIX}{k}")

        # 4) convenience for Make
        if not v and k.upper() == "MAKE":
            v = os.getenv("MAKE_API_TOKEN", "").strip()

        if v:
            out["Authorization"] = _format_authorization(v, auth_mode)
            # only one Authorization expected
            break

    return out


def _extract_http_exec_input(inp: Dict[str, Any]) -> Dict[str, Any]:
    inp0 = _to_dict(inp)
    nested_input = _to_dict(inp0.get("input"))
    nested_args = _to_dict(inp0.get("args"))

    url_like = _pick_first(
        inp0.get("url"),
        inp0.get("http_target"),
        inp0.get("target"),
        inp0.get("tool"),
        nested_input.get("url"),
        nested_input.get("http_target"),
        nested_input.get("target"),
        nested_input.get("tool"),
        nested_args.get("url"),
        nested_args.get("http_target"),
        nested_args.get("target"),
        nested_args.get("tool"),
    )

    method = _pick_first(inp0.get("method"), nested_input.get("method"), nested_args.get("method"))
    headers = _pick_first(inp0.get("headers"), nested_input.get("headers"), nested_args.get("headers"))
    headers = headers if isinstance(headers, dict) else {}

    secret_keys = _pick_first(
        inp0.get("secret_header_keys"),
        nested_input.get("secret_header_keys"),
        nested_args.get("secret_header_keys"),
    )
    secret_keys = secret_keys if isinstance(secret_keys, list) else []

    json_body = _pick_first(
        inp0.get("json"),
        inp0.get("body"),
        nested_input.get("json"),
        nested_input.get("body"),
        nested_args.get("json"),
        nested_args.get("body"),
    )

    raw_data = _pick_first(inp0.get("data"), nested_input.get("data"), nested_args.get("data"))

    return {
        "raw_target": str(url_like or "").strip(),
        "method": str(method or "POST").strip().upper(),
        "headers": headers,
        "secret_header_keys": secret_keys,
        "json_body": json_body,
        "raw_data": raw_data,
    }


def _toolcatalog_apply_overrides(tool_fields: Dict[str, Any], extracted: Dict[str, Any]) -> Tuple[str, str, Dict[str, str], float]:
    url_override = str(tool_fields.get("URL", "") or "").strip()
    base_url = str(tool_fields.get("Base_URL", "") or "").strip()
    method_override = str(tool_fields.get("Method", "") or "").strip().upper()

    url_final = extracted.get("raw_target", "")
    if url_override:
        url_final = url_override
    elif base_url and url_final and not url_final.startswith("http"):
        url_final = base_url.rstrip("/") + "/" + url_final.lstrip("/")

    method_final = extracted.get("method", "POST")
    if method_override in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        method_final = method_override

    headers_tool = _json_load_maybe(tool_fields.get("Headers_JSON"))
    headers_tool = headers_tool if isinstance(headers_tool, dict) else {}
    headers_in = extracted.get("headers") if isinstance(extracted.get("headers"), dict) else {}
    headers_final: Dict[str, str] = {}
    for k, v in headers_tool.items():
        ks = str(k).strip()
        if ks:
            headers_final[ks] = str(v)
    for k, v in headers_in.items():
        ks = str(k).strip()
        if ks:
            headers_final[ks] = str(v)

    timeout_s = HTTP_EXEC_TIMEOUT_SECONDS
    try:
        t = tool_fields.get("Timeout_S")
        if t is not None and str(t).strip() != "":
            timeout_s = float(t)
    except Exception:
        timeout_s = HTTP_EXEC_TIMEOUT_SECONDS

    return url_final, method_final, headers_final, timeout_s


def _merge_secret_keys(request_keys: List[str], tool_fields: Optional[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    seen = set()

    def add_many(vals: Any):
        if isinstance(vals, list):
            for x in vals:
                xs = str(x).strip()
                if xs and xs not in seen:
                    seen.add(xs)
                    out.append(xs)
        elif isinstance(vals, str):
            for x in [p.strip() for p in vals.split(",") if p.strip()]:
                if x and x not in seen:
                    seen.add(x)
                    out.append(x)

    add_many(request_keys or [])
    if tool_fields:
        add_many(tool_fields.get("Secret_Header_Keys"))
    return out


def capability_http_exec(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    inp = req.input or {}

    if isinstance(inp.get("input"), dict) and inp.get("input"):
        nested = inp.get("input")
        if any(
            k in nested
            for k in (
                "url",
                "http_target",
                "target",
                "tool",
                "method",
                "headers",
                "json",
                "body",
                "data",
                "secret_header_keys",
                "Tool_Key",
                "tool_key",
                "Tool_Mode",
                "tool_mode",
                "Tool_Intent",
                "tool_intent",
                "Approved",
                "approved",
            )
        ):
            inp = nested

    extracted = _extract_http_exec_input(inp)

    tool_meta = _extract_tool_meta(inp)
    tool_key = tool_meta["tool_key"]
    tool_mode = tool_meta["tool_mode"]
    tool_intent = tool_meta["tool_intent"]
    approved = bool(tool_meta["approved"])

    tool_fields: Optional[Dict[str, Any]] = None
    local_timeout = HTTP_EXEC_TIMEOUT_SECONDS

    if TOOLCATALOG_ENFORCE_HTTP_EXEC and tool_key:
        tool_fields = _toolcatalog_enforce_or_raise(req, tool_key, tool_mode, tool_intent, approved)

        args_obj = {}
        if isinstance(extracted.get("json_body"), dict):
            args_obj = extracted.get("json_body")  # type: ignore
        _toolcatalog_minimal_args_check(tool_fields, args_obj)

        if TOOLCATALOG_OVERRIDE_HTTP:
            url_final, method_final, headers_final, timeout_s = _toolcatalog_apply_overrides(tool_fields, extracted)
            extracted["raw_target"] = url_final
            extracted["method"] = method_final
            extracted["headers"] = headers_final
            local_timeout = float(timeout_s)

    raw_target = extracted["raw_target"]
    url = _resolve_http_target(raw_target)

    # SAFE fallback: if Tool_Key provided and still no url, use ToolCatalog.URL
    if not url and tool_fields:
        url = str(tool_fields.get("URL", "") or "").strip()

    if not url:
        raise HTTPException(
            status_code=400,
            detail=(
                "HTTP_EXEC missing url (provide input.url or input.http_target/target/tool; "
                "or set HTTP_EXEC_TARGETS_JSON for alias resolution)."
            ),
        )

    meta = _validate_http_exec_url(url)

    method = str(extracted["method"] or "POST").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        raise HTTPException(status_code=400, detail=f"HTTP_EXEC invalid method: {method}")

    headers_in = extracted["headers"] if isinstance(extracted["headers"], dict) else {}

    # Auth mode from ToolCatalog (optional)
    auth_mode = "token"
    if tool_fields:
        am = str(tool_fields.get("Authorization_Mode", "") or "").strip().lower()
        if am in ("raw", "token", "bearer"):
            auth_mode = am

    merged_secret_keys = _merge_secret_keys(extracted["secret_header_keys"], tool_fields)

    secret_headers = _build_secret_headers(merged_secret_keys, auth_mode=auth_mode)
    headers = {**headers_in, **secret_headers}

    json_body = extracted["json_body"]
    raw_data = extracted["raw_data"]

    if raw_data is not None and json_body is not None:
        raise HTTPException(status_code=400, detail="HTTP_EXEC use json/body OR data, not both.")

    if req.dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "run_record_id": run_record_id,
            "host": meta["host"],
            "method": method,
            "url": url,
            "headers": _safe_headers_for_log(headers),
            "allowlist": HTTP_EXEC_ALLOWLIST,
            "tool_key": tool_key or None,
            "tool_mode": tool_mode or None,
            "tool_intent": tool_intent or None,
            "auth_mode": auth_mode,
            "note": "HTTP call skipped (dry_run).",
        }

    if raw_data is not None:
        if not isinstance(raw_data, (str, bytes)):
            raise HTTPException(status_code=400, detail="HTTP_EXEC data must be str or bytes.")
        raw_bytes = raw_data.encode("utf-8") if isinstance(raw_data, str) else raw_data
        raw_bytes = _truncate_bytes(raw_bytes, HTTP_EXEC_MAX_BODY_BYTES)
        resp = requests.request(method, url, headers=headers, data=raw_bytes, timeout=float(local_timeout))
    else:
        jb = json_body if json_body is not None else {}
        jb_bytes = json.dumps(jb, ensure_ascii=False).encode("utf-8")
        if len(jb_bytes) > HTTP_EXEC_MAX_BODY_BYTES:
            raise HTTPException(status_code=400, detail="HTTP_EXEC json/body too large.")
        resp = requests.request(method, url, headers=headers, json=jb, timeout=float(local_timeout))

    status = resp.status_code
    resp_headers = dict(resp.headers or {})
    content_bytes = _truncate_bytes(resp.content or b"", HTTP_EXEC_MAX_RESPONSE_BYTES)

    parsed_json = None
    text_preview = None
    try:
        parsed_json = json.loads(content_bytes.decode("utf-8"))
    except Exception:
        try:
            text_preview = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            text_preview = None

    ok = 200 <= status < 300
    return {
        "ok": ok,
        "run_record_id": run_record_id,
        "host": meta["host"],
        "method": method,
        "url": url,
        "status_code": status,
        "tool_key": tool_key or None,
        "tool_mode": tool_mode or None,
        "tool_intent": tool_intent or None,
        "auth_mode": auth_mode,
        "request_headers": _safe_headers_for_log(headers),
        "response_headers": {
            k: (v if k.lower() != "set-cookie" else "***redacted***")
            for k, v in resp_headers.items()
        },
        "response_json": parsed_json,
        "response_text": (text_preview[:2000] if text_preview else None),
    }


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
    return str(
        fields.get(
            "Status_select",
            fields.get(
                "Status",
                fields.get("Status_raw", ""),
            ),
        ) or ""
    ).strip()


def capability_command_orchestrator(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
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

        status = _read_command_status(fields)
        if status and status not in ("Queued", "QUEUE", "Queue"):
            blocked += 1
            continue

        capability = str(fields.get("Capability", "")).strip()
        if not capability:
            failed += 1
            try:
                airtable_update(
                    COMMANDS_TABLE_NAME,
                    cid,
                    {
                        "Status_select": "Error",
                        "Error_Message": "Missing Capability",
                        "Linked_Run": [run_record_id],
                    },
                )
            except Exception:
                pass
            continue

        fn = CAPABILITIES.get(capability)
        if not fn:
            unsupported += 1
            try:
                airtable_update(
                    COMMANDS_TABLE_NAME,
                    cid,
                    {
                        "Status_select": "Unsupported",
                        "Error_Message": f"Unsupported capability: {capability}",
                        "Linked_Run": [run_record_id],
                    },
                )
            except Exception:
                pass
            continue

        idem = str(fields.get("Idempotency_Key", "")).strip() or f"cmd:{cid}:{capability}"
        cmd_input = _compose_command_input(fields)

        try:
            airtable_update(
                COMMANDS_TABLE_NAME,
                cid,
                {
                    "Status_select": "Running",
                    "Idempotency_Key": idem,
                    "Linked_Run": [run_record_id],
                    "Error_Message": "",
                },
            )
        except Exception:
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

            airtable_update(
                COMMANDS_TABLE_NAME,
                cid,
                {
                    "Status_select": "Done",
                    "Result_JSON": json.dumps(result_obj, ensure_ascii=False),
                    "Linked_Run": [run_record_id],
                },
            )
            succeeded += 1

        except HTTPException as e:
            msg = str(e.detail)
            failed += 1
            try:
                airtable_update(
                    COMMANDS_TABLE_NAME,
                    cid,
                    {
                        "Status_select": "Error",
                        "Error_Message": msg,
                        "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                        "Linked_Run": [run_record_id],
                    },
                )
            except Exception:
                pass
            errors.append(f"{cid}: {msg}")

        except Exception as e:
            msg = repr(e)
            failed += 1
            try:
                airtable_update(
                    COMMANDS_TABLE_NAME,
                    cid,
                    {
                        "Status_select": "Error",
                        "Error_Message": msg,
                        "Result_JSON": json.dumps({"error": msg}, ensure_ascii=False),
                        "Linked_Run": [run_record_id],
                    },
                )
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
    return {"ok": True, "app": APP_NAME, "version": APP_VERSION, "worker": WORKER_NAME, "ts": utc_now_iso()}


@app.get("/health/score")
def health_score() -> Dict[str, Any]:
    score = 100
    issues: List[str] = []
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        score -= 50
        issues.append("airtable_env_missing")
    if RUN_SHARED_SECRET:
        issues.append("signature_enforced")
    if not HTTP_EXEC_ALLOWLIST:
        issues.append("http_exec_disabled_no_allowlist")
    if not HTTP_EXEC_TARGETS_JSON:
        issues.append("http_exec_no_alias_targets")
    if TOOLCATALOG_ENFORCE_HTTP_EXEC:
        issues.append("toolcatalog_http_exec_enforced")
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

        # IMPORTANT FIX:
        # We always call the capability even in dry_run,
        # so http_exec returns full "dry_run" details (url/method/headers/allowlist/etc).
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
