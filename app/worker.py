# app/worker.py — BOSAI Worker (v2.3.7)
# SAFE from v2.3.6 baseline:
# - Keeps GET /, HEAD /, /health, /health/score, POST /run behavior
# - Status_select schema for System_Runs
# - Idempotency replay: Idempotency_Key + Status_select only
# - Commands Orchestrator V1 unchanged
# - SLA Machine V1 unchanged (writes Logs_Erreurs: SLA_Status, Last_SLA_Check, Linked_Run)
# - No-Chaos: Lock TTL Cleanup unchanged
# - State table support unchanged
# IMPORTANT: No Is_bad (removed entirely)
#
# PATCH (SAFE): HTTP_EXEC hardened + compatibility:
# - Normalizes allowlist entries: accepts host OR full URL (https://hook.../ => host)
# - Supports inputs:
#   - input.url OR input.http_target OR input.target OR input.tool
#   - ALSO supports nested shapes: input.input.url, input.args.url (safe fallback)
# - Alias resolution via HTTP_EXEC_TARGETS_JSON unchanged
# - Stricter allowlist by host (supports *.domain.tld)
# - Optional secret headers via ENV (no secrets in Airtable)
# - Blocks localhost/private nets by default

import os
import json
import time
import uuid
import hmac
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field, ConfigDict
from pydantic.aliases import AliasChoices


# ============================================================
# Env / settings
# ============================================================

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()

# Tables (match your base)
SYSTEM_RUNS_TABLE_NAME = os.getenv("SYSTEM_RUNS_TABLE_NAME", "System_Runs").strip()
COMMANDS_TABLE_NAME = os.getenv("COMMANDS_TABLE_NAME", "Commands").strip()
LOGS_ERRORS_TABLE_NAME = os.getenv("LOGS_ERRORS_TABLE_NAME", "Logs_Erreurs").strip()
STATE_TABLE_NAME = os.getenv("STATE_TABLE_NAME", "State").strip()

# Views
LOGS_ERRORS_VIEW_NAME = os.getenv("LOGS_ERRORS_VIEW_NAME", "Active").strip()
COMMANDS_VIEW_NAME = os.getenv("COMMANDS_VIEW_NAME", "Queue").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()
APP_NAME = os.getenv("APP_NAME", "bosai-worker").strip()
APP_VERSION = os.getenv("APP_VERSION", "2.3.7").strip()

RUN_MAX_SECONDS = float(os.getenv("RUN_MAX_SECONDS", "30").strip() or "30")
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "20").strip() or "20")

# No-Chaos: stale "Running" TTL cleanup (seconds)
RUN_LOCK_TTL_SECONDS = int(os.getenv("RUN_LOCK_TTL_SECONDS", "600").strip() or "600")

# Signature HMAC (optional). If empty => no verification.
RUN_SHARED_SECRET = os.getenv("RUN_SHARED_SECRET", "").strip()

# SLA thresholds (minutes)
SLA_WARNING_THRESHOLD_MIN = float(os.getenv("SLA_WARNING_THRESHOLD_MIN", "60").strip() or "60")

# Allowlist fields (Logs_Erreurs) — must match Airtable exactly
LOGS_ERRORS_FIELDS_ALLOWED = set(
    [s.strip() for s in os.getenv(
        "LOGS_ERRORS_FIELDS_ALLOWED",
        "SLA_Status,Last_SLA_Check,Linked_Run"
    ).split(",") if s.strip()]
)

# SLA status options — must match Airtable exactly (case included)
SLA_STATUS_OK = os.getenv("SLA_STATUS_OK", "OK").strip()
SLA_STATUS_WARNING = os.getenv("SLA_STATUS_WARNING", "Warning").strip()
SLA_STATUS_BREACHED = os.getenv("SLA_STATUS_BREACHED", "Breached").strip()
SLA_STATUS_ESCALATED = os.getenv("SLA_STATUS_ESCALATED", "Escalated").strip()

# State lock status options (recommended)
STATE_LOCK_ACTIVE = os.getenv("STATE_LOCK_ACTIVE", "Active").strip()
STATE_LOCK_RELEASED = os.getenv("STATE_LOCK_RELEASED", "Released").strip()
STATE_LOCK_EXPIRED = os.getenv("STATE_LOCK_EXPIRED", "Expired").strip()


# ============================================================
# HTTP_EXEC (PATCH)
# ============================================================

HTTP_EXEC_TIMEOUT_SECONDS = float(os.getenv("HTTP_EXEC_TIMEOUT_SECONDS", "20").strip() or "20")
HTTP_EXEC_MAX_BODY_BYTES = int(os.getenv("HTTP_EXEC_MAX_BODY_BYTES", "250000").strip() or "250000")
HTTP_EXEC_MAX_RESPONSE_BYTES = int(os.getenv("HTTP_EXEC_MAX_RESPONSE_BYTES", "250000").strip() or "250000")

# Allowlist strict by hostname. Examples:
# HTTP_EXEC_ALLOWLIST=hook.make.com,api.airtable.com,api.openai.com,*.supabase.co
# NOTE: now also accepts full URLs in this ENV: https://hook.make.com/xxx (we normalize to host)
HTTP_EXEC_ALLOWLIST_RAW = os.getenv("HTTP_EXEC_ALLOWLIST", "").strip()

# Alias -> URL mapping (so you can keep "make_webhook_test" in Airtable)
# HTTP_EXEC_TARGETS_JSON='{"make_webhook_test":"https://hook.make.com/xxxx"}'
HTTP_EXEC_TARGETS_JSON = os.getenv("HTTP_EXEC_TARGETS_JSON", "").strip()

# Block private nets by default (safer)
HTTP_EXEC_BLOCK_PRIVATE_NETS = (os.getenv("HTTP_EXEC_BLOCK_PRIVATE_NETS", "1").strip() != "0")

# Secret headers stored in ENV, referenced by key (no secrets in Airtable)
# Example:
# HTTP_EXEC_SECRET_HEADER_PREFIX=HTTP_EXEC_HEADER_AUTH_
# HTTP_EXEC_HEADER_AUTH_make=Bearer xxx
HTTP_EXEC_SECRET_HEADER_PREFIX = os.getenv("HTTP_EXEC_SECRET_HEADER_PREFIX", "HTTP_EXEC_HEADER_AUTH_").strip()


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# ============================================================
# Models
# ============================================================

class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    worker: str = Field(default=WORKER_NAME)

    # Canonical: capability, but accept legacy "capacity"
    capability: str = Field(
        ...,
        validation_alias=AliasChoices("capability", "capacity"),
    )

    # Canonical: idempotency_key
    idempotency_key: str = Field(
        ...,
        validation_alias=AliasChoices("idempotency_key", "idempotencyKey"),
    )

    priority: int = 1

    # Canonical: input, but accept legacy "inputs"
    input: Dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("input", "inputs"),
    )

    dry_run: bool = False

    # Optional knobs used by command orchestrator
    view: Optional[str] = None
    max_commands: int = 0


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
                airtable_update(SYSTEM_RUNS_TABLE_NAME, rid, {
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

def fail_system_run(record_id: str, error_message: str) -> None:
    fields = {
        "Status_select": "Error",
        "Finished_At": utc_now_iso(),
        "Result_JSON": json.dumps({"error": error_message}, ensure_ascii=False),
    }
    airtable_update(SYSTEM_RUNS_TABLE_NAME, record_id, fields)

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

        new_fields = {
            "App_Key": app_key,
            "Lock_Status": STATE_LOCK_ACTIVE,
            "Value_JSON": json.dumps({"holder": holder, "acquired_at": now}, ensure_ascii=False),
            "Updated_At": now,
            "App_Version": APP_VERSION,
        }
        airtable_update(STATE_TABLE_NAME, rec["id"], new_fields)
        return {"ok": True, "locked": True, "record_id": rec["id"], "lock_status": STATE_LOCK_ACTIVE}

    rid = airtable_create(STATE_TABLE_NAME, {
        "App_Key": app_key,
        "Lock_Status": STATE_LOCK_ACTIVE,
        "Value_JSON": json.dumps({"holder": holder, "acquired_at": now}, ensure_ascii=False),
        "Updated_At": now,
        "App_Version": APP_VERSION,
    })
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
    airtable_update(STATE_TABLE_NAME, rec["id"], {
        "Lock_Status": STATE_LOCK_RELEASED,
        "Updated_At": now,
        "Value_JSON": json.dumps({"holder": holder, "released_at": now}, ensure_ascii=False),
        "App_Version": APP_VERSION,
    })
    return {"ok": True, "released": True, "record_id": rec["id"]}


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

    return {
        "ok": True,
        "updated": updated,
        "skipped": skipped,
        "errors_count": len(errors),
        "errors": errors[:10],
    }


# ----------------------------
# HTTP_EXEC (PATCH HELPERS)
# ----------------------------

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

def _normalize_allowlist_hosts(raw: str) -> List[str]:
    """
    Accepts:
      - "https://hook.eu1.make.com/,https://httpbin.org/"
      - "hook.eu1.make.com,httpbin.org"
      - "*.supabase.co"
    Returns list of host rules (lowercased, deduped):
      - ["hook.eu1.make.com","httpbin.org","*.supabase.co"]
    """
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

        # keep wildcard host as-is
        if pl.startswith("*.") and "/" not in pl and "://" not in pl:
            if pl not in seen:
                seen.add(pl)
                out.append(pl)
            continue

        # if full URL, extract hostname
        if "://" in pl:
            try:
                pu = urlparse(pl)
                h = (pu.hostname or "").strip().lower()
                if h and h not in seen:
                    seen.add(h)
                    out.append(h)
                continue
            except Exception:
                # fall through to host cleanup
                pass

        # host-only, but user might have pasted "host/path"
        if "/" in pl:
            pl = pl.split("/", 1)[0].strip()

        if pl and pl not in seen:
            seen.add(pl)
            out.append(pl)

    return out

# normalized allowlist (IMPORTANT)
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
    targets = _http_exec_targets()
    return targets.get(s, "")

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

def _build_secret_headers(header_keys: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key in header_keys or []:
        env_name = f"{HTTP_EXEC_SECRET_HEADER_PREFIX}{str(key).strip()}"
        val = os.getenv(env_name, "").strip()
        if val:
            # Deterministic: single Authorization header (last wins if multiple keys)
            out["Authorization"] = val
    return out

def _extract_http_exec_input(inp: Dict[str, Any]) -> Dict[str, Any]:
    """
    SAFE compatibility:
    - accepts url/http_target/target/tool at top-level
    - also accepts nested shapes:
        inp["input"]["url"], inp["args"]["url"]
    This DOES NOT change RunRequest schema; it's only internal parsing.
    """
    inp0 = _to_dict(inp)
    nested_input = _to_dict(inp0.get("input"))
    nested_args = _to_dict(inp0.get("args"))

    # prefer top-level, then nested
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

    method = _pick_first(
        inp0.get("method"),
        nested_input.get("method"),
        nested_args.get("method"),
    )

    headers = _pick_first(
        inp0.get("headers"),
        nested_input.get("headers"),
        nested_args.get("headers"),
    )
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

    raw_data = _pick_first(
        inp0.get("data"),
        nested_input.get("data"),
        nested_args.get("data"),
    )

    return {
        "raw_target": str(url_like or "").strip(),
        "method": str(method or "POST").strip().upper(),
        "headers": headers,
        "secret_header_keys": secret_keys,
        "json_body": json_body,
        "raw_data": raw_data,
    }


def capability_http_exec(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    """
    Supports inputs:
      - url OR http_target OR target OR tool
      - also supports nested shapes: input.input.*, input.args.* (safe fallback)
      - alias resolution via HTTP_EXEC_TARGETS_JSON
    Payload supported:
      - headers (dict)
      - body (any JSON-serializable) OR json (alias of body)
      - data (raw string/bytes) optional (mutually exclusive with body/json)
      - secret_header_keys (list) -> Authorization from ENV (no secrets in Airtable)
      - method (GET/POST/PUT/PATCH/DELETE)
    """
    inp = req.input or {}
    extracted = _extract_http_exec_input(inp)

    raw_target = extracted["raw_target"]

    # 1) resolve alias -> URL
    url = _resolve_http_target(raw_target)
    if not url:
        raise HTTPException(
            status_code=400,
            detail=(
                "HTTP_EXEC missing url (provide input.url or input.http_target/target/tool; "
                "or set HTTP_EXEC_TARGETS_JSON for alias resolution)."
            ),
        )

    meta = _validate_http_exec_url(url)

    method = extracted["method"]
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        raise HTTPException(status_code=400, detail=f"HTTP_EXEC invalid method: {method}")

    headers_in = extracted["headers"]
    secret_keys = extracted["secret_header_keys"]

    secret_headers = _build_secret_headers(secret_keys)
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
            "note": "HTTP call skipped (dry_run).",
        }

    # request
    if raw_data is not None:
        if not isinstance(raw_data, (str, bytes)):
            raise HTTPException(status_code=400, detail="HTTP_EXEC data must be str or bytes.")
        raw_bytes = raw_data.encode("utf-8") if isinstance(raw_data, str) else raw_data
        raw_bytes = _truncate_bytes(raw_bytes, HTTP_EXEC_MAX_BODY_BYTES)
        resp = requests.request(
            method,
            url,
            headers=headers,
            data=raw_bytes,
            timeout=HTTP_EXEC_TIMEOUT_SECONDS,
        )
    else:
        jb = json_body if json_body is not None else {}
        jb_bytes = json.dumps(jb, ensure_ascii=False).encode("utf-8")
        if len(jb_bytes) > HTTP_EXEC_MAX_BODY_BYTES:
            raise HTTPException(status_code=400, detail="HTTP_EXEC json/body too large.")
        resp = requests.request(
            method,
            url,
            headers=headers,
            json=jb,
            timeout=HTTP_EXEC_TIMEOUT_SECONDS,
        )

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
        "request_headers": _safe_headers_for_log(headers),
        "response_headers": {k: (v if k.lower() != "set-cookie" else "***redacted***") for k, v in resp_headers.items()},
        "response_json": parsed_json,
        "response_text": (text_preview[:2000] if text_preview else None),
    }


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


def capability_command_orchestrator(req: RunRequest, run_record_id: str) -> Dict[str, Any]:
    """
    Commands Orchestrator V1 (unchanged logic)
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
                airtable_update(COMMANDS_TABLE_NAME, cid, {
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
                airtable_update(COMMANDS_TABLE_NAME, cid, {
                    "Status_select": "Unsupported",
                    "Error_Message": f"Unsupported capability: {capability}",
                    "Linked_Run": [run_record_id],
                })
            except Exception:
                pass
            continue

        idem = str(fields.get("Idempotency_Key", "")).strip() or f"cmd:{cid}:{capability}"
        cmd_input = _json_load_maybe(fields.get("Input_JSON"))

        try:
            airtable_update(COMMANDS_TABLE_NAME, cid, {
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

            airtable_update(COMMANDS_TABLE_NAME, cid, {
                "Status_select": "Done",
                "Result_JSON": json.dumps(result_obj, ensure_ascii=False),
                "Linked_Run": [run_record_id],
            })
            succeeded += 1

        except HTTPException as e:
            msg = str(e.detail)
            failed += 1
            try:
                airtable_update(COMMANDS_TABLE_NAME, cid, {
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
                airtable_update(COMMANDS_TABLE_NAME, cid, {
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
    "http_exec": capability_http_exec,  # PATCHED
    "state_get": capability_state_get,
    "state_put": capability_state_put,
    "lock_acquire": capability_lock_acquire,
    "lock_release": capability_lock_release,
    "command_orchestrator": capability_command_orchestrator,
}


# ============================================================
# Routes
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
    if not HTTP_EXEC_ALLOWLIST:
        issues.append("http_exec_disabled_no_allowlist")
    if not HTTP_EXEC_TARGETS_JSON:
        issues.append("http_exec_no_alias_targets")
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
