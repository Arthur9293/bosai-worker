# app/capabilities/http_exec.py
# BOSAI Worker — capability http_exec (single source of truth)
#
# HARDENED PATCH:
# - SSRF real protection: DNS resolve -> IP block (private/link-local/reserved/multicast/metadata)
# - Redirects OFF by default (HTTP_EXEC_FOLLOW_REDIRECTS=0 recommended)
# - Timeout caps (HTTP_EXEC_MAX_TIMEOUT_SECONDS)
# - Shared requests.Session support (keep-alive, stable)
# - ToolCatalog enforcement preserved (optional)
# - dry_run returns full diagnostics
# - Supabase auto-auth disabled by default (HTTP_EXEC_SUPABASE_AUTO_AUTH=0 recommended)
#
# Additional SAFE improvement (for Supabase without leaking secrets in Airtable):
# - If Secret_Header_Keys includes "SUPABASE", we inject BOTH:
#     apikey: <secret>
#     Authorization: Bearer <secret>
#   sourced from env/secret files (same precedence as Authorization).
# - This does NOT change behavior for other keys.
#
# SAFE diagnostics patch:
# - dry_run now reports whether secrets were found and whether apikey/Authorization were injected,
#   WITHOUT ever returning secret values.

import os
import json
import time
import re
import ipaddress
import socket
from typing import Any, Dict, Optional, List, Tuple
from urllib.parse import urlparse

import requests
from fastapi import HTTPException


# ============================================================
# HTTP_EXEC env / settings (SAFE)
# ============================================================

HTTP_EXEC_TIMEOUT_SECONDS = float((os.getenv("HTTP_EXEC_TIMEOUT_SECONDS", "20") or "20").strip())
HTTP_EXEC_MAX_TIMEOUT_SECONDS = float((os.getenv("HTTP_EXEC_MAX_TIMEOUT_SECONDS", "30") or "30").strip())

HTTP_EXEC_MAX_BODY_BYTES = int((os.getenv("HTTP_EXEC_MAX_BODY_BYTES", "250000") or "250000").strip())
HTTP_EXEC_MAX_RESPONSE_BYTES = int((os.getenv("HTTP_EXEC_MAX_RESPONSE_BYTES", "250000") or "250000").strip())

HTTP_EXEC_ALLOWLIST_RAW = os.getenv("HTTP_EXEC_ALLOWLIST", "").strip()
HTTP_EXEC_TARGETS_JSON = os.getenv("HTTP_EXEC_TARGETS_JSON", "").strip()

HTTP_EXEC_BLOCK_PRIVATE_NETS = (os.getenv("HTTP_EXEC_BLOCK_PRIVATE_NETS", "1").strip() != "0")
HTTP_EXEC_BLOCK_METADATA = (os.getenv("HTTP_EXEC_BLOCK_METADATA", "1").strip() != "0")

HTTP_EXEC_FOLLOW_REDIRECTS = (os.getenv("HTTP_EXEC_FOLLOW_REDIRECTS", "0").strip() != "0")  # recommended 0

HTTP_EXEC_ALLOWED_SCHEMES = set(
    s.strip().lower()
    for s in (os.getenv("HTTP_EXEC_ALLOWED_SCHEMES", "https,http") or "https,http").split(",")
    if s.strip()
)

HTTP_EXEC_ALLOWED_METHODS = set(
    m.strip().upper()
    for m in (os.getenv("HTTP_EXEC_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE") or "").split(",")
    if m.strip()
)

HTTP_EXEC_SECRET_HEADER_PREFIX = os.getenv("HTTP_EXEC_SECRET_HEADER_PREFIX", "HTTP_EXEC_HEADER_AUTH_").strip()
SECRET_FILE_PREFIX = os.getenv("SECRET_FILE_PREFIX", "SECRET_HEADER_").strip()

# Supabase auto-auth (disabled by default; prefer ToolCatalog Secret_Header_Keys or SUPABASE key injection below)
HTTP_EXEC_SUPABASE_AUTO_AUTH = (os.getenv("HTTP_EXEC_SUPABASE_AUTO_AUTH", "0").strip() != "0")

# ToolCatalog behavior toggles (SAFE defaults)
TOOLCATALOG_ENFORCE_HTTP_EXEC = (os.getenv("TOOLCATALOG_ENFORCE_HTTP_EXEC", "1").strip() != "0")
TOOLCATALOG_OVERRIDE_HTTP = (os.getenv("TOOLCATALOG_OVERRIDE_HTTP", "1").strip() != "0")  # URL/Method/Headers/Timeout
TOOLCATALOG_CACHE_SECONDS = int((os.getenv("TOOLCATALOG_CACHE_SECONDS", "30") or "30").strip())

# Airtable ToolCatalog (used only for http_exec policy)
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()
TOOLCATALOG_TABLE_NAME = os.getenv("TOOLCATALOG_TABLE_NAME", "ToolCatalog").strip()

HTTP_TIMEOUT_SECONDS = float((os.getenv("HTTP_TIMEOUT_SECONDS", "20") or "20").strip())


# ============================================================
# Airtable minimal client (ToolCatalog read only)
# ============================================================

def _airtable_url(table_name: str) -> str:
    return f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{table_name}"


def _airtable_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }


# ============================================================
# Small helpers
# ============================================================

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


# ============================================================
# Allowlist + private nets
# ============================================================

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


def _resolve_ips(host: str) -> List[str]:
    ips: List[str] = []
    try:
        for res in socket.getaddrinfo(host, None):
            ip = res[4][0]
            if ip and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return True

    # loopback
    if addr.is_loopback:
        return True

    # private / link-local / reserved / multicast
    if HTTP_EXEC_BLOCK_PRIVATE_NETS and (addr.is_private or addr.is_link_local or addr.is_reserved or addr.is_multicast):
        return True

    # metadata
    if HTTP_EXEC_BLOCK_METADATA and str(addr) == "169.254.169.254":
        return True

    return False


def _validate_http_exec_url(url: str) -> Dict[str, str]:
    parsed = urlparse(url)

    scheme = (parsed.scheme or "").lower()
    if scheme not in HTTP_EXEC_ALLOWED_SCHEMES:
        raise HTTPException(status_code=403, detail=f"HTTP_EXEC invalid url scheme: {scheme}")

    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise HTTPException(status_code=400, detail="HTTP_EXEC missing host")

    # Deny-by-default: require allowlist
    if not HTTP_EXEC_ALLOWLIST:
        raise HTTPException(status_code=403, detail="HTTP_EXEC allowlist is empty (set HTTP_EXEC_ALLOWLIST).")
    if not _host_matches_allowlist(host, HTTP_EXEC_ALLOWLIST):
        raise HTTPException(status_code=403, detail=f"HTTP_EXEC host not in allowlist: {host}")

    # Extra: obvious private hostnames
    if HTTP_EXEC_BLOCK_PRIVATE_NETS and _is_private_host(host):
        raise HTTPException(status_code=403, detail=f"HTTP_EXEC blocked private host: {host}")

    # Real SSRF: DNS -> IP checks
    ips = _resolve_ips(host)
    for ip in ips:
        if _is_blocked_ip(ip):
            raise HTTPException(status_code=403, detail=f"HTTP_EXEC blocked destination ip: {ip}")

    return {"host": host, "scheme": scheme}


# ============================================================
# Headers safety + truncation
# ============================================================

def _safe_headers_for_log(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk in ("authorization", "cookie", "x-api-key", "set-cookie", "apikey"):
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


# ============================================================
# ToolCatalog cache + enforcement (SAFE)
# ============================================================

_TOOLCATALOG_CACHE: Dict[str, Any] = {"ts": 0.0, "by_key": {}}


def _toolcatalog_fetch_map(session: requests.Session, force: bool = False) -> Dict[str, Dict[str, Any]]:
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
        r = session.get(
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


def _toolcatalog_get(session: requests.Session, tool_key: str) -> Optional[Dict[str, Any]]:
    tool_key = str(tool_key or "").strip()
    if not tool_key:
        return None
    m = _toolcatalog_fetch_map(session=session, force=False)
    rec = m.get(tool_key)
    if rec:
        return rec
    m2 = _toolcatalog_fetch_map(session=session, force=True)
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


def _toolcatalog_enforce_or_raise(
    session: requests.Session,
    req: Any,
    tool_key: str,
    tool_mode: str,
    tool_intent: str,
    approved: bool,
) -> Dict[str, Any]:
    rec = _toolcatalog_get(session=session, tool_key=tool_key)
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
    if _as_bool(requires_approval) and (not getattr(req, "dry_run", False)) and (not approved):
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


def _tc_int(fields: Dict[str, Any], name: str, default: int) -> int:
    try:
        v = fields.get(name)
        if v is None or str(v).strip() == "":
            return default
        return int(float(str(v).strip()))
    except Exception:
        return default


def _tc_list_csv(fields: Dict[str, Any], name: str) -> List[str]:
    v = fields.get(name)
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        return [p.strip() for p in v.split(",") if p.strip()]
    return []


def _should_retry(status_code: Optional[int], err: Optional[str], retry_status: List[str], retry_errors: List[str]) -> bool:
    if err:
        e = err.lower()
        for token in retry_errors:
            if token and token.lower() in e:
                return True
    if status_code is not None:
        return str(status_code) in retry_status
    return False


# ============================================================
# Targets + secrets
# ============================================================

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


def _read_secret_file(name: str) -> str:
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
    s = (raw or "").strip()
    if not s:
        return ""
    if mode == "raw":
        return s
    if " " in s:
        return s
    if mode == "bearer":
        return f"Bearer {s}"
    return f"Token {s}"


def _load_secret_for_key(k: str) -> str:
    """
    Precedence:
      1) env: HTTP_EXEC_HEADER_AUTH_<KEY>
      2) env: SECRET_HEADER_<KEY> (or configured SECRET_FILE_PREFIX)
      3) file: /etc/secrets/SECRET_HEADER_<KEY>
      4) if KEY=="MAKE": MAKE_API_TOKEN
    """
    k = (k or "").strip()
    if not k:
        return ""

    v = (os.getenv(f"{HTTP_EXEC_SECRET_HEADER_PREFIX}{k}", "") or "").strip()
    if not v:
        v = (os.getenv(f"{SECRET_FILE_PREFIX}{k}", "") or "").strip()
    if not v:
        v = _read_secret_file(f"{SECRET_FILE_PREFIX}{k}")
    if not v and k.upper() == "MAKE":
        v = (os.getenv("MAKE_API_TOKEN", "") or "").strip()
    return (v or "").strip()


def _build_secret_headers(header_keys: List[str], auth_mode: str = "token") -> Dict[str, str]:
    """
    SAFE behavior:
      - Default: inject Authorization only (as before)
      - If key == "SUPABASE": inject apikey + Authorization: Bearer <secret> (Supabase REST expects both)
    """
    out: Dict[str, str] = {}

    for key in header_keys or []:
        k = str(key).strip()
        if not k:
            continue

        secret = _load_secret_for_key(k)
        if not secret:
            continue

        if k.upper() == "SUPABASE":
            out["apikey"] = secret
            out["Authorization"] = f"Bearer {secret}"
            return out

        out["Authorization"] = _format_authorization(secret, auth_mode)
        return out

    return out


def _diagnose_secret_keys(header_keys: List[str]) -> Dict[str, Any]:
    """
    SAFE: diagnostics only — returns booleans and key names; never returns secret values.
    """
    found_keys: List[str] = []
    for key in header_keys or []:
        k = str(key).strip()
        if not k:
            continue
        try:
            v = _load_secret_for_key(k)
            if v:
                found_keys.append(k)
        except Exception:
            continue

    return {
        "requested": [str(k).strip() for k in (header_keys or []) if str(k).strip()],
        "found_any": bool(found_keys),
        "found_keys": found_keys[:5],
    }


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

    return url_final, method_final, headers_final, float(timeout_s)


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


# ============================================================
# PUBLIC capability
# ============================================================

def capability_http_exec(req: Any, run_record_id: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    sess = session or requests.Session()

    inp = getattr(req, "input", None) or {}
    dry_run = bool(getattr(req, "dry_run", False))

    # compat: if input contains nested "input" dict, use it when it carries http_exec keys
    if isinstance(inp.get("input"), dict) and inp.get("input"):
        nested = inp.get("input")
        if any(
            k in nested
            for k in (
                "url", "http_target", "target", "tool",
                "method", "headers", "json", "body", "data",
                "secret_header_keys",
                "Tool_Key", "tool_key",
                "Tool_Mode", "tool_mode",
                "Tool_Intent", "tool_intent",
                "Approved", "approved",
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
    local_timeout = float(HTTP_EXEC_TIMEOUT_SECONDS)

    if TOOLCATALOG_ENFORCE_HTTP_EXEC and tool_key:
        tool_fields = _toolcatalog_enforce_or_raise(sess, req, tool_key, tool_mode, tool_intent, approved)

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

    # timeout cap (anti-chaos)
    if local_timeout <= 0:
        local_timeout = float(HTTP_EXEC_TIMEOUT_SECONDS)
    local_timeout = max(1.0, min(float(local_timeout), float(HTTP_EXEC_MAX_TIMEOUT_SECONDS)))

    raw_target = extracted["raw_target"]
    url = _resolve_http_target(raw_target)

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
    if method not in HTTP_EXEC_ALLOWED_METHODS:
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

    # Optional: auto-auth for Supabase REST (disabled by default)
    if HTTP_EXEC_SUPABASE_AUTO_AUTH:
        supa_key = os.getenv("SUPABASE_API_KEY", "").strip()
        if supa_key:
            host_l = (meta.get("host") or "").lower()
            if host_l.endswith(".supabase.co"):
                headers.setdefault("apikey", supa_key)
                headers.setdefault("Authorization", f"Bearer {supa_key}")

    # ToolCatalog-driven retry (SAFE defaults = no retry)
    retry_max = 0
    retry_backoff_s = 0
    retry_on_status: List[str] = []
    retry_on_errors: List[str] = []
    if tool_fields:
        retry_max = max(0, _tc_int(tool_fields, "Retry_Max", 0))
        retry_backoff_s = max(0, _tc_int(tool_fields, "Retry_Backoff_S", 0))
        retry_on_status = _tc_list_csv(tool_fields, "Retry_On_Status")
        retry_on_errors = _tc_list_csv(tool_fields, "Retry_On_Errors")

    json_body = extracted["json_body"]
    raw_data = extracted["raw_data"]

    if raw_data is not None and json_body is not None:
        raise HTTPException(status_code=400, detail="HTTP_EXEC use json/body OR data, not both.")

    if dry_run:
        # SAFE: show whether secrets were found without leaking them
        sec_diag = _diagnose_secret_keys(merged_secret_keys)
        sec_diag["headers_injected"] = {
            "authorization_present": ("Authorization" in secret_headers),
            "apikey_present": ("apikey" in secret_headers),
        }
        sec_diag["supabase_mode_detected"] = ("apikey" in secret_headers and "Authorization" in secret_headers)

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
            "timeout_s": local_timeout,
            "follow_redirects": HTTP_EXEC_FOLLOW_REDIRECTS,
            "retry": {
                "retry_max": retry_max,
                "retry_backoff_s": retry_backoff_s,
                "retry_on_status": retry_on_status,
                "retry_on_errors": retry_on_errors,
            },
            "diagnostics": {
                "secrets": sec_diag,
            },
            "note": "HTTP call skipped (dry_run).",
        }

    attempts = 0
    last_err: Optional[str] = None
    resp: Optional[requests.Response] = None
    max_attempts = retry_max + 1

    while True:
        attempts += 1
        last_err = None

        try:
            if raw_data is not None:
                if not isinstance(raw_data, (str, bytes)):
                    raise HTTPException(status_code=400, detail="HTTP_EXEC data must be str or bytes.")
                raw_bytes = raw_data.encode("utf-8") if isinstance(raw_data, str) else raw_data
                raw_bytes = _truncate_bytes(raw_bytes, HTTP_EXEC_MAX_BODY_BYTES)

                resp = sess.request(
                    method,
                    url,
                    headers=headers,
                    data=raw_bytes,
                    timeout=float(local_timeout),
                    allow_redirects=bool(HTTP_EXEC_FOLLOW_REDIRECTS),
                )
            else:
                jb = json_body if json_body is not None else {}
                jb_bytes = json.dumps(jb, ensure_ascii=False).encode("utf-8")
                if len(jb_bytes) > HTTP_EXEC_MAX_BODY_BYTES:
                    raise HTTPException(status_code=400, detail="HTTP_EXEC json/body too large.")

                resp = sess.request(
                    method,
                    url,
                    headers=headers,
                    json=jb,
                    timeout=float(local_timeout),
                    allow_redirects=bool(HTTP_EXEC_FOLLOW_REDIRECTS),
                )

            status = int(resp.status_code)

            # If redirects allowed, re-validate final URL (SSRF safe)
            if HTTP_EXEC_FOLLOW_REDIRECTS:
                final_url = str(getattr(resp, "url", "") or "")
                if final_url and final_url != url:
                    _ = _validate_http_exec_url(final_url)
                    url = final_url  # for diagnostics

            if attempts < max_attempts and _should_retry(status, None, retry_on_status, retry_on_errors):
                last_err = f"retry_status:{status}"
                if retry_backoff_s > 0:
                    time.sleep(float(retry_backoff_s) * float(attempts))
                continue

            break

        except HTTPException:
            raise
        except requests.exceptions.Timeout:
            last_err = "timeout"
        except Exception as e:
            last_err = f"request_failed:{type(e).__name__}:{str(e)[:200]}"

        if attempts < max_attempts and _should_retry(None, last_err, retry_on_status, retry_on_errors):
            if retry_backoff_s > 0:
                time.sleep(float(retry_backoff_s) * float(attempts))
            continue

        break

    if resp is None:
        return {
            "ok": False,
            "run_record_id": run_record_id,
            "host": meta["host"],
            "method": method,
            "url": url,
            "status_code": None,
            "tool_key": tool_key or None,
            "tool_mode": tool_mode or None,
            "tool_intent": tool_intent or None,
            "auth_mode": auth_mode,
            "attempts": attempts,
            "retry_max": retry_max,
            "last_error": last_err or "request_failed",
            "request_headers": _safe_headers_for_log(headers),
            "response_headers": {},
            "response_json": None,
            "response_text": None,
        }

    status = int(resp.status_code)
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
        "attempts": attempts,
        "retry_max": retry_max,
        "last_error": last_err,
        "timeout_s": local_timeout,
        "follow_redirects": bool(HTTP_EXEC_FOLLOW_REDIRECTS),
        "request_headers": _safe_headers_for_log(headers),
        "response_headers": {
            k: (v if k.lower() != "set-cookie" else "***redacted***")
            for k, v in resp_headers.items()
        },
        "response_json": parsed_json,
        "response_text": (text_preview[:2000] if text_preview else None),
    }
