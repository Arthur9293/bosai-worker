# app/capabilities/http_exec.py
#
# BOSAI Worker — http_exec capability (SAFE update, backward compatible)
#
# Goals (no breaking changes):
# - Keep existing input schema working: url/method/headers/query/body/timeout_seconds
# - ADD support for: target + path (alias resolution) without changing callers
# - ADD support for HTTP_EXEC_TARGETS_JSON (alias -> base_url OR object with base_url/headers)
# - ADD support for secret headers via env or Render Secret Files:
#     - env:        HTTP_EXEC_HEADER_AUTH_<KEY>
#     - env legacy: SECRET_HEADER_<KEY>
#     - file:       /etc/secrets/SECRET_HEADER_<KEY>
#     - convenience: MAKE_API_TOKEN when KEY=="MAKE"
# - Improve allowlist matching: exact, ".domain.com", "*.domain.com"
#
# Input supported (ALL optional except url/target):
# {
#   "url": "https://....",                 # direct URL (works as before)
#   "target": "SUPABASE_REST",             # alias to base_url via HTTP_EXEC_TARGETS_JSON
#   "path": "/rest/v1/table?select=*",     # appended to base_url (if target used)
#   "method": "GET|POST|PUT|PATCH|DELETE",
#   "headers": {...},
#   "secret_header_keys": ["SUPABASE","MAKE"],  # optional: adds Authorization from secrets
#   "auth_mode": "token|bearer|raw",       # optional formatting for Authorization
#   "query": {...},
#   "body": {...} | "raw text",
#   "timeout_seconds": 10
# }

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, urlencode

import requests


# ----------------------------
# Env helpers
# ----------------------------

def _env_list(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default).strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        return json.dumps({"_error": "json_dump_failed"}, ensure_ascii=False)


def _normalize_method(m: str) -> str:
    return (m or "").strip().upper()


# ----------------------------
# Allowlist
# ----------------------------

def _is_host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    """
    Strict host allowlist:
    - exact match: "api.example.com"
    - subdomain match:
        - ".example.com" matches "api.example.com"
        - "*.example.com" matches "api.example.com"
    """
    host = (host or "").strip().lower()
    if not host:
        return False

    for a in allowed_hosts:
        a = (a or "").strip().lower()
        if not a:
            continue

        # "*.example.com" -> ".example.com"
        if a.startswith("*."):
            a = a[1:]  # remove leading "*"

        # ".example.com" means any subdomain
        if a.startswith(".") and host.endswith(a):
            return True

        # exact host
        if host == a:
            return True

    return False


# ----------------------------
# Headers policy
# ----------------------------

def _sanitize_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """
    Minimal header policy:
    - keep only simple string headers
    - drop hop-by-hop / dangerous headers
    """
    if not headers:
        return {}

    blocked = {
        "host",
        "content-length",
        "connection",
        "transfer-encoding",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
    }

    out: Dict[str, str] = {}
    for k, v in headers.items():
        if not isinstance(k, str):
            continue
        key = k.strip()
        if not key:
            continue
        if key.lower() in blocked:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[key] = str(v)
        else:
            out[key] = str(v)
    return out


def _has_header(headers: Dict[str, str], name: str) -> bool:
    ln = name.lower()
    return any(k.lower() == ln for k in (headers or {}).keys())


# ----------------------------
# Body coercion
# ----------------------------

def _coerce_body(body: Any) -> Tuple[Optional[bytes], Optional[str], Optional[Dict[str, Any]]]:
    """
    Returns: (data_bytes, content_type, json_body)
    Priority:
    - if body is dict/list -> JSON
    - if body is str/int/float/bool -> raw text
    - if body is None -> no body
    """
    if body is None:
        return None, None, None

    if isinstance(body, (dict, list)):
        return None, "application/json", body

    if isinstance(body, (str, int, float, bool)):
        b = str(body).encode("utf-8")
        return b, "text/plain; charset=utf-8", None

    b = _safe_json(body).encode("utf-8")
    return b, "application/json", None


# ----------------------------
# Targets (alias resolution)
# ----------------------------

def _load_targets_json() -> Dict[str, Any]:
    raw = os.getenv("HTTP_EXEC_TARGETS_JSON", "").strip()
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _pick_first(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        return v
    return None


def _join_base_and_path(base_url: str, path: str) -> str:
    b = (base_url or "").strip()
    p = (path or "").strip()
    if not b:
        return ""
    if not p:
        return b

    # If path is already a full URL, keep it (safe behavior)
    if p.startswith("http://") or p.startswith("https://"):
        return p

    # join cleanly
    if b.endswith("/") and p.startswith("/"):
        return b[:-1] + p
    if (not b.endswith("/")) and (not p.startswith("/")):
        return b + "/" + p
    return b + p


def _resolve_url_from_input(input_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any], str]:
    """
    Returns: (final_url, target_meta, resolution_mode)
    target_meta may contain: base_url, headers, auth_mode, secret_header_keys
    """
    url = (input_data.get("url") or "").strip()
    if url:
        return url, {}, "direct_url"

    target = (input_data.get("target") or input_data.get("http_target") or input_data.get("tool") or "").strip()
    path = (input_data.get("path") or "").strip()

    if not target:
        return "", {}, "missing"

    targets = _load_targets_json()
    t = targets.get(target)

    # Support:
    # - "ALIAS": "https://base"
    # - "ALIAS": { "base_url": "...", "headers": {...}, "auth_mode": "...", "secret_header_keys": [...] }
    if isinstance(t, str):
        base_url = t.strip()
        meta = {"base_url": base_url}
        return _join_base_and_path(base_url, path), meta, "alias_string"

    if isinstance(t, dict):
        base_url = str(t.get("base_url") or t.get("baseUrl") or t.get("url") or "").strip()
        headers = t.get("headers") if isinstance(t.get("headers"), dict) else {}
        auth_mode = str(t.get("auth_mode") or t.get("authMode") or "").strip().lower()
        shk = t.get("secret_header_keys") if isinstance(t.get("secret_header_keys"), list) else []
        meta = {
            "base_url": base_url,
            "headers": headers,
            "auth_mode": auth_mode,
            "secret_header_keys": shk,
        }
        return _join_base_and_path(base_url, path), meta, "alias_object"

    return "", {}, "alias_not_found"


# ----------------------------
# Secrets -> Authorization
# ----------------------------

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
    if " " in s:
        return s
    if mode == "bearer":
        return f"Bearer {s}"
    return f"Token {s}"


def _build_secret_authorization(header_keys: list[str], auth_mode: str) -> Optional[str]:
    """
    For each KEY in secret_header_keys:
      1) env var: HTTP_EXEC_HEADER_AUTH_<KEY>
      2) env var: SECRET_HEADER_<KEY> (legacy)
      3) secret file: /etc/secrets/SECRET_HEADER_<KEY>
      4) if KEY=="MAKE": MAKE_API_TOKEN
    Returns formatted Authorization value (or None).
    """
    prefix = os.getenv("HTTP_EXEC_SECRET_HEADER_PREFIX", "HTTP_EXEC_HEADER_AUTH_").strip() or "HTTP_EXEC_HEADER_AUTH_"
    file_prefix = os.getenv("SECRET_FILE_PREFIX", "SECRET_HEADER_").strip() or "SECRET_HEADER_"

    for key in header_keys or []:
        k = str(key).strip()
        if not k:
            continue

        v = os.getenv(f"{prefix}{k}", "").strip()

        if not v:
            v = os.getenv(f"{file_prefix}{k}", "").strip()

        if not v:
            v = _read_secret_file(f"{file_prefix}{k}")

        if not v and k.upper() == "MAKE":
            v = os.getenv("MAKE_API_TOKEN", "").strip()

        if v:
            return _format_authorization(v, auth_mode)

    return None


# ----------------------------
# Result
# ----------------------------

@dataclass
class HttpExecResult:
    ok: bool
    status_code: int
    url: str
    method: str
    host: str
    elapsed_ms: int
    response_truncated: bool
    response_headers: Dict[str, str]
    response_text: Optional[str]
    response_json: Optional[Any]
    error: Optional[str] = None


# ----------------------------
# Main capability
# ----------------------------

def run_http_exec(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Capability: http_exec

    Backward compatible input schema (still works):
    {
      "url": "https://hooks.make.com/xxxxx",
      "method": "POST",
      "headers": {"Content-Type": "application/json"},
      "query": {"a":"b"},                 # optional
      "body": {...} | "raw text",         # optional
      "timeout_seconds": 10               # optional (override <= env timeout)
    }

    Added (optional):
    {
      "target": "SUPABASE_REST",          # alias in HTTP_EXEC_TARGETS_JSON
      "path": "/rest/v1/table?select=*",  # appended to base_url
      "secret_header_keys": ["SUPABASE"], # adds Authorization from secrets
      "auth_mode": "bearer"              # token|bearer|raw
    }
    """
    allowed_hosts = _env_list("HTTP_EXEC_ALLOWLIST", "")
    allowed_methods = set([_normalize_method(x) for x in _env_list("HTTP_EXEC_ALLOW_METHODS", "GET,POST")])
    timeout_env = float(os.getenv("HTTP_EXEC_TIMEOUT_SECONDS", "20").strip() or "20")
    max_bytes = _env_int("HTTP_EXEC_MAX_RESPONSE_BYTES", 200000)

    # Resolve URL (direct or alias+path)
    url, target_meta, resolution_mode = _resolve_url_from_input(input_data)

    method = _normalize_method(input_data.get("method") or "GET")

    # Merge headers (target headers first, then request headers override)
    headers_target = target_meta.get("headers") if isinstance(target_meta.get("headers"), dict) else {}
    headers_in = input_data.get("headers") if isinstance(input_data.get("headers"), dict) else {}
    headers = _sanitize_headers({**headers_target, **headers_in})

    query = input_data.get("query") if isinstance(input_data.get("query"), dict) else None
    body = input_data.get("body", None)

    # Secrets (Authorization) — only if caller asks OR target_meta includes keys
    req_secret_keys = input_data.get("secret_header_keys") if isinstance(input_data.get("secret_header_keys"), list) else []
    meta_secret_keys = target_meta.get("secret_header_keys") if isinstance(target_meta.get("secret_header_keys"), list) else []
    secret_keys = []
    for x in (req_secret_keys + meta_secret_keys):
        xs = str(x).strip()
        if xs and xs not in secret_keys:
            secret_keys.append(xs)

    # Auth mode (default token; can come from input or target_meta)
    auth_mode = str(_pick_first(input_data.get("auth_mode"), target_meta.get("auth_mode"), "token") or "token").strip().lower()
    if auth_mode not in ("token", "bearer", "raw"):
        auth_mode = "token"

    if secret_keys and (not _has_header(headers, "Authorization")):
        auth = _build_secret_authorization(secret_keys, auth_mode=auth_mode)
        if auth:
            headers["Authorization"] = auth

    if not url:
        return {"ok": False, "error": "missing_url", "resolution_mode": resolution_mode}

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": f"invalid_scheme:{parsed.scheme or 'none'}", "resolution_mode": resolution_mode}

    host = (parsed.hostname or "").strip().lower()
    if not _is_host_allowed(host, allowed_hosts):
        return {"ok": False, "error": f"host_not_allowed:{host}", "resolution_mode": resolution_mode}

    if method not in allowed_methods:
        return {"ok": False, "error": f"method_not_allowed:{method}", "resolution_mode": resolution_mode}

    # Timeout guard
    try:
        timeout_req = float(input_data.get("timeout_seconds", timeout_env))
    except Exception:
        timeout_req = timeout_env
    if timeout_req <= 0:
        timeout_req = timeout_env
    if timeout_req > timeout_env:
        timeout_req = timeout_env

    # Body
    data_bytes, inferred_ct, json_body = _coerce_body(body)
    if inferred_ct and (not _has_header(headers, "Content-Type")):
        headers["Content-Type"] = inferred_ct

    # If query dict is present and url already has query, requests will merge; OK.
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=query,
            data=data_bytes,
            json=json_body,
            timeout=timeout_req,
        )
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "timeout", "resolution_mode": resolution_mode}
    except Exception as e:
        return {"ok": False, "error": f"request_failed:{type(e).__name__}:{str(e)[:200]}", "resolution_mode": resolution_mode}

    elapsed_ms = int(getattr(resp, "elapsed", None).total_seconds() * 1000) if getattr(resp, "elapsed", None) else 0
    content = resp.content or b""
    truncated = False
    if len(content) > max_bytes:
        content = content[:max_bytes]
        truncated = True

    resp_headers: Dict[str, str] = {}
    for k, v in (resp.headers or {}).items():
        if isinstance(k, str) and isinstance(v, str):
            resp_headers[k] = v[:500]

    text: Optional[str] = None
    js: Optional[Any] = None

    ctype = (resp.headers.get("Content-Type", "") or "").lower()
    if "application/json" in ctype or "json" in ctype:
        try:
            js = resp.json()
        except Exception:
            try:
                text = content.decode("utf-8", errors="replace")
            except Exception:
                text = None
    else:
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            text = None

    result = HttpExecResult(
        ok=True,
        status_code=int(resp.status_code),
        url=url,
        method=method,
        host=host,
        elapsed_ms=elapsed_ms,
        response_truncated=truncated,
        response_headers=resp_headers,
        response_text=text,
        response_json=js,
        error=None,
    )

    return {
        "ok": result.ok,
        "status_code": result.status_code,
        "url": result.url,
        "method": result.method,
        "host": result.host,
        "elapsed_ms": result.elapsed_ms,
        "response_truncated": result.response_truncated,
        "response_headers": result.response_headers,
        "response_text": result.response_text,
        "response_json": result.response_json,
        # debug (safe): shows how URL was resolved
        "resolution_mode": resolution_mode,
    }
