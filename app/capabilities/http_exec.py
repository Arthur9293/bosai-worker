# app/capabilities/http_exec.py

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests


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


def _is_host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    """
    Strict host allowlist:
    - allow exact match
    - allow subdomain match only if allowlist contains a wildcard-like root with leading dot (optional)
      Example: ".make.com" will allow "hook.eu2.make.com"
    """
    host = (host or "").strip().lower()
    if not host:
        return False

    for a in allowed_hosts:
        a = a.strip().lower()
        if not a:
            continue
        if a.startswith(".") and host.endswith(a):
            return True
        if host == a:
            return True
    return False


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


def _coerce_body(body: Any) -> Tuple[Optional[bytes], Optional[str], Optional[Dict[str, Any]]]:
    """
    Returns: (data_bytes, content_type, json_body)
    Priority:
    - if body is dict/list -> JSON
    - if body is str -> raw text
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


def run_http_exec(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Capability: http_exec

    input_data schema:
    {
      "url": "https://hooks.make.com/xxxxx",
      "method": "POST",
      "headers": {"Content-Type": "application/json"},
      "query": {"a":"b"},                 # optional
      "body": {...} | "raw text",         # optional
      "timeout_seconds": 10               # optional (override <= env timeout)
    }
    """
    allowed_hosts = _env_list("HTTP_EXEC_ALLOWLIST", "")
    allowed_methods = set([_normalize_method(x) for x in _env_list("HTTP_EXEC_ALLOW_METHODS", "GET,POST")])
    timeout_env = float(os.getenv("HTTP_EXEC_TIMEOUT_SECONDS", "20").strip() or "20")
    max_bytes = _env_int("HTTP_EXEC_MAX_RESPONSE_BYTES", 200000)

    url = (input_data.get("url") or "").strip()
    method = _normalize_method(input_data.get("method") or "GET")
    headers = _sanitize_headers(input_data.get("headers") or {})
    query = input_data.get("query") if isinstance(input_data.get("query"), dict) else None
    body = input_data.get("body", None)

    if not url:
        return {"ok": False, "error": "missing_url"}

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": f"invalid_scheme:{parsed.scheme or 'none'}"}

    host = (parsed.hostname or "").strip().lower()
    if not _is_host_allowed(host, allowed_hosts):
        return {"ok": False, "error": f"host_not_allowed:{host}"}

    if method not in allowed_methods:
        return {"ok": False, "error": f"method_not_allowed:{method}"}

    try:
        timeout_req = float(input_data.get("timeout_seconds", timeout_env))
    except Exception:
        timeout_req = timeout_env
    if timeout_req <= 0:
        timeout_req = timeout_env
    if timeout_req > timeout_env:
        timeout_req = timeout_env

    data_bytes, inferred_ct, json_body = _coerce_body(body)
    if inferred_ct and "Content-Type" not in headers and "content-type" not in {k.lower() for k in headers.keys()}:
        headers["Content-Type"] = inferred_ct

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
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": f"request_failed:{type(e).__name__}:{str(e)[:200]}"}

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
    }
