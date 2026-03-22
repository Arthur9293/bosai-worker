# app/capabilities/http_exec.py
# BOSAI Worker — capability http_exec
#
# Production-ready single-source implementation.
#
# Guarantees:
# - SSRF protection (DNS resolve -> IP validation)
# - Host allowlist enforcement
# - Redirects OFF by default
# - Timeout caps
# - Optional shared requests.Session support
# - Optional ToolCatalog enforcement (input-driven, non-breaking)
# - Secret header injection support
# - Retry metadata propagation:
#     flow_id
#     root_event_id
#     step_index
#     retry_count
#     retry_max
# - On failure: http_exec routes ONLY to retry_router
# - No incident_router logic here
#
# Notes:
# - This file is intentionally tolerant to multiple payload shapes so it can
#   survive old/new records without breaking the worker.
# - It does not assume a specific Airtable schema inside the capability.
# - It returns structured output the worker / retry_router can consume.

from __future__ import annotations

import ipaddress
import json
import os
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


# ============================================================
# Environment
# ============================================================

HTTP_EXEC_ENABLED = os.getenv("HTTP_EXEC_ENABLED", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}

HTTP_EXEC_USER_AGENT = os.getenv(
    "HTTP_EXEC_USER_AGENT",
    "BOSAI-Worker/http_exec",
).strip()

HTTP_EXEC_DEFAULT_TIMEOUT_SECONDS = float(
    os.getenv("HTTP_EXEC_DEFAULT_TIMEOUT_SECONDS", "20").strip() or "20"
)

HTTP_EXEC_MAX_TIMEOUT_SECONDS = float(
    os.getenv("HTTP_EXEC_MAX_TIMEOUT_SECONDS", "30").strip() or "30"
)

HTTP_EXEC_MAX_RESPONSE_BYTES = int(
    os.getenv("HTTP_EXEC_MAX_RESPONSE_BYTES", "1048576").strip() or "1048576"
)

HTTP_EXEC_FOLLOW_REDIRECTS = os.getenv(
    "HTTP_EXEC_FOLLOW_REDIRECTS",
    "0",
).strip().lower() in {"1", "true", "yes", "on"}

HTTP_EXEC_VERIFY_SSL = os.getenv(
    "HTTP_EXEC_VERIFY_SSL",
    "1",
).strip().lower() not in {"0", "false", "no", "off"}

HTTP_EXEC_ALLOW_PRIVATE_IPS = os.getenv(
    "HTTP_EXEC_ALLOW_PRIVATE_IPS",
    "0",
).strip().lower() in {"1", "true", "yes", "on"}

HTTP_EXEC_ALLOWLIST = [
    item.strip().lower()
    for item in os.getenv("HTTP_EXEC_ALLOWLIST", "").split(",")
    if item.strip()
]

HTTP_EXEC_BLOCKED_HOSTS = {
    item.strip().lower()
    for item in os.getenv(
        "HTTP_EXEC_BLOCKED_HOSTS",
        "localhost,127.0.0.1,::1,0.0.0.0,metadata.google.internal,"
        "169.254.169.254,100.100.100.200,host.docker.internal",
    ).split(",")
    if item.strip()
}

HTTP_EXEC_SUPABASE_AUTO_AUTH = os.getenv(
    "HTTP_EXEC_SUPABASE_AUTO_AUTH",
    "0",
).strip().lower() in {"1", "true", "yes", "on"}


# ============================================================
# Constants
# ============================================================

SAFE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
DEFAULT_RETRY_MAX = 3


# ============================================================
# Helpers — generic parsing
# ============================================================

def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_int(value: Any, default: int) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _to_float(value: Any, default: float) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_json_maybe(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return default
        try:
            return json.loads(raw)
        except Exception:
            return default
    return default


def _normalize_headers(value: Any) -> Dict[str, str]:
    parsed = _parse_json_maybe(value, {})
    if not isinstance(parsed, dict):
        return {}
    out: Dict[str, str] = {}
    for k, v in parsed.items():
        if k is None:
            continue
        key = str(k).strip()
        if not key:
            continue
        out[key] = "" if v is None else str(v)
    return out


def _normalize_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        parsed = _parse_json_maybe(raw, None)
        if isinstance(parsed, list):
            return [str(x).strip() for x in parsed if str(x).strip()]
        return [item.strip() for item in raw.split(",") if item.strip()]
    return []


def _pick(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in d and d[key] is not None:
            return d[key]
    return default


def _safe_json_text(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return str(value)


# ============================================================
# Helpers — retry metadata
# ============================================================

def _extract_retry_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    flow_id = _pick(payload, "flow_id", "Flow_ID", "flowId", default="")
    root_event_id = _pick(
        payload,
        "root_event_id",
        "Root_Event_ID",
        "rootEventId",
        default="",
    )
    step_index = _to_int(
        _pick(payload, "step_index", "Step_Index", "stepIndex", default=0),
        0,
    )
    retry_count = _to_int(
        _pick(payload, "retry_count", "Retry_Count", "retryCount", default=0),
        0,
    )
    retry_max = _to_int(
        _pick(payload, "retry_max", "Retry_Max", "retryMax", default=DEFAULT_RETRY_MAX),
        DEFAULT_RETRY_MAX,
    )

    return {
        "flow_id": str(flow_id or ""),
        "root_event_id": str(root_event_id or ""),
        "step_index": step_index,
        "retry_count": retry_count,
        "retry_max": retry_max,
    }


def _retry_meta_block(meta: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "flow_id": meta.get("flow_id", ""),
        "root_event_id": meta.get("root_event_id", ""),
        "step_index": meta.get("step_index", 0),
        "retry_count": meta.get("retry_count", 0),
        "retry_max": meta.get("retry_max", DEFAULT_RETRY_MAX),
        "retry": {
            "count": meta.get("retry_count", 0),
            "max": meta.get("retry_max", DEFAULT_RETRY_MAX),
        },
    }


# ============================================================
# Helpers — URL / SSRF / allowlist
# ============================================================

def _is_ip_blocked(ip_str: str) -> Tuple[bool, str]:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception:
        return True, f"invalid_ip:{ip_str}"

    if HTTP_EXEC_ALLOW_PRIVATE_IPS:
        return False, "allowed_by_env"

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return True, f"blocked_ip:{ip_str}"

    return False, "public_ip"


def _resolve_hostname_ips(hostname: str) -> List[str]:
    ips: List[str] = []
    try:
        results = socket.getaddrinfo(hostname, None)
        for item in results:
            sockaddr = item[4]
            if not sockaddr:
                continue
            ip_str = sockaddr[0]
            if ip_str and ip_str not in ips:
                ips.append(ip_str)
    except Exception:
        return []
    return ips


def _host_matches_allow_rule(host: str, rule: str) -> bool:
    host = host.lower().strip(".")
    rule = rule.lower().strip(".")

    if not host or not rule:
        return False

    if rule == "*":
        return True

    if rule.startswith("*."):
        suffix = rule[2:]
        return host == suffix or host.endswith("." + suffix)

    return host == rule or host.endswith("." + rule)


def _resolve_allowlist(payload: Dict[str, Any]) -> List[str]:
    per_request = _normalize_list(
        _pick(
            payload,
            "allowlist",
            "Allowlist",
            "allowed_domains",
            "Allowed_Domains",
            "AllowedHosts",
            default=[],
        )
    )
    merged = []
    for item in per_request + HTTP_EXEC_ALLOWLIST:
        normalized = item.strip().lower()
        if normalized and normalized not in merged:
            merged.append(normalized)
    return merged


def _validate_url(url: str, allowlist: List[str]) -> Tuple[bool, str, Dict[str, Any]]:
    diag: Dict[str, Any] = {
        "url": url,
        "allowlist": allowlist,
        "resolved_ips": [],
        "host": "",
        "scheme": "",
        "port": None,
    }

    if not url or not isinstance(url, str):
        return False, "missing_url", diag

    try:
        parsed = urlparse(url.strip())
    except Exception as exc:
        return False, f"invalid_url_parse:{exc}", diag

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port

    diag["host"] = host
    diag["scheme"] = scheme
    diag["port"] = port

    if scheme not in {"http", "https"}:
        return False, f"invalid_scheme:{scheme or 'empty'}", diag

    if not host:
        return False, "missing_host", diag

    if host in HTTP_EXEC_BLOCKED_HOSTS:
        return False, f"blocked_host:{host}", diag

    if allowlist:
        if not any(_host_matches_allow_rule(host, rule) for rule in allowlist):
            return False, f"host_not_in_allowlist:{host}", diag

    direct_ip = None
    try:
        direct_ip = str(ipaddress.ip_address(host))
    except Exception:
        direct_ip = None

    resolved_ips = [direct_ip] if direct_ip else _resolve_hostname_ips(host)
    diag["resolved_ips"] = resolved_ips

    if not resolved_ips:
        return False, f"dns_resolution_failed:{host}", diag

    for ip_str in resolved_ips:
        blocked, reason = _is_ip_blocked(ip_str)
        if blocked:
            return False, reason, diag

    return True, "ok", diag


# ============================================================
# Helpers — ToolCatalog / secrets / payload normalization
# ============================================================

def _extract_tool_config(payload: Dict[str, Any]) -> Dict[str, Any]:
    tool = _pick(payload, "tool", "Tool", "_tool", "tool_config", default={})
    parsed = _parse_json_maybe(tool, {})
    return parsed if isinstance(parsed, dict) else {}


def _enforce_toolcatalog(payload: Dict[str, Any], url: str, method: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Non-breaking optional enforcement.
    Expected shapes supported:
      payload["tool"] = {
          "enabled": true,
          "allowed_methods": ["GET", "POST"],
          "allowed_domains": ["api.example.com", "*.supabase.co"],
          "base_url": "https://..."
      }
    If tool config absent, this function passes.
    """
    tool = _extract_tool_config(payload)
    if not tool:
        return True, "no_tool_config", {}

    tool_enabled = _to_bool(tool.get("enabled", True), True)
    if not tool_enabled:
        return False, "tool_disabled", {"tool": tool}

    allowed_methods = [m.upper() for m in _normalize_list(tool.get("allowed_methods"))]
    allowed_domains = [d.lower() for d in _normalize_list(tool.get("allowed_domains"))]
    base_url = str(tool.get("base_url", "") or "").strip()

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if allowed_methods and method.upper() not in allowed_methods:
        return False, f"tool_method_not_allowed:{method.upper()}", {
            "tool": tool,
            "host": host,
        }

    if allowed_domains:
        if not any(_host_matches_allow_rule(host, rule) for rule in allowed_domains):
            return False, f"tool_domain_not_allowed:{host}", {
                "tool": tool,
                "host": host,
            }

    if base_url:
        if not url.startswith(base_url):
            return False, "tool_base_url_mismatch", {
                "tool": tool,
                "url": url,
            }

    return True, "tool_allowed", {"tool": tool}


def _get_secret_value(secret_key_name: str) -> str:
    if not secret_key_name:
        return ""
    return os.getenv(secret_key_name, "").strip()


def _apply_secret_headers(
    headers: Dict[str, str],
    payload: Dict[str, Any],
    url: str,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """
    Supported shapes:
    - Secret_Header_Keys: ["MY_API_KEY", "Authorization"]
      => inject header Authorization: <ENV[Authorization]> if env exists
      => inject header MY_API_KEY: <ENV[MY_API_KEY]> if env exists
    - Secret_Header_Map: {"Authorization": "MY_TOKEN_ENV", "x-api-key": "MY_KEY_ENV"}
    - If Secret_Header_Keys contains 'SUPABASE' and auto-auth enabled:
      inject apikey + Authorization: Bearer <SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY>
    """
    out = dict(headers)
    diag: Dict[str, Any] = {
        "secret_headers_applied": [],
        "secret_headers_missing": [],
    }

    secret_keys = _normalize_list(
        _pick(payload, "Secret_Header_Keys", "secret_header_keys", default=[])
    )
    secret_map = _parse_json_maybe(
        _pick(payload, "Secret_Header_Map", "secret_header_map", default={}),
        {},
    )
    if not isinstance(secret_map, dict):
        secret_map = {}

    for header_name, env_name in secret_map.items():
        header_name = str(header_name).strip()
        env_name = str(env_name).strip()
        if not header_name or not env_name:
            continue
        secret_value = _get_secret_value(env_name)
        if secret_value:
            out[header_name] = secret_value
            diag["secret_headers_applied"].append(header_name)
        else:
            diag["secret_headers_missing"].append(f"{header_name}:{env_name}")

    for item in secret_keys:
        token = str(item).strip()
        if not token:
            continue

        if token.upper() == "SUPABASE" and HTTP_EXEC_SUPABASE_AUTO_AUTH:
            supabase_secret = (
                os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
                or os.getenv("SUPABASE_ANON_KEY", "").strip()
            )
            parsed = urlparse(url)
            is_supabase_host = (parsed.hostname or "").endswith(".supabase.co")
            if supabase_secret and is_supabase_host:
                out["apikey"] = supabase_secret
                out["Authorization"] = f"Bearer {supabase_secret}"
                diag["secret_headers_applied"].extend(["apikey", "Authorization"])
            else:
                diag["secret_headers_missing"].append("SUPABASE")
            continue

        secret_value = _get_secret_value(token)
        if secret_value:
            out[token] = secret_value
            diag["secret_headers_applied"].append(token)
        else:
            diag["secret_headers_missing"].append(token)

    return out, diag


def _build_request_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    method = str(
        _pick(payload, "method", "Method", default="GET")
    ).strip().upper()
    if method not in SAFE_METHODS:
        method = "GET"

    url = str(_pick(payload, "url", "URL", "endpoint", "Endpoint", default="")).strip()

    headers = _normalize_headers(_pick(payload, "headers", "Headers", default={}))
    params = _parse_json_maybe(_pick(payload, "params", "Params", default={}), {})
    if not isinstance(params, dict):
        params = {}

    json_body = _parse_json_maybe(
        _pick(payload, "json", "json_body", "Json_Body", default=None),
        None,
    )

    raw_body = _pick(payload, "body", "Body", "data", "Data", default=None)

    timeout_seconds = _to_float(
        _pick(
            payload,
            "timeout_seconds",
            "Timeout_Seconds",
            "timeout",
            default=HTTP_EXEC_DEFAULT_TIMEOUT_SECONDS,
        ),
        HTTP_EXEC_DEFAULT_TIMEOUT_SECONDS,
    )
    timeout_seconds = max(0.5, min(timeout_seconds, HTTP_EXEC_MAX_TIMEOUT_SECONDS))

    follow_redirects = _to_bool(
        _pick(
            payload,
            "follow_redirects",
            "Follow_Redirects",
            default=HTTP_EXEC_FOLLOW_REDIRECTS,
        ),
        HTTP_EXEC_FOLLOW_REDIRECTS,
    )

    verify_ssl = _to_bool(
        _pick(payload, "verify_ssl", "Verify_SSL", default=HTTP_EXEC_VERIFY_SSL),
        HTTP_EXEC_VERIFY_SSL,
    )

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "params": params,
        "json_body": json_body,
        "raw_body": raw_body,
        "timeout_seconds": timeout_seconds,
        "follow_redirects": follow_redirects,
        "verify_ssl": verify_ssl,
    }


# ============================================================
# Helpers — HTTP execution
# ============================================================

def _truncate_bytes(data: bytes, max_bytes: int) -> bytes:
    if len(data) <= max_bytes:
        return data
    return data[:max_bytes]


def _decode_response_body(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except Exception:
        try:
            return raw.decode("latin-1")
        except Exception:
            return raw.decode("utf-8", errors="replace")


def _response_to_dict(response: requests.Response) -> Dict[str, Any]:
    raw = _truncate_bytes(response.content or b"", HTTP_EXEC_MAX_RESPONSE_BYTES)
    text = _decode_response_body(raw)

    parsed_json = None
    content_type = response.headers.get("Content-Type", "")
    if "application/json" in content_type.lower():
        try:
            parsed_json = response.json()
        except Exception:
            parsed_json = None

    return {
        "status_code": response.status_code,
        "reason": response.reason,
        "ok_http": response.ok,
        "headers": dict(response.headers),
        "content_type": content_type,
        "body_text": text,
        "body_json": parsed_json,
        "body_bytes_read": len(raw),
        "final_url": response.url,
    }


def _build_session(provided_session: Optional[requests.Session] = None) -> requests.Session:
    session = provided_session or requests.Session()
    session.headers.update({"User-Agent": HTTP_EXEC_USER_AGENT})
    return session


# ============================================================
# Public capability
# ============================================================

def capability_http_exec(
    input_data: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
    session: Optional[requests.Session] = None,
    **_: Any,
) -> Dict[str, Any]:
    """
    Main BOSAI capability entrypoint.

    Returns a structured dict.
    Failure path always targets retry_router via next_commands.
    """
    started_at = _now_ts()
    payload = input_data or {}
    retry_meta = _extract_retry_meta(payload)
    retry_block = _retry_meta_block(retry_meta)

    flow_id = str(payload.get("flow_id") or "").strip()
    root_event_id = str(payload.get("root_event_id") or "").strip()
    workspace_id = str(payload.get("workspace_id") or "").strip()

    def _build_retry_input(
        reason: str,
        error: str = "",
        http_status: Optional[int] = None,
    ) -> Dict[str, Any]:
        retry_input = dict(payload)
        retry_input.update(
            {
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "workspace_id": workspace_id,
                "original_capability": "http_exec",
                "original_input": dict(payload),
                "retry_reason": reason,
            }
        )

        if error:
            retry_input["error"] = error
        if http_status is not None:
            retry_input["http_status"] = http_status

        return retry_input

    def _build_retry_next_command(
        reason: str,
        error: str = "",
        http_status: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        return [
            {
                "capability": "retry_router",
                "priority": 2,
                "input": _build_retry_input(
                    reason=reason,
                    error=error,
                    http_status=http_status,
                ),
            }
        ]

    if not HTTP_EXEC_ENABLED:
        return {
            "ok": False,
            "capability": "http_exec",
            "status": "disabled",
            "error_code": "http_exec_disabled",
            "error": "HTTP_EXEC_ENABLED=0",
            "started_at": started_at,
            **retry_block,
            "next_commands": _build_retry_next_command(
                "capability_disabled",
                error="HTTP_EXEC_ENABLED=0",
            ),
            "retry_reason": "capability_disabled",
            "terminal": False,
        }

    request_cfg = _build_request_payload(payload)
    method = request_cfg["method"]
    url = request_cfg["url"]
    headers = dict(request_cfg["headers"])
    params = dict(request_cfg["params"])
    json_body = request_cfg["json_body"]
    raw_body = request_cfg["raw_body"]
    timeout_seconds = request_cfg["timeout_seconds"]
    follow_redirects = request_cfg["follow_redirects"]
    verify_ssl = request_cfg["verify_ssl"]

    allowlist = _resolve_allowlist(payload)

    if "Accept" not in headers:
        headers["Accept"] = "application/json, text/plain, */*"

    body_to_send = None
    if json_body is not None:
        headers.setdefault("Content-Type", "application/json")
    elif raw_body is not None:
        if isinstance(raw_body, (dict, list)):
            body_to_send = _safe_json_text(raw_body)
            headers.setdefault("Content-Type", "application/json")
        else:
            body_to_send = str(raw_body)

    headers, secret_diag = _apply_secret_headers(headers, payload, url)

    url_ok, url_reason, url_diag = _validate_url(url, allowlist)
    if not url_ok:
        return {
            "ok": False,
            "capability": "http_exec",
            "status": "blocked",
            "error_code": "ssrf_or_allowlist_block",
            "error": url_reason,
            "started_at": started_at,
            **retry_block,
            "request": {
                "method": method,
                "url": url,
                "headers": {
                    k: ("***" if k.lower() == "authorization" else v)
                    for k, v in headers.items()
                },
                "params": params,
                "timeout_seconds": timeout_seconds,
                "follow_redirects": follow_redirects,
                "verify_ssl": verify_ssl,
            },
            "security": {
                "url_validation": url_diag,
                **secret_diag,
            },
            "next_commands": _build_retry_next_command(
                "url_blocked",
                error=url_reason,
            ),
            "retry_reason": "url_blocked",
            "terminal": False,
        }

    tool_ok, tool_reason, tool_diag = _enforce_toolcatalog(payload, url, method)
    if not tool_ok:
        return {
            "ok": False,
            "capability": "http_exec",
            "status": "blocked",
            "error_code": "toolcatalog_block",
            "error": tool_reason,
            "started_at": started_at,
            **retry_block,
            "request": {
                "method": method,
                "url": url,
            },
            "toolcatalog": tool_diag,
            "next_commands": _build_retry_next_command(
                "toolcatalog_block",
                error=tool_reason,
            ),
            "retry_reason": "toolcatalog_block",
            "terminal": False,
        }

    if dry_run:
        return {
            "ok": True,
            "capability": "http_exec",
            "status": "dry_run",
            "started_at": started_at,
            **retry_block,
            "request": {
                "method": method,
                "url": url,
                "headers": {
                    k: ("***" if k.lower() == "authorization" else v)
                    for k, v in headers.items()
                },
                "params": params,
                "json_body": json_body,
                "body": body_to_send,
                "timeout_seconds": timeout_seconds,
                "follow_redirects": follow_redirects,
                "verify_ssl": verify_ssl,
            },
            "security": {
                "url_validation": url_diag,
                **secret_diag,
            },
            "toolcatalog": tool_diag,
            "next_commands": [],
            "terminal": True,
        }

    client = _build_session(session)
    request_started = time.time()

    try:
        response = client.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=json_body if json_body is not None else None,
            data=body_to_send if json_body is None else None,
            timeout=timeout_seconds,
            allow_redirects=follow_redirects,
            verify=verify_ssl,
        )
        elapsed_ms = int((time.time() - request_started) * 1000)
        response_dict = _response_to_dict(response)

        if response.ok:
            return {
                "ok": True,
                "capability": "http_exec",
                "status": "done",
                "started_at": started_at,
                "finished_at": _now_ts(),
                "elapsed_ms": elapsed_ms,
                **retry_block,
                "request": {
                    "method": method,
                    "url": url,
                    "params": params,
                    "timeout_seconds": timeout_seconds,
                },
                "response": response_dict,
                "security": {
                    "url_validation": url_diag,
                    **secret_diag,
                },
                "toolcatalog": tool_diag,
                "next_commands": [],
                "terminal": True,
            }

        error_payload = _build_retry_input(
            reason="http_status_error",
            error=f"HTTP {response.status_code}",
            http_status=response.status_code,
        )
        error_payload.update(
            {
                "url": url,
                "http_target": url,
                "method": method,
            }
        )

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error_code": "http_status_error",
            "error": f"HTTP {response.status_code}",
            "started_at": started_at,
            "finished_at": _now_ts(),
            "elapsed_ms": elapsed_ms,
            **retry_block,
            "request": {
                "method": method,
                "url": url,
                "params": params,
                "timeout_seconds": timeout_seconds,
            },
            "response": response_dict,
            "security": {
                "url_validation": url_diag,
                **secret_diag,
            },
            "toolcatalog": tool_diag,
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "http_status_error",
            "terminal": False,
        }

    except requests.Timeout as exc:
        elapsed_ms = int((time.time() - request_started) * 1000)

        error_payload = _build_retry_input(
            reason="timeout",
            error=str(exc),
            http_status=None,
        )
        error_payload.update(
            {
                "url": url,
                "http_target": url,
                "method": method,
            }
        )

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error_code": "timeout",
            "error": str(exc),
            "started_at": started_at,
            "finished_at": _now_ts(),
            "elapsed_ms": elapsed_ms,
            **retry_block,
            "request": {
                "method": method,
                "url": url,
                "params": params,
                "timeout_seconds": timeout_seconds,
            },
            "security": {
                "url_validation": url_diag,
                **secret_diag,
            },
            "toolcatalog": tool_diag,
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "timeout",
            "terminal": False,
        }

    except requests.RequestException as exc:
        elapsed_ms = int((time.time() - request_started) * 1000)

        error_payload = _build_retry_input(
            reason="request_exception",
            error=str(exc),
            http_status=None,
        )
        error_payload.update(
            {
                "url": url,
                "http_target": url,
                "method": method,
            }
        )

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error_code": "request_exception",
            "error": str(exc),
            "started_at": started_at,
            "finished_at": _now_ts(),
            "elapsed_ms": elapsed_ms,
            **retry_block,
            "request": {
                "method": method,
                "url": url,
                "params": params,
                "timeout_seconds": timeout_seconds,
            },
            "security": {
                "url_validation": url_diag,
                **secret_diag,
            },
            "toolcatalog": tool_diag,
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "request_exception",
            "terminal": False,
        }

    except Exception as exc:
        elapsed_ms = int((time.time() - request_started) * 1000)

        error_payload = _build_retry_input(
            reason="unexpected_exception",
            error=str(exc),
            http_status=None,
        )
        error_payload.update(
            {
                "url": url,
                "http_target": url,
                "method": method,
            }
        )

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error_code": "unexpected_exception",
            "error": str(exc),
            "started_at": started_at,
            "finished_at": _now_ts(),
            "elapsed_ms": elapsed_ms,
            **retry_block,
            "request": {
                "method": method,
                "url": url,
                "params": params,
                "timeout_seconds": timeout_seconds,
            },
            "security": {
                "url_validation": url_diag,
                **secret_diag,
            },
            "toolcatalog": tool_diag,
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "unexpected_exception",
            "terminal": False,
        }
def run(req: Any = None, run_record_id: str = "") -> Dict[str, Any]:
    """
    Alias compatible with workers calling fn(req, run_record_id).
    """
    if isinstance(req, dict):
        payload = req
    else:
        payload = getattr(req, "input", None) or {}

    if not isinstance(payload, dict):
        payload = {}

    payload = dict(payload)

    if run_record_id and "run_record_id" not in payload:
        payload["run_record_id"] = run_record_id

    return capability_http_exec(
        input_data=payload,
        dry_run=False,
        session=None,
    )
