# app/capabilities/http_exec.py

from __future__ import annotations

import ipaddress
import json
import socket
import time
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

print("HTTP_EXEC_MODULE_LOADED_V3")

HTTP_EXEC_ENABLED = True
DEFAULT_RETRY_MAX = 3
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_RETRY_DELAY_SECONDS = 10
DEFAULT_MAX_DEPTH = 8

REQUEST_SESSION = requests.Session()

FORBIDDEN_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
}


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _to_float(value: Any, default: float) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def _safe_json_dumps(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        try:
            return json.dumps(str(value), ensure_ascii=False)
        except Exception:
            return "{}"


def _trim_text(value: Any, limit: int = 2000) -> str:
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _normalize_method(value: Any) -> str:
    method = str(value or "GET").strip().upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        return "GET"
    return method


def _normalize_headers(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}

    result: Dict[str, str] = {}
    for k, v in value.items():
        key = str(k).strip()
        if not key:
            continue
        result[key] = "" if v is None else str(v)
    return result


def _normalize_params(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return dict(value)


def _normalize_json_body(value: Any) -> Optional[Any]:
    if value is None or value == "":
        return None
    return value


def _normalize_text_body(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list)):
        return _safe_json_dumps(value)
    return str(value)


def _sanitize_headers_for_logs(headers: Dict[str, Any]) -> Dict[str, Any]:
    secret_markers = {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "apikey",
        "cookie",
        "set-cookie",
        "x-auth-token",
    }

    sanitized: Dict[str, Any] = {}
    for k, v in (headers or {}).items():
        key = str(k)
        if key.strip().lower() in secret_markers:
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = v
    return sanitized


def _extract_retry_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    flow_id = str(payload.get("flow_id", "") or "")
    root_event_id = str(payload.get("root_event_id", "") or "")
    parent_command_id = str(
        payload.get("parent_command_id")
        or payload.get("parent_id")
        or payload.get("linked_command_id")
        or ""
    )

    step_index = _to_int(payload.get("step_index"), 0)
    retry_count = _to_int(payload.get("retry_count"), 0)
    retry_max = _to_int(payload.get("retry_max"), DEFAULT_RETRY_MAX)
    retry_delay_seconds = _to_int(
        payload.get("retry_delay_seconds"),
        _to_int(payload.get("retry_delay_sec"), DEFAULT_RETRY_DELAY_SECONDS),
    )

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "parent_command_id": parent_command_id,
        "step_index": step_index,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_delay_seconds": retry_delay_seconds,
    }


def _compute_backoff_seconds(payload: Dict[str, Any], retry_count_after_failure: int) -> int:
    fixed_delay = _to_int(
        payload.get("retry_delay_seconds"),
        _to_int(payload.get("retry_delay_sec"), DEFAULT_RETRY_DELAY_SECONDS),
    )
    base = max(1, fixed_delay)

    if _to_bool(payload.get("retry_backoff_exponential"), False):
        max_delay = max(base, _to_int(payload.get("retry_backoff_max_seconds"), 300))
        return min(base * (2 ** max(0, retry_count_after_failure - 1)), max_delay)

    return base


def _build_next_retry_at(delay_seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + max(0, delay_seconds)))


def _get_depth(payload: Dict[str, Any]) -> int:
    return _to_int(payload.get("_depth"), 0)


def _increment_depth(payload: Dict[str, Any]) -> int:
    return _get_depth(payload) + 1


def _parse_allowlist(payload: Dict[str, Any]) -> List[str]:
    raw = payload.get("allowed_hosts") or payload.get("host_allowlist") or []
    if isinstance(raw, str):
        items = [x.strip() for x in raw.split(",")]
    elif isinstance(raw, list):
        items = [str(x).strip() for x in raw]
    else:
        items = []

    cleaned = [x.lower() for x in items if x]
    return cleaned


def _host_matches_allowlist(host: str, allowlist: List[str]) -> bool:
    if not allowlist:
        return True

    host_l = host.lower()
    for allowed in allowlist:
        if not allowed:
            continue
        if host_l == allowed:
            return True
        if allowed.startswith("*."):
            suffix = allowed[1:]
            if host_l.endswith(suffix) and host_l != suffix.lstrip("."):
                return True
        elif host_l.endswith("." + allowed):
            return True
    return False


def _ip_is_forbidden(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        return bool(
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except Exception:
        return True


def _resolve_host_ips(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []

    ips: List[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if ip and ip not in ips:
            ips.append(ip)
    return ips


def _validate_url(url: str, allowlist: List[str]) -> Tuple[bool, str, Dict[str, Any]]:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().lower()

    debug = {
        "scheme": scheme,
        "host": host,
        "port": parsed.port,
        "path": parsed.path,
    }

    if scheme not in {"http", "https"}:
        return False, "invalid_scheme", debug

    if not host:
        return False, "missing_host", debug

    if host in FORBIDDEN_HOSTS:
        return False, "forbidden_host", debug

    if not _host_matches_allowlist(host, allowlist):
        return False, "host_not_allowed", debug

    ips = _resolve_host_ips(host)
    debug["resolved_ips"] = ips

    if not ips:
        return False, "dns_resolution_failed", debug

    for ip in ips:
        if _ip_is_forbidden(ip):
            debug["blocked_ip"] = ip
            return False, "forbidden_ip", debug

    return True, "ok", debug


def _extract_response_payload(response: requests.Response) -> Dict[str, Any]:
    content_type = str(response.headers.get("Content-Type", "") or "")
    text = response.text if response.text is not None else ""

    body_json: Optional[Any] = None
    if "application/json" in content_type.lower():
        try:
            body_json = response.json()
        except Exception:
            body_json = None

    return {
        "status_code": int(response.status_code),
        "ok": bool(response.ok),
        "content_type": content_type,
        "headers": dict(response.headers),
        "body_text": _trim_text(text, 4000),
        "body_json": body_json,
        "elapsed_ms": int(getattr(response.elapsed, "total_seconds", lambda: 0.0)() * 1000),
    }


def _build_incident_router_command(
    *,
    original_payload: Dict[str, Any],
    meta: Dict[str, Any],
    error_code: str,
    error_message: str,
    http_status: Optional[int],
    request_summary: Dict[str, Any],
    response_summary: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    next_depth = _increment_depth(original_payload)

    incident_input = {
        "flow_id": meta["flow_id"],
        "root_event_id": meta["root_event_id"],
        "parent_command_id": meta["parent_command_id"],
        "step_index": meta["step_index"] + 1,
        "_depth": next_depth,
        "source_capability": "http_exec",
        "incident_type": "http_exec_failure",
        "incident_code": error_code,
        "incident_message": error_message,
        "http_status": http_status,
        "request": request_summary,
        "response": response_summary or {},
        "failed_at": _now_ts(),
        "retry_count": meta["retry_count"],
        "retry_max": meta["retry_max"],
        "final_failure": True,
    }

    return {
        "capability": "incident_router",
        "input": incident_input,
    }


def _update_monitored_endpoint_best_effort(
    *,
    original_payload: Dict[str, Any],
    runtime_context: Dict[str, Any],
    status_code: Optional[int],
    error_text: str,
    elapsed_ms: Optional[int],
) -> None:
    try:
        endpoint_name = str(
            original_payload.get("endpoint_name")
            or original_payload.get("endpoint")
            or ""
        ).strip()

        airtable_update_by_field = runtime_context.get("airtable_update_by_field")
        run_record_id = str(runtime_context.get("run_record_id") or "").strip()

        if not endpoint_name:
            print("[http_exec] skip monitored endpoint update: missing endpoint_name", flush=True)
            return

        if not callable(airtable_update_by_field):
            print("[http_exec] skip monitored endpoint update: missing helper", flush=True)
            return

        fields: Dict[str, Any] = {
            "Last_Check_At": _now_ts(),
            "Last_Error": str(error_text or ""),
        }

        if status_code is not None:
            fields["Last_Status"] = int(status_code)

        if elapsed_ms is not None:
            fields["Last_Response_Time_ms"] = int(elapsed_ms)

        if run_record_id:
            fields["Last_Run_ID"] = run_record_id

        airtable_update_by_field(
            table="Monitored_Endpoints",
            field="Name",
            value=endpoint_name,
            fields=fields,
        )
        print("[http_exec] endpoint runtime updated =", endpoint_name, flush=True)

    except Exception as e:
        print("[http_exec] endpoint update error =", repr(e), flush=True)


def capability_http_exec(
    payload: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    print("[HTTP_EXEC CORE] entered")
    context = context or {}

    runtime_context: Dict[str, Any] = dict(context) if isinstance(context, dict) else {}

    if "run_record_id" not in runtime_context and kwargs.get("run_record_id"):
        runtime_context["run_record_id"] = kwargs.get("run_record_id")

    if "airtable_update_by_field" not in runtime_context and kwargs.get("airtable_update_by_field"):
        runtime_context["airtable_update_by_field"] = kwargs.get("airtable_update_by_field")

    if payload is None and isinstance(kwargs.get("input_data"), dict):
        payload = kwargs["input_data"]
    elif payload is None and isinstance(kwargs.get("payload"), dict):
        payload = kwargs["payload"]

    original_payload = deepcopy(payload or {})
    meta = _extract_retry_meta(original_payload)

    if not HTTP_EXEC_ENABLED:
        result = {
            "ok": False,
            "status": "blocked",
            "error": "http_exec_disabled",
            "ts": _now_ts(),
            "flow_id": meta["flow_id"],
            "root_event_id": meta["root_event_id"],
            "step_index": meta["step_index"],
            "retry_planned": False,
            "next_commands": [],
            "http_status": None,
            "status_code": None,
        }
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    if _get_depth(original_payload) >= _to_int(original_payload.get("max_depth"), DEFAULT_MAX_DEPTH):
        result = {
            "ok": False,
            "status": "blocked",
            "error": "max_depth_exceeded",
            "ts": _now_ts(),
            "flow_id": meta["flow_id"],
            "root_event_id": meta["root_event_id"],
            "step_index": meta["step_index"],
            "retry_planned": False,
            "next_commands": [],
            "http_status": None,
            "status_code": None,
        }
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    url = str(original_payload.get("url") or "").strip()
    method = _normalize_method(original_payload.get("method"))
    timeout_seconds = max(
        1,
        _to_int(original_payload.get("timeout_seconds"), DEFAULT_TIMEOUT_SECONDS),
    )
    params = _normalize_params(original_payload.get("params"))
    headers = _normalize_headers(original_payload.get("headers"))
    json_body = _normalize_json_body(original_payload.get("json"))
    data_body = _normalize_text_body(original_payload.get("data"))
    allow_redirects = _to_bool(original_payload.get("follow_redirects"), False)
    verify_tls = _to_bool(original_payload.get("verify_tls"), True)
    dry_run = _to_bool(original_payload.get("dry_run"), False)

    allowlist = _parse_allowlist(original_payload)
    if not url:
        result = {
            "ok": False,
            "status": "error",
            "error": "missing_url",
            "ts": _now_ts(),
            "flow_id": meta["flow_id"],
            "root_event_id": meta["root_event_id"],
            "step_index": meta["step_index"],
            "retry_planned": False,
            "next_commands": [],
            "http_status": None,
            "status_code": None,
        }
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    allowed, allow_reason, url_debug = _validate_url(url, allowlist)
    request_summary = {
        "method": method,
        "url": url,
        "params": params,
        "headers": _sanitize_headers_for_logs(headers),
        "has_json": json_body is not None,
        "has_data": data_body is not None,
        "timeout_seconds": timeout_seconds,
        "follow_redirects": allow_redirects,
        "verify_tls": verify_tls,
        "url_debug": url_debug,
    }

    if not allowed:
        result = {
            "ok": False,
            "status": "blocked",
            "error": allow_reason,
            "error_message": f"URL blocked: {allow_reason}",
            "ts": _now_ts(),
            "flow_id": meta["flow_id"],
            "root_event_id": meta["root_event_id"],
            "step_index": meta["step_index"],
            "request": request_summary,
            "retry_planned": False,
            "next_commands": [],
            "http_status": None,
            "status_code": None,
        }
        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=None,
            error_text=allow_reason,
            elapsed_ms=None,
        )
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    if dry_run:
        result = {
            "ok": True,
            "status": "done",
            "dry_run": True,
            "ts": _now_ts(),
            "flow_id": meta["flow_id"],
            "root_event_id": meta["root_event_id"],
            "step_index": meta["step_index"],
            "request": request_summary,
            "response": {
                "status_code": 0,
                "ok": True,
                "content_type": "application/json",
                "headers": {},
                "body_text": "",
                "body_json": {"dry_run": True},
                "elapsed_ms": 0,
            },
            "retry_planned": False,
            "next_commands": [],
            "http_status": 0,
            "status_code": 0,
        }
        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=0,
            error_text="",
            elapsed_ms=0,
        )
        print("[HTTP_EXEC CORE] success return")
        return result

    started_at = time.time()

    try:
        response = REQUEST_SESSION.request(
            method=method,
            url=url,
            params=params or None,
            headers=headers or None,
            json=json_body,
            data=data_body,
            timeout=timeout_seconds,
            allow_redirects=allow_redirects,
            verify=verify_tls,
        )

        elapsed_ms = int((time.time() - started_at) * 1000)
        response_payload = _extract_response_payload(response)
        response_payload["elapsed_ms"] = elapsed_ms

        success_statuses = original_payload.get("success_statuses")
        if isinstance(success_statuses, list) and success_statuses:
            is_success = int(response.status_code) in {
                _to_int(x, -999999) for x in success_statuses
            }
        else:
            is_success = 200 <= int(response.status_code) < 300

        if is_success:
            result = {
                "ok": True,
                "status": "done",
                "ts": _now_ts(),
                "flow_id": meta["flow_id"],
                "root_event_id": meta["root_event_id"],
                "step_index": meta["step_index"],
                "request": request_summary,
                "response": response_payload,
                "status_code": int(response.status_code),
                "http_status": int(response.status_code),
                "retry_planned": False,
                "next_commands": [],
            }
            _update_monitored_endpoint_best_effort(
                original_payload=original_payload,
                runtime_context=runtime_context,
                status_code=int(response.status_code),
                error_text="",
                elapsed_ms=elapsed_ms,
            )
            print("[HTTP_EXEC CORE] success return")
            return result

        retry_count_after_failure = meta["retry_count"] + 1
        retry_allowed = retry_count_after_failure <= meta["retry_max"]

        result: Dict[str, Any] = {
            "ok": False,
            "status": "error",
            "ts": _now_ts(),
            "flow_id": meta["flow_id"],
            "root_event_id": meta["root_event_id"],
            "step_index": meta["step_index"],
            "request": request_summary,
            "response": response_payload,
            "status_code": int(response.status_code),
            "http_status": int(response.status_code),
            "error": "http_status_error",
            "error_message": f"HTTP request failed with status {response.status_code}",
            "retry_count": retry_count_after_failure,
            "retry_max": meta["retry_max"],
            "retry_planned": False,
            "next_commands": [],
        }

        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=int(response.status_code),
            error_text="http_status_error",
            elapsed_ms=elapsed_ms,
        )

        if retry_allowed:
            delay_seconds = _compute_backoff_seconds(original_payload, retry_count_after_failure)
            next_retry_at = _build_next_retry_at(delay_seconds)

            retry_input = deepcopy(original_payload)
            retry_input["retry_count"] = retry_count_after_failure
            retry_input["next_retry_at"] = next_retry_at
            retry_input["_depth"] = _increment_depth(original_payload)

            result["retry_planned"] = True
            result["next_retry_at"] = next_retry_at
            result["next_commands"] = [
                {
                    "capability": "retry_router",
                    "input": retry_input,
                }
            ]
            print("[HTTP_EXEC CORE] error return =", result)
            return result

        incident_command = _build_incident_router_command(
            original_payload=original_payload,
            meta=meta,
            error_code="http_status_error",
            error_message=f"HTTP request failed with status {response.status_code}",
            http_status=int(response.status_code),
            request_summary=request_summary,
            response_summary=response_payload,
        )

        result["next_commands"] = [incident_command]
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    except requests.Timeout as exc:
        elapsed_ms = int((time.time() - started_at) * 1000)
        retry_count_after_failure = meta["retry_count"] + 1
        retry_allowed = retry_count_after_failure <= meta["retry_max"]

        result = {
            "ok": False,
            "status": "error",
            "ts": _now_ts(),
            "flow_id": meta["flow_id"],
            "root_event_id": meta["root_event_id"],
            "step_index": meta["step_index"],
            "request": request_summary,
            "response": {
                "status_code": None,
                "ok": False,
                "content_type": "",
                "headers": {},
                "body_text": "",
                "body_json": None,
                "elapsed_ms": elapsed_ms,
            },
            "status_code": None,
            "http_status": None,
            "error": "timeout",
            "error_message": _trim_text(str(exc), 1000) or "Request timeout",
            "retry_count": retry_count_after_failure,
            "retry_max": meta["retry_max"],
            "retry_planned": False,
            "next_commands": [],
        }

        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=None,
            error_text="timeout",
            elapsed_ms=elapsed_ms,
        )

        if retry_allowed:
            delay_seconds = _compute_backoff_seconds(original_payload, retry_count_after_failure)
            next_retry_at = _build_next_retry_at(delay_seconds)

            retry_input = deepcopy(original_payload)
            retry_input["retry_count"] = retry_count_after_failure
            retry_input["next_retry_at"] = next_retry_at
            retry_input["_depth"] = _increment_depth(original_payload)

            result["retry_planned"] = True
            result["next_retry_at"] = next_retry_at
            result["next_commands"] = [
                {
                    "capability": "retry_router",
                    "input": retry_input,
                }
            ]
            print("[HTTP_EXEC CORE] error return =", result)
            return result

        incident_command = _build_incident_router_command(
            original_payload=original_payload,
            meta=meta,
            error_code="timeout",
            error_message=_trim_text(str(exc), 1000) or "Request timeout",
            http_status=None,
            request_summary=request_summary,
            response_summary=result["response"],
        )
        result["next_commands"] = [incident_command]
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    except requests.RequestException as exc:
        elapsed_ms = int((time.time() - started_at) * 1000)
        retry_count_after_failure = meta["retry_count"] + 1
        retry_allowed = retry_count_after_failure <= meta["retry_max"]

        result = {
            "ok": False,
            "status": "error",
            "ts": _now_ts(),
            "flow_id": meta["flow_id"],
            "root_event_id": meta["root_event_id"],
            "step_index": meta["step_index"],
            "request": request_summary,
            "response": {
                "status_code": None,
                "ok": False,
                "content_type": "",
                "headers": {},
                "body_text": "",
                "body_json": None,
                "elapsed_ms": elapsed_ms,
            },
            "status_code": None,
            "http_status": None,
            "error": "request_exception",
            "error_message": _trim_text(str(exc), 1000) or exc.__class__.__name__,
            "retry_count": retry_count_after_failure,
            "retry_max": meta["retry_max"],
            "retry_planned": False,
            "next_commands": [],
        }

        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=None,
            error_text="request_exception",
            elapsed_ms=elapsed_ms,
        )

        if retry_allowed:
            delay_seconds = _compute_backoff_seconds(original_payload, retry_count_after_failure)
            next_retry_at = _build_next_retry_at(delay_seconds)

            retry_input = deepcopy(original_payload)
            retry_input["retry_count"] = retry_count_after_failure
            retry_input["next_retry_at"] = next_retry_at
            retry_input["_depth"] = _increment_depth(original_payload)

            result["retry_planned"] = True
            result["next_retry_at"] = next_retry_at
            result["next_commands"] = [
                {
                    "capability": "retry_router",
                    "input": retry_input,
                }
            ]
            print("[HTTP_EXEC CORE] error return =", result)
            return result

        incident_command = _build_incident_router_command(
            original_payload=original_payload,
            meta=meta,
            error_code="request_exception",
            error_message=_trim_text(str(exc), 1000) or exc.__class__.__name__,
            http_status=None,
            request_summary=request_summary,
            response_summary=result["response"],
        )
        result["next_commands"] = [incident_command]
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    except Exception as exc:
        elapsed_ms = int((time.time() - started_at) * 1000)
        retry_count_after_failure = meta["retry_count"] + 1
        retry_allowed = retry_count_after_failure <= meta["retry_max"]

        result = {
            "ok": False,
            "status": "error",
            "ts": _now_ts(),
            "flow_id": meta["flow_id"],
            "root_event_id": meta["root_event_id"],
            "step_index": meta["step_index"],
            "request": request_summary,
            "response": {
                "status_code": None,
                "ok": False,
                "content_type": "",
                "headers": {},
                "body_text": "",
                "body_json": None,
                "elapsed_ms": elapsed_ms,
            },
            "status_code": None,
            "http_status": None,
            "error": "unexpected_exception",
            "error_message": _trim_text(f"{exc.__class__.__name__}: {exc}", 1000),
            "retry_count": retry_count_after_failure,
            "retry_max": meta["retry_max"],
            "retry_planned": False,
            "next_commands": [],
        }

        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=None,
            error_text="unexpected_exception",
            elapsed_ms=elapsed_ms,
        )

        if retry_allowed:
            delay_seconds = _compute_backoff_seconds(original_payload, retry_count_after_failure)
            next_retry_at = _build_next_retry_at(delay_seconds)

            retry_input = deepcopy(original_payload)
            retry_input["retry_count"] = retry_count_after_failure
            retry_input["next_retry_at"] = next_retry_at
            retry_input["_depth"] = _increment_depth(original_payload)

            result["retry_planned"] = True
            result["next_retry_at"] = next_retry_at
            result["next_commands"] = [
                {
                    "capability": "retry_router",
                    "input": retry_input,
                }
            ]
            print("[HTTP_EXEC CORE] error return =", result)
            return result

        incident_command = _build_incident_router_command(
            original_payload=original_payload,
            meta=meta,
            error_code="unexpected_exception",
            error_message=_trim_text(f"{exc.__class__.__name__}: {exc}", 1000),
            http_status=None,
            request_summary=request_summary,
            response_summary=result["response"],
        )
        result["next_commands"] = [incident_command]
        print("[HTTP_EXEC CORE] error return =", result)
        return result


def run(
    payload: Optional[Any] = None,
    context: Optional[Any] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    if payload is not None and hasattr(payload, "input"):
        payload = getattr(payload, "input", {}) or {}
    elif not isinstance(payload, dict):
        payload = {}

    return capability_http_exec(payload=payload, context=context, **kwargs)
