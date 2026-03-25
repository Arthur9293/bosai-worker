from __future__ import annotations

import time
from copy import deepcopy
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

HTTP_EXEC_ENABLED = True
DEFAULT_RETRY_MAX = 3
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_RETRY_DELAY_SECONDS = 10
DEFAULT_MAX_DEPTH = 8

REQUEST_SESSION = requests.Session()


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


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _clip(value: int, min_value: int, max_value: int) -> int:
    return max(min_value, min(value, max_value))


def _first_non_empty(payload: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    for key in keys:
        if key in payload:
            value = payload.get(key)
            if value is not None and value != "":
                return value
    return default


def _normalize_headers(value: Any) -> Dict[str, str]:
    raw = _safe_dict(value)
    out: Dict[str, str] = {}
    for k, v in raw.items():
        key = _safe_str(k).strip()
        if not key:
            continue
        out[key] = _safe_str(v)
    return out


def _normalize_method(value: Any) -> str:
    method = _safe_str(value).strip().upper()
    if not method:
        return "GET"

    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    return method if method in allowed else "GET"


def _coerce_payload(payload: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return payload

    candidate = kwargs.get("input_data")
    if isinstance(candidate, dict):
        return candidate

    candidate = kwargs.get("payload")
    if isinstance(candidate, dict):
        return candidate

    return {}


def _extract_flow_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    flow_id = _safe_str(
        _first_non_empty(payload, ["flow_id", "flowid", "Flow_ID", "FlowId"], "")
    ).strip()

    root_event_id = _safe_str(
        _first_non_empty(payload, ["root_event_id", "rooteventid", "rootEventId", "event_id"], "")
    ).strip()

    parent_command_id = _safe_str(
        _first_non_empty(payload, ["parent_command_id", "parentcommandid", "command_id", "commandid"], "")
    ).strip()

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "parent_command_id": parent_command_id,
    }


def _extract_retry_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    retry_count = _to_int(_first_non_empty(payload, ["retry_count", "retrycount"], 0), 0)
    retry_max = _to_int(
        _first_non_empty(payload, ["retry_max", "retrymax"], DEFAULT_RETRY_MAX),
        DEFAULT_RETRY_MAX,
    )
    retry_delay_seconds = _to_int(
        _first_non_empty(
            payload,
            ["retry_delay_seconds", "retrydelayseconds", "retry_delay"],
            DEFAULT_RETRY_DELAY_SECONDS,
        ),
        DEFAULT_RETRY_DELAY_SECONDS,
    )
    step_index = _to_int(_first_non_empty(payload, ["step_index", "stepindex"], 0), 0)
    max_depth = _to_int(
        _first_non_empty(payload, ["max_depth", "maxdepth"], DEFAULT_MAX_DEPTH),
        DEFAULT_MAX_DEPTH,
    )

    return {
        "retry_count": max(0, retry_count),
        "retry_max": _clip(retry_max, 0, 100),
        "retry_delay_seconds": max(0, retry_delay_seconds),
        "step_index": max(0, step_index),
        "max_depth": max(1, max_depth),
    }


def _extract_execution_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    timeout_seconds = _clip(
        _to_int(
            _first_non_empty(payload, ["timeout_seconds", "timeoutseconds"], DEFAULT_TIMEOUT_SECONDS),
            DEFAULT_TIMEOUT_SECONDS,
        ),
        1,
        300,
    )

    dry_run = _to_bool(_first_non_empty(payload, ["dry_run", "dryrun"], False), False)
    allow_redirects = _to_bool(
        _first_non_empty(payload, ["allow_redirects", "allowredirects"], False),
        False,
    )

    max_depth = max(
        1,
        _to_int(
            _first_non_empty(payload, ["max_depth", "maxdepth"], DEFAULT_MAX_DEPTH),
            DEFAULT_MAX_DEPTH,
        ),
    )

    return {
        "timeout_seconds": timeout_seconds,
        "dry_run": dry_run,
        "allow_redirects": allow_redirects,
        "max_depth": max_depth,
    }


def _extract_http_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    body = _first_non_empty(payload, ["body"], None)
    json_body = _first_non_empty(payload, ["json"], None)

    if json_body is None and isinstance(body, (dict, list)):
        json_body = deepcopy(body)
        body = None

    url = _safe_str(
        _first_non_empty(
            payload,
            ["url", "URL", "http_target", "httptarget", "target_url", "targeturl"],
            "",
        )
    ).strip()

    method = _normalize_method(
        _first_non_empty(payload, ["method", "HTTP_Method", "HTTPMethod", "http_method"], "GET")
    )

    headers = _normalize_headers(
        _first_non_empty(payload, ["headers", "HTTP_Headers_JSON", "http_headers_json"], {})
    )

    params = _safe_dict(_first_non_empty(payload, ["params"], {}))

    return {
        "url": url,
        "method": method,
        "headers": headers,
        "params": params,
        "json": deepcopy(json_body) if isinstance(json_body, (dict, list)) else json_body,
        "body": body,
    }


def _compose_clean_command_input(
    payload: Dict[str, Any],
    *,
    retry_count: Optional[int] = None,
    step_index: Optional[int] = None,
) -> Dict[str, Any]:
    flow_meta = _extract_flow_meta(payload)
    retry_meta = _extract_retry_meta(payload)
    exec_meta = _extract_execution_meta(payload)
    http_payload = _extract_http_payload(payload)

    if retry_count is not None:
        retry_meta["retry_count"] = max(0, retry_count)
    if step_index is not None:
        retry_meta["step_index"] = max(0, step_index)

    clean: Dict[str, Any] = {
        **flow_meta,
        **retry_meta,
        **exec_meta,
        **http_payload,
    }

    return {k: v for k, v in clean.items() if v is not None and v != ""}


def _is_input_polluted(payload: Dict[str, Any]) -> Dict[str, bool]:
    polluted_keys = {
        "event_type",
        "event_name",
        "event_status",
        "payload",
        "event_payload",
        "raw_event",
        "airtable_event",
    }
    return {key: key in payload for key in polluted_keys if key in payload}


def _has_reached_retry_limit(retry_count: int, retry_max: int) -> bool:
    return retry_count >= retry_max


def _has_reached_depth_limit(step_index: int, max_depth: int) -> bool:
    return step_index >= max_depth


def _should_retry(status_code: int, request_error: str) -> bool:
    if request_error:
        return True
    if status_code in (408, 409, 425, 429):
        return True
    if 500 <= status_code <= 599:
        return True
    return False


def _make_retry_command(
    payload: Dict[str, Any],
    *,
    clean_input: Dict[str, Any],
    flow_meta: Dict[str, Any],
    retry_count: int,
    retry_max: int,
    retry_delay_seconds: int,
    step_index: int,
    max_depth: int,
    status_code: int,
    request_error: str,
) -> Dict[str, Any]:
    workspace_id = _safe_str(
        _first_non_empty(payload, ["workspace_id", "workspaceid"], "")
    ).strip()

    error_type = ""
    retry_reason = ""

    if request_error:
        retry_reason = request_error
        error_type = "request_exception"
    elif status_code == 429:
        retry_reason = "http_429"
        error_type = "http_429"
    elif status_code == 408:
        retry_reason = "http_408"
        error_type = "http_408"
    elif status_code == 409:
        retry_reason = "http_409"
        error_type = "http_409"
    elif status_code == 425:
        retry_reason = "http_425"
        error_type = "http_425"
    elif 500 <= status_code <= 599:
        retry_reason = "http_5xx"
        error_type = "http_5xx"
    else:
        retry_reason = f"http_{status_code}" if status_code else "retry_requested"

    return {
        "capability": "retry_router",
        "command_input": {
            "target_capability": "http_exec",
            "original_input": clean_input,
            "flow_id": flow_meta["flow_id"],
            "root_event_id": flow_meta["root_event_id"],
            "workspace_id": workspace_id,
            "parent_command_id": flow_meta["parent_command_id"],
            "retry_count": retry_count,
            "retry_max": retry_max,
            "retry_delay_seconds": max(0, retry_delay_seconds),
            "step_index": step_index,
            "max_depth": max_depth,
            "retry_reason": retry_reason,
            "error_type": error_type,
            "http_status": status_code if status_code else None,
            "request_error": request_error,
        },
    }


def _safe_response_preview(response: Optional[requests.Response]) -> Dict[str, Any]:
    if response is None:
        return {}

    content_type = _safe_str(response.headers.get("Content-Type")).lower()
    text = ""

    try:
        text = response.text or ""
    except Exception:
        text = ""

    preview = text[:1000] if text else ""

    data: Dict[str, Any] = {
        "status_code": response.status_code,
        "content_type": content_type,
        "headers": dict(response.headers),
        "text_preview": preview,
    }

    if "application/json" in content_type:
        try:
            data["json_preview"] = response.json()
        except Exception:
            pass

    return data


def _build_log_summary(
    *,
    payload: Dict[str, Any],
    status_code: int,
    request_error: str,
    retry_scheduled: bool,
    blocked_by_retry_limit: bool,
    blocked_by_depth_limit: bool,
    duration_ms: int,
) -> Dict[str, Any]:
    http_payload = _extract_http_payload(payload)
    retry_meta = _extract_retry_meta(payload)

    parsed = urlparse(http_payload["url"])
    polluted = _is_input_polluted(payload)

    return {
        "ts": _now_ts(),
        "target_host": parsed.netloc,
        "method": http_payload["method"],
        "retry_count": retry_meta["retry_count"],
        "retry_max": retry_meta["retry_max"],
        "step_index": retry_meta["step_index"],
        "max_depth": retry_meta["max_depth"],
        "status_code": status_code,
        "request_error": request_error,
        "retry_scheduled": retry_scheduled,
        "blocked_by_retry_limit": blocked_by_retry_limit,
        "blocked_by_depth_limit": blocked_by_depth_limit,
        "duration_ms": duration_ms,
        "input_pollution_detected": polluted,
    }


def capability_http_exec(payload: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    started_at = time.time()
    payload = _coerce_payload(payload, **kwargs)

    if not HTTP_EXEC_ENABLED:
        return {
            "ok": False,
            "status": "disabled",
            "capability": "http_exec",
            "message": "http_exec disabled",
            "ts": _now_ts(),
            "next_commands": [],
        }

    flow_meta = _extract_flow_meta(payload)
    retry_meta = _extract_retry_meta(payload)
    exec_meta = _extract_execution_meta(payload)
    http_payload = _extract_http_payload(payload)

    retry_count = retry_meta["retry_count"]
    retry_max = retry_meta["retry_max"]
    retry_delay_seconds = retry_meta["retry_delay_seconds"]
    step_index = retry_meta["step_index"]
    max_depth = retry_meta["max_depth"]

    if _has_reached_depth_limit(step_index, max_depth):
        duration_ms = int((time.time() - started_at) * 1000)
        return {
            "ok": False,
            "status": "blocked",
            "capability": "http_exec",
            "message": "max_depth reached",
            "flow_id": flow_meta["flow_id"],
            "root_event_id": flow_meta["root_event_id"],
            "retry_count": retry_count,
            "retry_max": retry_max,
            "step_index": step_index,
            "max_depth": max_depth,
            "duration_ms": duration_ms,
            "ts": _now_ts(),
            "log": _build_log_summary(
                payload=payload,
                status_code=0,
                request_error="",
                retry_scheduled=False,
                blocked_by_retry_limit=False,
                blocked_by_depth_limit=True,
                duration_ms=duration_ms,
            ),
            "next_commands": [],
        }

    if not http_payload["url"]:
        duration_ms = int((time.time() - started_at) * 1000)
        return {
            "ok": False,
            "status": "error",
            "capability": "http_exec",
            "message": "missing url",
            "flow_id": flow_meta["flow_id"],
            "root_event_id": flow_meta["root_event_id"],
            "retry_count": retry_count,
            "retry_max": retry_max,
            "step_index": step_index,
            "max_depth": max_depth,
            "duration_ms": duration_ms,
            "ts": _now_ts(),
            "log": _build_log_summary(
                payload=payload,
                status_code=0,
                request_error="missing url",
                retry_scheduled=False,
                blocked_by_retry_limit=False,
                blocked_by_depth_limit=False,
                duration_ms=duration_ms,
            ),
            "next_commands": [],
        }

    clean_input = _compose_clean_command_input(payload)
    next_commands: List[Dict[str, Any]] = []

    if exec_meta["dry_run"]:
        duration_ms = int((time.time() - started_at) * 1000)
        return {
            "ok": True,
            "status": "dry_run",
            "capability": "http_exec",
            "message": "dry run only",
            "flow_id": flow_meta["flow_id"],
            "root_event_id": flow_meta["root_event_id"],
            "retry_count": retry_count,
            "retry_max": retry_max,
            "step_index": step_index,
            "max_depth": max_depth,
            "duration_ms": duration_ms,
            "ts": _now_ts(),
            "request": {
                "url": http_payload["url"],
                "method": http_payload["method"],
                "headers": http_payload["headers"],
                "params": http_payload["params"],
                "json": http_payload["json"],
                "body": http_payload["body"],
                "timeout_seconds": exec_meta["timeout_seconds"],
                "allow_redirects": exec_meta["allow_redirects"],
            },
            "clean_command_input": clean_input,
            "log": _build_log_summary(
                payload=payload,
                status_code=0,
                request_error="",
                retry_scheduled=False,
                blocked_by_retry_limit=False,
                blocked_by_depth_limit=False,
                duration_ms=duration_ms,
            ),
            "next_commands": [],
        }

    response: Optional[requests.Response] = None
    request_error = ""
    status_code = 0

    try:
        response = REQUEST_SESSION.request(
            method=http_payload["method"],
            url=http_payload["url"],
            headers=http_payload["headers"],
            params=http_payload["params"] or None,
            json=http_payload["json"],
            data=http_payload["body"] if http_payload["json"] is None else None,
            timeout=exec_meta["timeout_seconds"],
            allow_redirects=exec_meta["allow_redirects"],
        )
        status_code = int(response.status_code)
    except requests.RequestException as exc:
        request_error = _safe_str(exc).strip() or exc.__class__.__name__
    except Exception as exc:
        request_error = _safe_str(exc).strip() or exc.__class__.__name__

    blocked_by_retry_limit = False
    blocked_by_depth_limit = False
    retry_scheduled = False

    if _should_retry(status_code, request_error):
        if _has_reached_retry_limit(retry_count, retry_max):
            blocked_by_retry_limit = True
        elif _has_reached_depth_limit(step_index + 1, max_depth):
            blocked_by_depth_limit = True
        else:
            retry_scheduled = True
            next_commands.append(
                _make_retry_command(
                    payload,
                    clean_input=clean_input,
                    flow_meta=flow_meta,
                    retry_count=retry_count,
                    retry_max=retry_max,
                    retry_delay_seconds=retry_delay_seconds,
                    step_index=step_index,
                    max_depth=max_depth,
                    status_code=status_code,
                    request_error=request_error,
                )
            )

    duration_ms = int((time.time() - started_at) * 1000)
    response_preview = _safe_response_preview(response)

    if request_error:
        final_ok = False
        final_status = "blocked" if blocked_by_retry_limit or blocked_by_depth_limit else "error"
        message = request_error
    else:
        final_ok = 200 <= status_code < 300
        if final_ok:
            final_status = "done"
            message = "request completed"
        else:
            final_status = "blocked" if blocked_by_retry_limit or blocked_by_depth_limit else "error"
            message = f"http status {status_code}"

    return {
        "ok": final_ok,
        "status": final_status,
        "capability": "http_exec",
        "message": message,
        "flow_id": flow_meta["flow_id"],
        "root_event_id": flow_meta["root_event_id"],
        "parent_command_id": flow_meta["parent_command_id"],
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_delay_seconds": retry_delay_seconds,
        "step_index": step_index,
        "max_depth": max_depth,
        "duration_ms": duration_ms,
        "ts": _now_ts(),
        "request": {
            "url": http_payload["url"],
            "method": http_payload["method"],
        },
        "response": response_preview,
        "clean_command_input": clean_input,
        "log": _build_log_summary(
            payload=payload,
            status_code=status_code,
            request_error=request_error,
            retry_scheduled=retry_scheduled,
            blocked_by_retry_limit=blocked_by_retry_limit,
            blocked_by_depth_limit=blocked_by_depth_limit,
            duration_ms=duration_ms,
        ),
        "next_commands": next_commands,
    }


def run(payload: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return capability_http_exec(payload=payload, **kwargs)
