from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


DEFAULT_RETRY_MAX = 3
DEFAULT_RETRY_DELAY_SECONDS = 10
DEFAULT_MAX_DEPTH = 8
DEFAULT_PRIORITY = 2


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _to_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _pick(payload: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in payload:
            value = payload.get(key)
            if value is not None and value != "":
                return value
    return default


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


def _normalize_method(value: Any) -> str:
    method = _safe_str(value).strip().upper()
    if not method:
        return "GET"

    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    return method if method in allowed else "GET"


def _extract_flow_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    flow_id = _safe_str(
        _pick(payload, "flow_id", "flowid", default="")
    ).strip()

    root_event_id = _safe_str(
        _pick(payload, "root_event_id", "rooteventid", "event_id", default="")
    ).strip()

    workspace_id = _safe_str(
        _pick(payload, "workspace_id", "workspaceid", default="")
    ).strip()

    parent_command_id = _safe_str(
        _pick(payload, "parent_command_id", "parentcommandid", "command_id", default="")
    ).strip()

    incident_record_id = _safe_str(
        _pick(payload, "incident_record_id", default="")
    ).strip()

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "parent_command_id": parent_command_id,
        "incident_record_id": incident_record_id,
    }


def _extract_retry_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    retry_count = _to_int(_pick(payload, "retry_count", "retrycount", default=0), 0)
    retry_max = _to_int(_pick(payload, "retry_max", "retrymax", default=DEFAULT_RETRY_MAX), DEFAULT_RETRY_MAX)
    retry_delay_seconds = _to_int(
        _pick(payload, "retry_delay_seconds", "retrydelayseconds", "retry_delay", default=DEFAULT_RETRY_DELAY_SECONDS),
        DEFAULT_RETRY_DELAY_SECONDS,
    )
    step_index = _to_int(_pick(payload, "step_index", "stepindex", default=0), 0)
    max_depth = _to_int(_pick(payload, "max_depth", "maxdepth", default=DEFAULT_MAX_DEPTH), DEFAULT_MAX_DEPTH)

    return {
        "retry_count": max(0, retry_count),
        "retry_max": max(0, retry_max),
        "retry_delay_seconds": max(0, retry_delay_seconds),
        "step_index": max(0, step_index),
        "max_depth": max(1, max_depth),
    }


def _extract_target_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    target_capability = _safe_str(
        _pick(
            payload,
            "target_capability",
            "original_capability",
            default="http_exec",
        )
    ).strip() or "http_exec"

    original_input = _to_dict(
        _pick(payload, "original_input", "target_input", default={})
    )

    url_value = _safe_str(
        _pick(
            original_input,
            "url",
            "http_target",
            "URL",
            default=_pick(payload, "url", "http_target", "URL", default=""),
        )
    ).strip()

    method_value = _normalize_method(
        _pick(
            original_input,
            "method",
            "HTTP_Method",
            "HTTPMethod",
            default=_pick(payload, "method", "HTTP_Method", "HTTPMethod", default="GET"),
        )
    )

    return {
        "target_capability": target_capability,
        "original_input": original_input,
        "url": url_value,
        "method": method_value,
    }


def _extract_error_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    retry_reason = _safe_str(
        _pick(payload, "retry_reason", "reason", default="")
    ).strip()

    error_type = _safe_str(
        _pick(payload, "error_type", default=retry_reason)
    ).strip()

    request_error = _safe_str(
        _pick(payload, "request_error", default="")
    ).strip()

    http_status_raw = _pick(payload, "http_status", "status_code", default=None)
    http_status: Optional[int] = None
    if http_status_raw not in (None, ""):
        try:
            http_status = int(http_status_raw)
        except Exception:
            http_status = None

    return {
        "retry_reason": retry_reason,
        "error_type": error_type,
        "request_error": request_error,
        "http_status": http_status,
    }


def _is_retryable(payload: Dict[str, Any], error_meta: Dict[str, Any]) -> bool:
    http_status = error_meta["http_status"]
    request_error = error_meta["request_error"]
    retry_reason = (error_meta["retry_reason"] or "").lower()
    error_type = (error_meta["error_type"] or "").lower()

    if request_error:
        return True

    if http_status is not None:
        if http_status in {408, 409, 425, 429}:
            return True
        if 500 <= http_status <= 599:
            return True
        return False

    retryable_reasons = {
        "timeout",
        "network_error",
        "connection_error",
        "request_exception",
        "http_5xx",
        "http_429",
        "http_408",
        "http_409",
        "http_425",
    }

    return retry_reason in retryable_reasons or error_type in retryable_reasons


def _compute_priority(error_meta: Dict[str, Any]) -> int:
    http_status = error_meta["http_status"]
    reason = (error_meta["retry_reason"] or "").lower()
    error_type = (error_meta["error_type"] or "").lower()

    if http_status == 429 or reason == "http_429" or error_type == "http_429":
        return 3

    if http_status is not None and 500 <= http_status <= 599:
        return 2

    if reason in {"timeout", "network_error", "connection_error", "request_exception"}:
        return 2

    return DEFAULT_PRIORITY


def _compute_effective_delay(retry_delay_seconds: int, retry_count: int) -> int:
    base = max(0, retry_delay_seconds)
    multiplier = max(1, retry_count + 1)
    return base * multiplier


def _compose_retry_input(
    payload: Dict[str, Any],
    *,
    flow_meta: Dict[str, Any],
    retry_meta: Dict[str, Any],
    target_meta: Dict[str, Any],
    error_meta: Dict[str, Any],
) -> Dict[str, Any]:
    original_input = dict(target_meta["original_input"])

    next_retry_count = retry_meta["retry_count"] + 1
    next_step_index = retry_meta["step_index"] + 1
    effective_delay = _compute_effective_delay(
        retry_meta["retry_delay_seconds"],
        retry_meta["retry_count"],
    )

    retry_input: Dict[str, Any] = {
        **original_input,
        "flow_id": flow_meta["flow_id"],
        "root_event_id": flow_meta["root_event_id"],
        "workspace_id": flow_meta["workspace_id"],
        "parent_command_id": flow_meta["parent_command_id"],
        "incident_record_id": flow_meta["incident_record_id"],
        "retry_count": next_retry_count,
        "retry_max": retry_meta["retry_max"],
        "retry_delay_seconds": retry_meta["retry_delay_seconds"],
        "effective_retry_delay_seconds": effective_delay,
        "step_index": next_step_index,
        "max_depth": retry_meta["max_depth"],
    }

    if target_meta["url"]:
        retry_input["url"] = target_meta["url"]
        retry_input["http_target"] = target_meta["url"]

    retry_input["method"] = target_meta["method"]

    if error_meta["retry_reason"]:
        retry_input["retry_reason"] = error_meta["retry_reason"]
    if error_meta["error_type"]:
        retry_input["error_type"] = error_meta["error_type"]
    if error_meta["http_status"] is not None:
        retry_input["http_status"] = error_meta["http_status"]
    if error_meta["request_error"]:
        retry_input["request_error"] = error_meta["request_error"]

    return retry_input


def _build_log(
    *,
    flow_meta: Dict[str, Any],
    retry_meta: Dict[str, Any],
    target_meta: Dict[str, Any],
    error_meta: Dict[str, Any],
    decision: str,
    terminal: bool,
    next_priority: int,
    effective_delay: int,
) -> Dict[str, Any]:
    return {
        "ts": _now_ts(),
        "flow_id": flow_meta["flow_id"],
        "root_event_id": flow_meta["root_event_id"],
        "workspace_id": flow_meta["workspace_id"],
        "target_capability": target_meta["target_capability"],
        "url": target_meta["url"],
        "method": target_meta["method"],
        "retry_count": retry_meta["retry_count"],
        "retry_max": retry_meta["retry_max"],
        "step_index": retry_meta["step_index"],
        "max_depth": retry_meta["max_depth"],
        "retry_reason": error_meta["retry_reason"],
        "error_type": error_meta["error_type"],
        "http_status": error_meta["http_status"],
        "request_error": error_meta["request_error"],
        "decision": decision,
        "terminal": terminal,
        "next_priority": next_priority,
        "effective_retry_delay_seconds": effective_delay,
    }


def run(payload: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    payload = _coerce_payload(payload, **kwargs)

    flow_meta = _extract_flow_meta(payload)
    retry_meta = _extract_retry_meta(payload)
    target_meta = _extract_target_meta(payload)
    error_meta = _extract_error_meta(payload)

    retry_count = retry_meta["retry_count"]
    retry_max = retry_meta["retry_max"]
    step_index = retry_meta["step_index"]
    max_depth = retry_meta["max_depth"]

    is_retryable = _is_retryable(payload, error_meta)
    next_priority = _compute_priority(error_meta)
    effective_delay = _compute_effective_delay(retry_meta["retry_delay_seconds"], retry_count)

    next_commands: List[Dict[str, Any]] = []

    if not is_retryable:
        status = "retry_not_applicable"
        terminal = True
        decision = "not_retryable"

        return {
            "ok": True,
            "status": status,
            "capability": "retry_router",
            "flow_id": flow_meta["flow_id"],
            "root_event_id": flow_meta["root_event_id"],
            "workspace_id": flow_meta["workspace_id"],
            "target_capability": target_meta["target_capability"],
            "retry_count": retry_count,
            "retry_max": retry_max,
            "retry_reason": error_meta["retry_reason"],
            "error_type": error_meta["error_type"],
            "http_status": error_meta["http_status"],
            "request_error": error_meta["request_error"],
            "url": target_meta["url"],
            "method": target_meta["method"],
            "decision": decision,
            "terminal": terminal,
            "next_commands": [],
            "log": _build_log(
                flow_meta=flow_meta,
                retry_meta=retry_meta,
                target_meta=target_meta,
                error_meta=error_meta,
                decision=decision,
                terminal=terminal,
                next_priority=next_priority,
                effective_delay=effective_delay,
            ),
        }

    if retry_count >= retry_max:
        status = "retry_blocked"
        terminal = True
        decision = "retry_limit_reached"

        return {
            "ok": True,
            "status": status,
            "capability": "retry_router",
            "flow_id": flow_meta["flow_id"],
            "root_event_id": flow_meta["root_event_id"],
            "workspace_id": flow_meta["workspace_id"],
            "target_capability": target_meta["target_capability"],
            "retry_count": retry_count,
            "retry_max": retry_max,
            "retry_reason": error_meta["retry_reason"],
            "error_type": error_meta["error_type"],
            "http_status": error_meta["http_status"],
            "request_error": error_meta["request_error"],
            "url": target_meta["url"],
            "method": target_meta["method"],
            "decision": decision,
            "terminal": terminal,
            "next_commands": [],
            "log": _build_log(
                flow_meta=flow_meta,
                retry_meta=retry_meta,
                target_meta=target_meta,
                error_meta=error_meta,
                decision=decision,
                terminal=terminal,
                next_priority=next_priority,
                effective_delay=effective_delay,
            ),
        }

    if step_index + 1 >= max_depth:
        status = "retry_blocked"
        terminal = True
        decision = "max_depth_reached"

        return {
            "ok": True,
            "status": status,
            "capability": "retry_router",
            "flow_id": flow_meta["flow_id"],
            "root_event_id": flow_meta["root_event_id"],
            "workspace_id": flow_meta["workspace_id"],
            "target_capability": target_meta["target_capability"],
            "retry_count": retry_count,
            "retry_max": retry_max,
            "retry_reason": error_meta["retry_reason"],
            "error_type": error_meta["error_type"],
            "http_status": error_meta["http_status"],
            "request_error": error_meta["request_error"],
            "url": target_meta["url"],
            "method": target_meta["method"],
            "decision": decision,
            "terminal": terminal,
            "next_commands": [],
            "log": _build_log(
                flow_meta=flow_meta,
                retry_meta=retry_meta,
                target_meta=target_meta,
                error_meta=error_meta,
                decision=decision,
                terminal=terminal,
                next_priority=next_priority,
                effective_delay=effective_delay,
            ),
        }

    retry_input = _compose_retry_input(
        payload,
        flow_meta=flow_meta,
        retry_meta=retry_meta,
        target_meta=target_meta,
        error_meta=error_meta,
    )

    next_commands.append(
        {
            "capability": target_meta["target_capability"],
            "priority": next_priority,
            "input": retry_input,
        }
    )

    status = "retry_scheduled"
    terminal = False
    decision = "retry"

    return {
        "ok": True,
        "status": status,
        "capability": "retry_router",
        "flow_id": flow_meta["flow_id"],
        "root_event_id": flow_meta["root_event_id"],
        "workspace_id": flow_meta["workspace_id"],
        "target_capability": target_meta["target_capability"],
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_reason": error_meta["retry_reason"],
        "error_type": error_meta["error_type"],
        "http_status": error_meta["http_status"],
        "request_error": error_meta["request_error"],
        "url": target_meta["url"],
        "method": target_meta["method"],
        "decision": decision,
        "effective_retry_delay_seconds": effective_delay,
        "terminal": terminal,
        "next_commands": next_commands,
        "log": _build_log(
            flow_meta=flow_meta,
            retry_meta=retry_meta,
            target_meta=target_meta,
            error_meta=error_meta,
            decision=decision,
            terminal=terminal,
            next_priority=next_priority,
            effective_delay=effective_delay,
        ),
    }
