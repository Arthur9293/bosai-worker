from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


DEFAULT_RETRY_MAX = 3
DEFAULT_RETRY_DELAY_SECONDS = 10
DEFAULT_MAX_DEPTH = 8
DEFAULT_PRIORITY = 2

ORCHESTRATION_CAPABILITIES = {
    "retry_router",
    "incident_router",
    "incident_router_v2",
    "incident_deduplicate",
    "incident_create",
    "internal_escalate",
    "resolve_incident",
    "complete_flow_incident",
    "complete_flow",
    "complete_flow_demo",
    "decision_router",
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


def _unwrap_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    current = dict(payload)

    for nested_key in ("command_input", "commandinput", "input", "body"):
        nested = current.get(nested_key)
        if isinstance(nested, dict):
            merged = dict(nested)
            for k, v in current.items():
                if k != nested_key and k not in merged:
                    merged[k] = v
            current = merged

    return current


def _normalize_method(value: Any) -> str:
    method = _safe_str(value).strip().upper()
    if not method:
        return "GET"

    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    return method if method in allowed else "GET"


def _normalize_capability(value: Any) -> str:
    return _safe_str(value).strip()


def _is_orchestration_capability(value: Any) -> bool:
    cap = _normalize_capability(value)
    return bool(cap) and cap in ORCHESTRATION_CAPABILITIES


def _pick_business_capability(*values: Any, fallback: str = "http_exec") -> str:
    first_non_empty = ""

    for value in values:
        cap = _normalize_capability(value)
        if not cap:
            continue

        if not first_non_empty:
            first_non_empty = cap

        if not _is_orchestration_capability(cap):
            return cap

    if first_non_empty and not _is_orchestration_capability(first_non_empty):
        return first_non_empty

    return fallback


def _extract_flow_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    flow_id = _safe_str(
        _pick(payload, "flow_id", "flowid", default="")
    ).strip()

    root_event_id = _safe_str(
        _pick(payload, "root_event_id", "rooteventid", "event_id", default="")
    ).strip()

    source_event_id = _safe_str(
        _pick(payload, "source_event_id", "sourceeventid", "event_id", "eventid", default="")
    ).strip()

    workspace_id = _safe_str(
        _pick(payload, "workspace_id", "workspaceid", default="")
    ).strip()

    parent_command_id = _safe_str(
        _pick(payload, "parent_command_id", "parentcommandid", default="")
    ).strip()

    command_id = _safe_str(
        _pick(payload, "command_id", "commandid", default="")
    ).strip()

    linked_run = _safe_str(
        _pick(payload, "linked_run", "linkedrun", "run_record_id", "runrecordid", default="")
    ).strip()

    run_record_id = _safe_str(
        _pick(payload, "run_record_id", "runrecordid", "linked_run", "linkedrun", default="")
    ).strip()

    incident_record_id = _safe_str(
        _pick(payload, "incident_record_id", "incidentrecordid", default="")
    ).strip()

    if not source_event_id:
        source_event_id = root_event_id or flow_id

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "workspace_id": workspace_id,
        "parent_command_id": parent_command_id,
        "command_id": command_id,
        "linked_run": linked_run or run_record_id,
        "run_record_id": run_record_id or linked_run,
        "incident_record_id": incident_record_id,
    }


def _extract_retry_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    retry_count = _to_int(_pick(payload, "retry_count", "retrycount", default=0), 0)
    retry_max = _to_int(
        _pick(payload, "retry_max", "retrymax", default=DEFAULT_RETRY_MAX),
        DEFAULT_RETRY_MAX,
    )
    retry_delay_seconds = _to_int(
        _pick(
            payload,
            "retry_delay_seconds",
            "retrydelayseconds",
            "retry_delay",
            default=DEFAULT_RETRY_DELAY_SECONDS,
        ),
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
    original_input = _to_dict(
        _pick(
            payload,
            "original_input",
            "originalinput",
            "target_input",
            "targetinput",
            default={},
        )
    )

    original_input = _unwrap_payload(original_input)

    target_capability = _pick_business_capability(
        _pick(payload, "target_capability", "targetcapability", default=""),
        _pick(payload, "failed_capability", "failedcapability", default=""),
        _pick(payload, "source_capability", "sourcecapability", default=""),
        _pick(payload, "original_capability", "originalcapability", default=""),
        _pick(original_input, "target_capability", "targetcapability", default=""),
        _pick(original_input, "failed_capability", "failedcapability", default=""),
        _pick(original_input, "source_capability", "sourcecapability", default=""),
        _pick(original_input, "original_capability", "originalcapability", default=""),
        fallback="http_exec",
    )

    url_value = _safe_str(
        _pick(
            original_input,
            "url",
            "http_target",
            "failed_url",
            "target_url",
            "URL",
            default=_pick(payload, "url", "http_target", "failed_url", "target_url", "URL", default=""),
        )
    ).strip()

    method_value = _normalize_method(
        _pick(
            original_input,
            "method",
            "failed_method",
            "HTTP_Method",
            "HTTPMethod",
            default=_pick(payload, "method", "failed_method", "HTTP_Method", "HTTPMethod", default="GET"),
        )
    )

    return {
        "target_capability": target_capability,
        "original_input": original_input,
        "url": url_value,
        "method": method_value,
    }


def _extract_error_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    response_obj = _to_dict(_pick(payload, "response", default={}))
    original_input = _to_dict(_pick(payload, "original_input", "originalinput", default={}))

    retry_reason = _safe_str(
        _pick(
            payload,
            "retry_reason",
            "retryreason",
            "reason",
            "incident_code",
            default=_pick(
                original_input,
                "retry_reason",
                "retryreason",
                "reason",
                "incident_code",
                default="",
            ),
        )
    ).strip()

    error_type = _safe_str(
        _pick(
            payload,
            "error_type",
            "errortype",
            "incident_code",
            "error",
            default=_pick(
                original_input,
                "error_type",
                "errortype",
                "incident_code",
                "error",
                default=retry_reason,
            ),
        )
    ).strip()

    request_error = _safe_str(
        _pick(
            payload,
            "request_error",
            "requesterror",
            "error_message",
            "incident_message",
            "last_error",
            default=_pick(
                original_input,
                "request_error",
                "requesterror",
                "error_message",
                "incident_message",
                "last_error",
                default="",
            ),
        )
    ).strip()

    http_status_raw = _pick(
        payload,
        "http_status",
        "httpstatus",
        "status_code",
        "statuscode",
        default=_pick(
            response_obj,
            "status_code",
            default=_pick(
                original_input,
                "http_status",
                "httpstatus",
                "status_code",
                "statuscode",
                default=None,
            ),
        ),
    )

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

    if http_status is not None:
        if http_status in {408, 409, 425, 429}:
            return True
        if 500 <= http_status <= 599:
            return True
        return False

    if request_error:
        return True

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
        "http_status_error",
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

    if reason in {"timeout", "network_error", "connection_error", "request_exception", "http_status_error"}:
        return 2

    return DEFAULT_PRIORITY


def _compute_effective_delay(retry_delay_seconds: int, retry_count: int) -> int:
    base = max(0, retry_delay_seconds)
    multiplier = max(1, retry_count + 1)
    return base * multiplier


def _build_next_retry_at(delay_seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + max(0, delay_seconds)))


def _compose_retry_input(
    payload: Dict[str, Any],
    *,
    flow_meta: Dict[str, Any],
    retry_meta: Dict[str, Any],
    target_meta: Dict[str, Any],
    error_meta: Dict[str, Any],
) -> Dict[str, Any]:
    original_input = dict(target_meta["original_input"])
    request_obj = _to_dict(_pick(payload, "request", default={}))
    response_obj = _to_dict(_pick(payload, "response", default={}))

    next_retry_count = retry_meta["retry_count"] + 1
    next_step_index = retry_meta["step_index"] + 1
    next_depth = _to_int(_pick(payload, "_depth", "depth", default=0), 0) + 1
    effective_delay = _compute_effective_delay(
        retry_meta["retry_delay_seconds"],
        retry_meta["retry_count"],
    )

    retry_input: Dict[str, Any] = {
        **original_input,
        "flow_id": flow_meta["flow_id"],
        "root_event_id": flow_meta["root_event_id"],
        "source_event_id": flow_meta["source_event_id"],
        "event_id": flow_meta["source_event_id"],
        "workspace_id": flow_meta["workspace_id"],
        "workspace": flow_meta["workspace_id"],
        "parent_command_id": flow_meta["command_id"] or flow_meta["parent_command_id"],
        "command_id": flow_meta["command_id"],
        "incident_record_id": flow_meta["incident_record_id"],
        "run_record_id": flow_meta["run_record_id"],
        "linked_run": flow_meta["linked_run"],
        "retry_count": next_retry_count,
        "retry_max": retry_meta["retry_max"],
        "retry_delay_seconds": retry_meta["retry_delay_seconds"],
        "effective_retry_delay_seconds": effective_delay,
        "next_retry_at": _build_next_retry_at(effective_delay),
        "step_index": next_step_index,
        "_depth": next_depth,
        "max_depth": retry_meta["max_depth"],
        "original_capability": target_meta["target_capability"],
        "source_capability": target_meta["target_capability"],
        "failed_capability": target_meta["target_capability"],
        "original_input": original_input or {
            "url": target_meta["url"],
            "method": target_meta["method"],
            "flow_id": flow_meta["flow_id"],
            "root_event_id": flow_meta["root_event_id"],
            "workspace_id": flow_meta["workspace_id"],
        },
    }

    if target_meta["url"]:
        retry_input["url"] = target_meta["url"]
        retry_input["http_target"] = target_meta["url"]
        retry_input["failed_url"] = target_meta["url"]
        retry_input["target_url"] = target_meta["url"]

    retry_input["method"] = target_meta["method"]
    retry_input["failed_method"] = target_meta["method"]

    if error_meta["retry_reason"]:
        retry_input["retry_reason"] = error_meta["retry_reason"]
        retry_input["reason"] = error_meta["retry_reason"]
        retry_input["incident_code"] = error_meta["retry_reason"]

    if error_meta["error_type"]:
        retry_input["error_type"] = error_meta["error_type"]

    if error_meta["http_status"] is not None:
        retry_input["http_status"] = error_meta["http_status"]
        retry_input["status_code"] = error_meta["http_status"]

    if error_meta["request_error"]:
        retry_input["request_error"] = error_meta["request_error"]
        retry_input["error_message"] = error_meta["request_error"]
        retry_input["incident_message"] = error_meta["request_error"]
        retry_input["last_error"] = error_meta["request_error"]

    if request_obj:
        retry_input["request"] = request_obj
    if response_obj:
        retry_input["response"] = response_obj

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
        "source_event_id": flow_meta["source_event_id"],
        "workspace_id": flow_meta["workspace_id"],
        "run_record_id": flow_meta["run_record_id"],
        "linked_run": flow_meta["linked_run"],
        "command_id": flow_meta["command_id"],
        "parent_command_id": flow_meta["parent_command_id"],
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
    payload = _unwrap_payload(payload)

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
            "source_event_id": flow_meta["source_event_id"],
            "workspace_id": flow_meta["workspace_id"],
            "run_record_id": flow_meta["run_record_id"],
            "linked_run": flow_meta["linked_run"],
            "command_id": flow_meta["command_id"],
            "parent_command_id": flow_meta["parent_command_id"],
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
            "source_event_id": flow_meta["source_event_id"],
            "workspace_id": flow_meta["workspace_id"],
            "run_record_id": flow_meta["run_record_id"],
            "linked_run": flow_meta["linked_run"],
            "command_id": flow_meta["command_id"],
            "parent_command_id": flow_meta["parent_command_id"],
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
            "source_event_id": flow_meta["source_event_id"],
            "workspace_id": flow_meta["workspace_id"],
            "run_record_id": flow_meta["run_record_id"],
            "linked_run": flow_meta["linked_run"],
            "command_id": flow_meta["command_id"],
            "parent_command_id": flow_meta["parent_command_id"],
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

    next_commands: List[Dict[str, Any]] = [
        {
            "capability": target_meta["target_capability"],
            "priority": next_priority,
            "input": retry_input,
        }
    ]

    status = "retry_scheduled"
    terminal = False
    decision = "retry"

    return {
        "ok": True,
        "status": status,
        "capability": "retry_router",
        "flow_id": flow_meta["flow_id"],
        "root_event_id": flow_meta["root_event_id"],
        "source_event_id": flow_meta["source_event_id"],
        "workspace_id": flow_meta["workspace_id"],
        "run_record_id": flow_meta["run_record_id"],
        "linked_run": flow_meta["linked_run"],
        "command_id": flow_meta["command_id"],
        "parent_command_id": flow_meta["parent_command_id"],
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
