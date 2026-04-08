from __future__ import annotations

import ast
import json
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


def _coerce_scalar(value: Any) -> Any:
    current = value
    for _ in range(3):
        if isinstance(current, list):
            next_value = None
            for item in current:
                if item not in (None, "", {}, []):
                    next_value = item
                    break
            current = next_value
            continue
        if isinstance(current, tuple):
            current = list(current)
            continue
        break
    return current


def _json_like_to_dict(value: Any) -> Dict[str, Any]:
    value = _coerce_scalar(value)

    if isinstance(value, dict):
        return dict(value)

    if value is None:
        return {}

    text = _safe_str(value).strip()
    if not text:
        return {}

    candidates = [text]
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        inner = text[1:-1].strip()
        if inner:
            candidates.append(inner)

    def _unwrap(parsed: Any) -> Dict[str, Any]:
        current = _coerce_scalar(parsed)

        for _ in range(3):
            if isinstance(current, dict):
                return dict(current)

            if isinstance(current, str):
                inner_text = current.strip()
                if not inner_text:
                    return {}

                try:
                    current = json.loads(inner_text)
                    current = _coerce_scalar(current)
                    continue
                except Exception:
                    pass

                try:
                    current = ast.literal_eval(inner_text)
                    current = _coerce_scalar(current)
                    continue
                except Exception:
                    return {}

            return {}

        return dict(current) if isinstance(current, dict) else {}

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            out = _unwrap(parsed)
            if out:
                return out
        except Exception:
            pass

        try:
            parsed = ast.literal_eval(candidate)
            out = _unwrap(parsed)
            if out:
                return out
        except Exception:
            pass

        try:
            fixed = bytes(candidate, "utf-8").decode("unicode_escape")
            parsed = json.loads(fixed)
            out = _unwrap(parsed)
            if out:
                return out
        except Exception:
            pass

    return {}


def _to_dict(value: Any) -> Dict[str, Any]:
    return _json_like_to_dict(value)


def _pick(payload: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    if not isinstance(payload, dict):
        return default

    for key in keys:
        if key in payload:
            value = _coerce_scalar(payload.get(key))
            if value is not None and value != "":
                return value
    return default


def _pick_multi(dicts: List[Dict[str, Any]], *keys: str, default: Any = None) -> Any:
    for data in dicts:
        if not isinstance(data, dict):
            continue
        value = _pick(data, *keys, default=None)
        if value not in (None, ""):
            return value
    return default


def _coerce_payload(payload: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return dict(payload)

    candidate = kwargs.get("input_data")
    if isinstance(candidate, dict):
        return dict(candidate)

    candidate = kwargs.get("payload")
    if isinstance(candidate, dict):
        return dict(candidate)

    return {}


def _unwrap_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    # SAFE:
    # on unwrap uniquement les enveloppes d’orchestration.
    # on ne touche PAS à "body", sinon on peut écraser le contexte erreur
    # top-level provenant de http_exec.
    for key in ("command_input", "commandinput", "input"):
        nested = payload.get(key)
        nested_dict = _to_dict(nested)
        if isinstance(nested_dict, dict) and nested_dict:
            merged = dict(nested_dict)
            for k, v in payload.items():
                if k != key and k not in merged:
                    merged[k] = v
            return merged

    return dict(payload)


def _merge_preserving_top_level(raw_payload: Dict[str, Any], unwrapped_payload: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(raw_payload or {})

    for k, v in (unwrapped_payload or {}).items():
        if k not in merged or merged.get(k) in (None, "", {}, []):
            merged[k] = v

    return merged


def _extract_nested_sources(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
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
    original_input = _unwrap_payload(original_input) if isinstance(original_input, dict) else {}

    body = _to_dict(_pick(payload, "body", default={}))
    request = _to_dict(_pick(payload, "request", default={}))
    response = _to_dict(_pick(payload, "response", default={}))

    return {
        "original_input": original_input if isinstance(original_input, dict) else {},
        "body": body if isinstance(body, dict) else {},
        "request": request if isinstance(request, dict) else {},
        "response": response if isinstance(response, dict) else {},
    }


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
    nested = _extract_nested_sources(payload)
    search = [payload, nested["original_input"], nested["body"]]

    flow_id = _safe_str(
        _pick_multi(search, "flow_id", "flowid", default="")
    ).strip()

    root_event_id = _safe_str(
        _pick_multi(search, "root_event_id", "rooteventid", "event_id", "eventid", default="")
    ).strip()

    source_event_id = _safe_str(
        _pick_multi(search, "source_event_id", "sourceeventid", "event_id", "eventid", default="")
    ).strip()

    workspace_id = _safe_str(
        _pick_multi(search, "workspace_id", "workspaceid", default="")
    ).strip()

    parent_command_id = _safe_str(
        _pick_multi(search, "parent_command_id", "parentcommandid", default="")
    ).strip()

    command_id = _safe_str(
        _pick_multi(search, "command_id", "commandid", default="")
    ).strip()

    linked_run = _safe_str(
        _pick_multi(search, "linked_run", "linkedrun", "run_record_id", "runrecordid", default="")
    ).strip()

    run_record_id = _safe_str(
        _pick_multi(search, "run_record_id", "runrecordid", "linked_run", "linkedrun", default="")
    ).strip()

    incident_record_id = _safe_str(
        _pick_multi(search, "incident_record_id", "incidentrecordid", default="")
    ).strip()

    if not root_event_id:
        root_event_id = flow_id

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
    nested = _extract_nested_sources(payload)
    search = [payload, nested["original_input"], nested["body"]]

    retry_count = _to_int(
        _pick_multi(search, "retry_count", "retrycount", default=0),
        0,
    )
    retry_max = _to_int(
        _pick_multi(search, "retry_max", "retrymax", default=DEFAULT_RETRY_MAX),
        DEFAULT_RETRY_MAX,
    )
    retry_delay_seconds = _to_int(
        _pick_multi(
            search,
            "retry_delay_seconds",
            "retrydelayseconds",
            "retry_delay",
            "effective_retry_delay_seconds",
            default=DEFAULT_RETRY_DELAY_SECONDS,
        ),
        DEFAULT_RETRY_DELAY_SECONDS,
    )
    step_index = _to_int(
        _pick_multi(search, "step_index", "stepindex", default=0),
        0,
    )
    max_depth = _to_int(
        _pick_multi(search, "max_depth", "maxdepth", default=DEFAULT_MAX_DEPTH),
        DEFAULT_MAX_DEPTH,
    )

    return {
        "retry_count": max(0, retry_count),
        "retry_max": max(0, retry_max),
        "retry_delay_seconds": max(0, retry_delay_seconds),
        "step_index": max(0, step_index),
        "max_depth": max(1, max_depth),
    }


def _extract_target_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    nested = _extract_nested_sources(payload)
    original_input = nested["original_input"]
    body = nested["body"]
    request = nested["request"]

    search = [payload, original_input, body]

    target_capability = _pick_business_capability(
        _pick_multi(search, "target_capability", "targetcapability", default=""),
        _pick_multi(search, "failed_capability", "failedcapability", default=""),
        _pick_multi(search, "source_capability", "sourcecapability", default=""),
        _pick_multi(search, "original_capability", "originalcapability", default=""),
        fallback="http_exec",
    )

    url_value = _safe_str(
        _pick_multi(
            [payload, original_input, body, request],
            "url",
            "http_target",
            "failed_url",
            "target_url",
            "URL",
            default="",
        )
    ).strip()

    method_value = _normalize_method(
        _pick_multi(
            [payload, original_input, body, request],
            "method",
            "failed_method",
            "HTTP_Method",
            "HTTPMethod",
            default="GET",
        )
    )

    original_input_seed = dict(original_input or {})

    if url_value and _pick(original_input_seed, "url", "http_target", "target_url", default="") in (None, ""):
        original_input_seed["url"] = url_value
        original_input_seed["http_target"] = url_value

    if _pick(original_input_seed, "method", default="") in (None, ""):
        original_input_seed["method"] = method_value

    goal_value = _pick_multi([payload, original_input, body], "goal", "failed_goal", default="")
    if goal_value and _pick(original_input_seed, "goal", default="") in (None, ""):
        original_input_seed["goal"] = goal_value

    return {
        "target_capability": target_capability,
        "original_input": original_input_seed,
        "url": url_value,
        "method": method_value,
    }


def _extract_error_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    nested = _extract_nested_sources(payload)
    original_input = nested["original_input"]
    body = nested["body"]
    response_obj = nested["response"]

    search = [payload, original_input, body]

    retry_reason = _safe_str(
        _pick_multi(
            search,
            "retry_reason",
            "retryreason",
            "reason",
            "origin_reason",
            "incident_code",
            default="",
        )
    ).strip()

    error_type = _safe_str(
        _pick_multi(
            search,
            "error_type",
            "errortype",
            "error",
            default=retry_reason,
        )
    ).strip()

    request_error = _safe_str(
        _pick_multi(
            search,
            "request_error",
            "requesterror",
            "error_message",
            "last_error",
            "incident_message",
            default="",
        )
    ).strip()

    http_status_raw = _pick_multi(
        search,
        "http_status",
        "httpstatus",
        "status_code",
        "statuscode",
        default=_pick(response_obj, "status_code", default=None),
    )

    http_status: Optional[int] = None
    if http_status_raw not in (None, ""):
        try:
            http_status = int(http_status_raw)
        except Exception:
            http_status = None

    if not retry_reason and http_status is not None and 500 <= http_status <= 599:
        retry_reason = "http_status_error"

    if not error_type and retry_reason:
        error_type = retry_reason

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
        "http_status_error",
        "http_failure",
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

    if reason in {
        "timeout",
        "network_error",
        "connection_error",
        "request_exception",
        "http_status_error",
        "http_failure",
    }:
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
    original_input = dict(target_meta["original_input"] or {})

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
        "target_capability": target_meta["target_capability"],
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

    if error_meta["error_type"]:
        retry_input["error_type"] = error_meta["error_type"]

    if error_meta["http_status"] is not None:
        retry_input["http_status"] = error_meta["http_status"]
        retry_input["status_code"] = error_meta["http_status"]

    if error_meta["request_error"]:
        retry_input["request_error"] = error_meta["request_error"]
        retry_input["error_message"] = error_meta["request_error"]
        retry_input["last_error"] = error_meta["request_error"]

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
    raw_payload = _coerce_payload(payload, **kwargs)
    unwrapped_payload = _unwrap_payload(raw_payload)
    payload = _merge_preserving_top_level(raw_payload, unwrapped_payload)

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
