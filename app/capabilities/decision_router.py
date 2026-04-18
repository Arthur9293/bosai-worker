from __future__ import annotations

from typing import Any, Dict, List, Optional


def _to_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value).strip()
    except Exception:
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _safe_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _pick_text(*values: Any) -> str:
    for value in values:
        if isinstance(value, list):
            for item in value:
                text = _to_str(item)
                if text:
                    return text
            continue

        text = _to_str(value)
        if text:
            return text
    return ""


def _normalize_step_index(value: Any) -> int:
    return _to_int(value, 0)


def _is_retryable_http_status(status_code: int) -> bool:
    return status_code in {408, 409, 425, 429, 500, 502, 503, 504}


def _looks_like_retryable_reason(*values: Any) -> bool:
    haystack = " ".join(_to_str(v).lower() for v in values if _to_str(v))
    if not haystack:
        return False

    retry_markers = [
        "retry",
        "timeout",
        "timed out",
        "connection reset",
        "connection aborted",
        "connection refused",
        "temporary failure",
        "temporarily unavailable",
        "dns",
        "network",
        "unreachable",
        "http_status_error",
        "status 408",
        "status 409",
        "status 425",
        "status 429",
        "status 500",
        "status 502",
        "status 503",
        "status 504",
    ]
    return any(marker in haystack for marker in retry_markers)


def _base_context(input_obj: Dict[str, Any], run_record_id: str) -> Dict[str, Any]:
    raw_flow_id = _pick_text(
        input_obj.get("flow_id"),
        input_obj.get("flowid"),
        input_obj.get("flowId"),
    )

    raw_root_event_id = _pick_text(
        input_obj.get("root_event_id"),
        input_obj.get("rooteventid"),
        input_obj.get("rootEventId"),
        input_obj.get("event_id"),
        input_obj.get("eventId"),
        raw_flow_id,
    )

    raw_source_event_id = _pick_text(
        input_obj.get("source_event_id"),
        input_obj.get("sourceeventid"),
        input_obj.get("sourceEventId"),
        input_obj.get("event_id"),
        input_obj.get("eventId"),
        raw_root_event_id,
        raw_flow_id,
    )

    flow_id = raw_flow_id or raw_root_event_id or raw_source_event_id or f"flow_run_{run_record_id}"
    root_event_id = raw_root_event_id or flow_id
    source_event_id = raw_source_event_id or root_event_id or flow_id

    workspace_id = _pick_text(
        input_obj.get("workspace_id"),
        input_obj.get("workspaceId"),
        input_obj.get("Workspace_ID"),
        input_obj.get("workspace"),
    )

    step_index = _normalize_step_index(input_obj.get("step_index"))

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "workspace_id": workspace_id,
        "step_index": step_index,
        "run_record_id": run_record_id,
        "linked_run": run_record_id,
    }


def _build_child_input(
    parent_ctx: Dict[str, Any],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    out = {
        "workspace_id": parent_ctx.get("workspace_id", ""),
        "workspace": parent_ctx.get("workspace_id", ""),
        "flow_id": parent_ctx.get("flow_id", ""),
        "root_event_id": parent_ctx.get("root_event_id", ""),
        "source_event_id": parent_ctx.get("source_event_id", ""),
        "event_id": (
            parent_ctx.get("source_event_id")
            or parent_ctx.get("root_event_id")
            or parent_ctx.get("flow_id")
            or ""
        ),
        "step_index": _to_int(parent_ctx.get("step_index"), 0) + 1,
        "run_record_id": parent_ctx.get("run_record_id", ""),
        "linked_run": parent_ctx.get("linked_run", ""),
    }

    if isinstance(extra, dict):
        out.update(extra)

    return out


def _route_from_input(input_obj: Dict[str, Any]) -> Dict[str, Any]:
    goal = _pick_text(input_obj.get("goal")).lower()

    route_to = _pick_text(
        input_obj.get("route_to"),
        input_obj.get("target_capability"),
        input_obj.get("capability_hint"),
    )

    url = _pick_text(
        input_obj.get("url"),
        input_obj.get("http_target"),
        input_obj.get("endpoint"),
    )

    incident_id = _pick_text(
        input_obj.get("incident_id"),
        input_obj.get("Incident_ID"),
    )

    command_id = _pick_text(
        input_obj.get("command_id"),
        input_obj.get("Command_ID"),
        input_obj.get("parent_command_id"),
        input_obj.get("Parent_Command_ID"),
    )

    retry_count = _to_int(input_obj.get("retry_count"), 0)
    retry_max = _to_int(input_obj.get("retry_max"), 3)
    if retry_max <= 0:
        retry_max = 3

    status_code = _to_int(
        _pick_text(
            input_obj.get("status_code"),
            input_obj.get("http_status"),
            input_obj.get("status"),
        ),
        0,
    )

    retry_reason = _pick_text(
        input_obj.get("retry_reason"),
        input_obj.get("reason"),
        input_obj.get("error_type"),
        input_obj.get("error_message"),
        input_obj.get("request_error"),
        input_obj.get("last_error"),
    )

    if route_to:
        return {
            "decision": route_to,
            "reason": "explicit_route_requested",
            "target_capability": route_to,
        }

    if (
        retry_count < retry_max
        and (
            _is_retryable_http_status(status_code)
            or _looks_like_retryable_reason(
                retry_reason,
                goal,
                input_obj.get("error_type"),
                input_obj.get("error_message"),
                input_obj.get("request_error"),
                input_obj.get("last_error"),
            )
        )
    ):
        return {
            "decision": "retry",
            "reason": retry_reason or f"http_status_{status_code}" or "retryable_failure_detected",
            "target_capability": "retry_router",
        }

    if incident_id and "resolve" in goal:
        return {
            "decision": "resolve_incident",
            "reason": "incident_resolution_requested",
            "target_capability": "resolve_incident",
        }

    if incident_id or command_id or "incident" in goal:
        return {
            "decision": "route_incident",
            "reason": "incident_context_detected",
            "target_capability": "incident_router_v2",
        }

    if "health" in goal or "check" in goal or "diagnostic" in goal:
        return {
            "decision": "health_check",
            "reason": "health_goal_detected",
            "target_capability": "health_tick",
        }

    if url:
        return {
            "decision": "send_http_ping",
            "reason": "http_target_detected",
            "target_capability": "http_exec",
        }

    return {
        "decision": "no_route",
        "reason": "no_matching_rule",
        "target_capability": "",
    }


def decision_router(req: Any, run_record_id: str) -> Dict[str, Any]:
    input_obj = _safe_dict(getattr(req, "input", {}) or {})
    parent_ctx = _base_context(input_obj, run_record_id)

    route = _route_from_input(input_obj)
    target_capability = _to_str(route.get("target_capability"))

    next_commands: List[Dict[str, Any]] = []

    if target_capability == "retry_router":
        failed_url = _pick_text(
            input_obj.get("failed_url"),
            input_obj.get("url"),
            input_obj.get("http_target"),
            input_obj.get("endpoint"),
        )

        failed_method = _pick_text(
            input_obj.get("failed_method"),
            input_obj.get("method"),
            "GET",
        ) or "GET"

        retry_count = _to_int(input_obj.get("retry_count"), 0)
        retry_max = _to_int(input_obj.get("retry_max"), 3)
        if retry_max <= 0:
            retry_max = 3

        retry_delay_seconds = _to_int(
            input_obj.get("retry_delay_seconds")
            or input_obj.get("effective_retry_delay_seconds")
            or input_obj.get("next_retry_delay_seconds")
            or 10,
            10,
        )
        if retry_delay_seconds <= 0:
            retry_delay_seconds = 10

        status_code = _to_int(
            _pick_text(
                input_obj.get("status_code"),
                input_obj.get("http_status"),
                input_obj.get("status"),
            ),
            0,
        )

        reason = _pick_text(
            input_obj.get("retry_reason"),
            input_obj.get("reason"),
            input_obj.get("error_type"),
            input_obj.get("error_message"),
            input_obj.get("request_error"),
            input_obj.get("last_error"),
            f"http_status_{status_code}" if status_code else "",
        )

        child_input = _build_child_input(
            parent_ctx,
            {
                "failed_url": failed_url,
                "failed_uri": failed_url,
                "failed_method": failed_method,
                "url": failed_url,
                "http_target": failed_url,
                "method": failed_method,
                "retry_count": retry_count,
                "retry_max": retry_max,
                "retry_delay_seconds": retry_delay_seconds,
                "effective_retry_delay_seconds": retry_delay_seconds,
                "reason": reason,
                "retry_reason": reason,
                "error_type": _pick_text(input_obj.get("error_type"), reason),
                "error_message": _pick_text(
                    input_obj.get("error_message"),
                    input_obj.get("request_error"),
                    input_obj.get("last_error"),
                    reason,
                ),
                "request_error": _pick_text(
                    input_obj.get("request_error"),
                    input_obj.get("error_message"),
                    input_obj.get("last_error"),
                ),
                "last_error": _pick_text(
                    input_obj.get("last_error"),
                    input_obj.get("error_message"),
                    input_obj.get("request_error"),
                ),
                "http_status": status_code,
                "status_code": status_code,
                "source_capability": _pick_text(
                    input_obj.get("source_capability"),
                    input_obj.get("failed_capability"),
                    input_obj.get("original_capability"),
                    "http_exec",
                ),
                "failed_capability": _pick_text(
                    input_obj.get("failed_capability"),
                    input_obj.get("source_capability"),
                    input_obj.get("original_capability"),
                    "http_exec",
                ),
                "target_capability": "http_exec",
                "original_capability": _pick_text(
                    input_obj.get("original_capability"),
                    input_obj.get("source_capability"),
                    "http_exec",
                ),
                "command_id": _pick_text(
                    input_obj.get("command_id"),
                    input_obj.get("Command_ID"),
                ),
                "parent_command_id": _pick_text(
                    input_obj.get("parent_command_id"),
                    input_obj.get("Parent_Command_ID"),
                    input_obj.get("command_id"),
                    input_obj.get("Command_ID"),
                ),
            },
        )

        next_commands.append(
            {
                "capability": "retry_router",
                "input": child_input,
            }
        )

    elif target_capability == "http_exec":
        resolved_url = _pick_text(
            input_obj.get("url"),
            input_obj.get("http_target"),
            input_obj.get("endpoint"),
            "https://httpbin.org/get",
        )

        child_input = _build_child_input(
            parent_ctx,
            {
                "url": resolved_url,
                "http_target": resolved_url,
                "method": _pick_text(input_obj.get("method"), "GET") or "GET",
            },
        )

        next_commands.append(
            {
                "capability": "http_exec",
                "input": child_input,
            }
        )

    elif target_capability == "incident_router_v2":
        child_input = _build_child_input(
            parent_ctx,
            {
                "incident_id": _pick_text(
                    input_obj.get("incident_id"),
                    input_obj.get("Incident_ID"),
                ),
                "command_id": _pick_text(
                    input_obj.get("command_id"),
                    input_obj.get("Command_ID"),
                ),
                "reason": _pick_text(input_obj.get("reason"), input_obj.get("goal")),
                "context": _safe_dict(input_obj.get("context")),
            },
        )

        next_commands.append(
            {
                "capability": "incident_router_v2",
                "input": child_input,
            }
        )

    elif target_capability == "resolve_incident":
        child_input = _build_child_input(
            parent_ctx,
            {
                "incident_id": _pick_text(
                    input_obj.get("incident_id"),
                    input_obj.get("Incident_ID"),
                ),
                "resolution_note": _pick_text(
                    input_obj.get("resolution_note"),
                    input_obj.get("goal"),
                    "Resolved via decision_router",
                ),
            },
        )

        next_commands.append(
            {
                "capability": "resolve_incident",
                "input": child_input,
            }
        )

    elif target_capability == "health_tick":
        child_input = _build_child_input(parent_ctx, {})

        next_commands.append(
            {
                "capability": "health_tick",
                "input": child_input,
            }
        )

    return {
        "ok": True,
        "status": "done",
        "decision": _to_str(route.get("decision")),
        "reason": _to_str(route.get("reason")),
        "target_capability": target_capability,
        "next_commands": next_commands,
        "terminal": len(next_commands) == 0,
        "final_failure": False,
        "retriable": target_capability == "retry_router",
        "retry_count": _to_int(input_obj.get("retry_count"), 0),
        "retry_max": _to_int(input_obj.get("retry_max"), 3),
        "http_status": _to_int(
            _pick_text(
                input_obj.get("http_status"),
                input_obj.get("status_code"),
                input_obj.get("status"),
            ),
            0,
        ),
        "status_code": _to_int(
            _pick_text(
                input_obj.get("status_code"),
                input_obj.get("http_status"),
                input_obj.get("status"),
            ),
            0,
        ),
        "flow_id": parent_ctx.get("flow_id"),
        "root_event_id": parent_ctx.get("root_event_id"),
        "source_event_id": parent_ctx.get("source_event_id"),
        "workspace_id": parent_ctx.get("workspace_id"),
        "step_index": parent_ctx.get("step_index", 0),
        "run_record_id": run_record_id,
        "linked_run": run_record_id,
    }


def run(req: Any, run_record_id: str) -> Dict[str, Any]:
    return decision_router(req, run_record_id)
