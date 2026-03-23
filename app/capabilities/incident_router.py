# app/capabilities/incident_router.py
from __future__ import annotations

from typing import Any, Dict, Optional


def _to_payload(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    input_attr = getattr(value, "input", None)
    if isinstance(input_attr, dict):
        return input_attr

    return {}


def _to_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _pick(payload: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return default


def capability_incident_router(payload: Dict[str, Any], run_record_id: str = "") -> Dict[str, Any]:
    goal = str(
        _pick(payload, "goal", "Goal", default="")
        or ""
    ).strip()

    error = str(
        _pick(payload, "error", "last_error", "Error", default="")
        or ""
    ).strip()

    reason = str(
        _pick(payload, "reason", "retry_reason", "Reason", default="unknown")
        or "unknown"
    ).strip()

    http_status = _to_int(_pick(payload, "http_status", "status_code", "HTTP_Status"))
    if http_status is None:
        response_obj = payload.get("response")
        if isinstance(response_obj, dict):
            http_status = _to_int(response_obj.get("status_code"))

    retry_count = _to_int(_pick(payload, "retry_count", "Retry_Count")) or 0
    retry_max = _to_int(_pick(payload, "retry_max", "Retry_Max")) or 0

    flow_id = str(
        _pick(payload, "flow_id", "flowid", "Flow_ID", default="")
        or ""
    ).strip()

    root_event_id = str(
        _pick(payload, "root_event_id", "rooteventid", "Root_Event_ID", default="")
        or ""
    ).strip()

    workspace_id = str(
        _pick(payload, "workspace_id", "Workspace_ID", default="")
        or ""
    ).strip()

    original_capability = str(
        _pick(payload, "original_capability", "source_capability", default="http_exec")
        or "http_exec"
    ).strip() or "http_exec"

    original_input = (
        payload.get("original_input")
        if isinstance(payload.get("original_input"), dict)
        else {}
    )

    failed_url = str(
        _pick(
            payload,
            "failed_url",
            "url",
            "http_target",
            "URL",
            default="",
        ) or ""
    ).strip()

    failed_method = str(
        _pick(payload, "failed_method", "method", default="GET")
        or "GET"
    ).strip().upper()

    decision = "log_only"
    final_reason = reason or "default"

    if retry_max > 0 and retry_count >= retry_max:
        decision = "escalate"
        final_reason = reason or "retry_exhausted"

    elif http_status is not None:
        if 500 <= http_status <= 599:
            if retry_max > 0 and retry_count < retry_max:
                decision = "retry"
                final_reason = reason or "http_5xx"
            else:
                decision = "escalate"
                final_reason = reason or "http_5xx_exhausted"

        elif 400 <= http_status <= 499:
            decision = "escalate"
            final_reason = reason or "http_4xx"

    elif "timeout" in error.lower():
        if retry_max > 0 and retry_count < retry_max:
            decision = "retry"
            final_reason = reason or "timeout"
        else:
            decision = "escalate"
            final_reason = reason or "timeout_exhausted"

    elif error:
        decision = "log_only"
        final_reason = reason or "unknown_error"

    next_commands = []

    if decision == "retry":
        retry_input = dict(original_input) if isinstance(original_input, dict) else {}

        if not retry_input.get("url"):
            retry_input["url"] = failed_url

        if not retry_input.get("http_target"):
            retry_input["http_target"] = failed_url

        if not retry_input.get("method"):
            retry_input["method"] = failed_method

        retry_input.setdefault("flow_id", flow_id)
        retry_input.setdefault("root_event_id", root_event_id)
        retry_input.setdefault("workspace_id", workspace_id)

        retry_input["retry_count"] = retry_count + 1
        retry_input["retry_max"] = retry_max

        next_commands.append(
            {
                "capability": original_capability,
                "input": retry_input,
                "priority": 2,
            }
        )

    elif decision == "escalate":
        next_commands.append(
            {
                "capability": "internal_escalate",
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "goal": goal,
                    "reason": final_reason,
                    "error": error,
                    "http_status": http_status,
                    "status_code": http_status,
                    "source_capability": original_capability,
                    "original_capability": original_capability,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "workspace_id": workspace_id,
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "run_record_id": run_record_id,
                },
                "priority": 1,
            }
        )

    return {
        "ok": True,
        "capability": "incident_router",
        "status": "incident_escalated" if decision == "escalate" else "incident_logged",
        "decision": decision,
        "goal": goal,
        "reason": final_reason,
        "error": error,
        "http_status": http_status,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "run_record_id": run_record_id,
        "original_capability": original_capability,
        "failed_url": failed_url,
        "failed_method": failed_method,
        "next_commands": next_commands,
        "terminal": False,
    }


def run(req: Any = None, run_record_id: str = "") -> Dict[str, Any]:
    payload = _to_payload(req)
    return capability_incident_router(payload, run_record_id)
