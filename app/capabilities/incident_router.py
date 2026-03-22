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


def capability_incident_router(payload: Dict[str, Any], run_record_id: str = "") -> Dict[str, Any]:
    error = str(payload.get("error") or "").strip()
    http_status = _to_int(payload.get("http_status"))
    if http_status is None:
        http_status = _to_int(payload.get("status_code"))
    if http_status is None:
        http_status = _to_int(payload.get("HTTP_Status"))

    retry_count = _to_int(payload.get("retry_count")) or 0
    retry_max = _to_int(payload.get("retry_max")) or 0

    flow_id = str(payload.get("flow_id") or "").strip()
    root_event_id = str(payload.get("root_event_id") or "").strip()
    workspace_id = str(payload.get("workspace_id") or "").strip()
    original_capability = str(payload.get("original_capability") or "http_exec").strip() or "http_exec"
    original_input = payload.get("original_input") if isinstance(payload.get("original_input"), dict) else {}

    decision = "log_only"
    reason = "default"

    if retry_max > 0 and retry_count >= retry_max:
        decision = "escalate"
        reason = "retry_exhausted"
    elif isinstance(http_status, int):
        if 500 <= http_status <= 599:
            if retry_max > 0 and retry_count < retry_max:
                decision = "retry"
                reason = "http_5xx"
            else:
                decision = "escalate"
                reason = "http_5xx_exhausted"
        elif 400 <= http_status <= 499:
            decision = "escalate"
            reason = "http_4xx"
    elif "timeout" in error.lower():
        if retry_max > 0 and retry_count < retry_max:
            decision = "retry"
            reason = "timeout"
        else:
            decision = "escalate"
            reason = "timeout_exhausted"
    elif error:
        decision = "log_only"
        reason = "unknown_error"

    next_commands = []

    if decision == "retry":
        retry_input = dict(original_input) if isinstance(original_input, dict) else {}
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
                    "reason": reason,
                    "error": error,
                    "http_status": http_status,
                    "source_capability": original_capability,
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
        "decision": decision,
        "reason": reason,
        "http_status": http_status,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "run_record_id": run_record_id,
        "next_commands": next_commands,
        "terminal": False,
    }


def run(req: Any = None, run_record_id: str = "") -> Dict[str, Any]:
    payload = _to_payload(req)
    return capability_incident_router(payload, run_record_id)
