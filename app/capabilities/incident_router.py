# app/capabilities/incident_router.py
from __future__ import annotations

from typing import Any, Dict


def run(input_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload = input_data or {}

    error = str(payload.get("error") or "").strip()
    http_status = payload.get("http_status")
    retry_count = int(payload.get("retry_count") or 0)
    retry_max = int(payload.get("retry_max") or 0)

    decision = "log_only"
    reason = "default"

    if retry_max > 0 and retry_count >= retry_max:
        decision = "escalate"
        reason = "retry_exhausted"
    elif isinstance(http_status, int):
        if 500 <= http_status <= 599:
            decision = "retry"
            reason = "http_5xx"
        elif 400 <= http_status <= 499:
            decision = "escalate"
            reason = "http_4xx"
    elif "timeout" in error.lower():
        decision = "retry"
        reason = "timeout"
    elif error:
        decision = "log_only"
        reason = "unknown_error"

    next_commands = []

    if decision == "retry":
        next_commands.append(
            {
                "capability": payload.get("original_capability") or "http_exec",
                "input": payload.get("original_input") or {},
                "priority": 2,
            }
        )

    if decision == "escalate":
        next_commands.append(
            {
                "capability": "internal_escalate",
                "input": {
                    "flow_id": payload.get("flow_id"),
                    "root_event_id": payload.get("root_event_id"),
                    "reason": reason,
                    "error": error,
                    "http_status": http_status,
                    "source_capability": payload.get("original_capability"),
                    "workspace_id": payload.get("workspace_id"),
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
        "next_commands": next_commands,
        "terminal": decision in ("escalate", "log_only"),
    }
