from __future__ import annotations

from typing import Any, Dict, List


def run(input_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload = input_data or {}

    flow_id = payload.get("flow_id")
    root_event_id = payload.get("root_event_id")
    workspace_id = payload.get("workspace_id")

    original_capability = payload.get("original_capability") or "http_exec"
    original_input = payload.get("original_input") or {}

    retry_reason = str(payload.get("retry_reason") or payload.get("reason") or "").strip()
    retry_count = int(payload.get("retry_count") or 0)
    retry_max = int(payload.get("retry_max") or 3)
    http_status = payload.get("http_status")
    incident_record_id = payload.get("incident_record_id")

    if not isinstance(original_input, dict):
        original_input = {}

    next_commands: List[Dict[str, Any]] = []
    action = "noop"
    terminal = False

    if retry_count < retry_max:
        action = "retry"

        retry_input = {
            **original_input,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "workspace_id": workspace_id,
            "retry_count": retry_count + 1,
            "retry_max": retry_max,
            "retry_reason": retry_reason,
            "incident_record_id": incident_record_id,
        }

        next_commands.append(
            {
                "capability": original_capability,
                "priority": 2,
                "input": retry_input,
            }
        )

    else:
        action = "escalate"
        terminal = True

        next_commands.append(
            {
                "capability": "internal_escalate",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "workspace_id": workspace_id,
                    "incident_record_id": incident_record_id,
                    "original_capability": original_capability,
                    "original_input": original_input,
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "retry_reason": retry_reason,
                    "http_status": http_status,
                    "goal": "incident_escalation",
                },
            }
        )

    return {
        "ok": True,
        "capability": "retry_router",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "action": action,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_reason": retry_reason,
        "http_status": http_status,
        "next_commands": next_commands,
        "terminal": terminal,
    }
