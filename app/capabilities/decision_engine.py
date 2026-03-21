# app/capabilities/decision_engine.py
from __future__ import annotations

from typing import Any, Dict, List


def run(input_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload = input_data or {}

    flow_id = payload.get("flow_id")
    root_event_id = payload.get("root_event_id")
    workspace_id = payload.get("workspace_id")

    incident_decision = str(payload.get("incident_decision") or "").strip()
    incident_reason = str(payload.get("incident_reason") or "").strip()
    http_status = payload.get("http_status")
    retry_count = int(payload.get("retry_count") or 0)
    retry_max = int(payload.get("retry_max") or 0)
    original_capability = payload.get("original_capability") or "http_exec"
    original_input = payload.get("original_input") or {}
    incident_record_id = payload.get("incident_record_id")

    final_state = "observe"
    action_plan: List[str] = []
    next_commands: List[Dict[str, Any]] = []

    if incident_decision == "retry":
        final_state = "retrying"
        action_plan = [
            "retry original capability",
            "track retry attempt",
        ]
        next_commands.append(
            {
                "capability": original_capability,
                "priority": 2,
                "input": {
                    **original_input,
                    "retry_count": retry_count + 1,
                    "retry_max": retry_max,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "workspace_id": workspace_id,
                    "incident_record_id": incident_record_id,
                },
            }
        )

    elif incident_decision == "escalate":
        final_state = "escalated"
        action_plan = [
            "spawn escalation",
            "mark flow as escalated",
        ]
        next_commands.append(
            {
                "capability": "internal_escalate",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "workspace_id": workspace_id,
                    "incident_reason": incident_reason,
                    "http_status": http_status,
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "incident_record_id": incident_record_id,
                    "original_capability": original_capability,
                    "original_input": original_input,
                },
            }
        )

    else:
        final_state = "logged_only"
        action_plan = [
            "no automatic action",
            "keep trace in system",
        ]

    return {
        "ok": True,
        "capability": "decision_engine",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "incident_decision": incident_decision,
        "incident_reason": incident_reason,
        "final_state": final_state,
        "action_plan": action_plan,
        "next_commands": next_commands,
        "terminal": final_state in ("escalated", "logged_only"),
    }
