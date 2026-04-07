from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(v: Any) -> str:
    try:
        return str(v or "")
    except Exception:
        return ""


def _to_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return default
        return int(v)
    except Exception:
        return default


def _to_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    try:
        text = str(v).strip().lower()
    except Exception:
        return default

    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _json_load_maybe(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        return json.loads(text)
    except Exception:
        return None


def _pick_text(*values: Any) -> str:
    for value in values:
        if value is None:
            continue

        if isinstance(value, list):
            for item in value:
                text = _pick_text(item)
                if text:
                    return text
            continue

        if isinstance(value, dict):
            for key in ("id", "name", "value", "text"):
                if key in value:
                    text = _pick_text(value.get(key))
                    if text:
                        return text
            continue

        text = _to_str(value).strip()
        if text:
            return text

    return ""


def _normalize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    normalized = dict(payload)

    # unwrap input / command_input if present
    for key in ("input", "command_input"):
        nested = normalized.get(key)
        if isinstance(nested, dict):
            merged = dict(normalized)
            merged.pop(key, None)
            merged.update(nested)
            normalized = merged

    flow_id = _pick_text(
        normalized.get("flow_id"),
        normalized.get("flowid"),
        normalized.get("flowId"),
    )

    root_event_id = _pick_text(
        normalized.get("root_event_id"),
        normalized.get("rooteventid"),
        normalized.get("rootEventId"),
        normalized.get("event_id"),
        normalized.get("eventid"),
        normalized.get("eventId"),
        flow_id,
    )

    source_event_id = _pick_text(
        normalized.get("source_event_id"),
        normalized.get("sourceeventid"),
        normalized.get("sourceEventId"),
        normalized.get("event_id"),
        normalized.get("eventid"),
        normalized.get("eventId"),
        root_event_id,
        flow_id,
    )

    workspace_id = _pick_text(
        normalized.get("workspace_id"),
        normalized.get("workspaceid"),
        normalized.get("workspaceId"),
        normalized.get("workspace"),
        "production",
    )

    run_record_id = _pick_text(
        normalized.get("run_record_id"),
        normalized.get("runrecordid"),
        normalized.get("runRecordId"),
        normalized.get("linked_run"),
        normalized.get("linkedrun"),
    )

    linked_run = _pick_text(
        normalized.get("linked_run"),
        normalized.get("linkedrun"),
        run_record_id,
    )

    command_id = _pick_text(
        normalized.get("command_id"),
        normalized.get("commandid"),
        normalized.get("commandId"),
    )

    parent_command_id = _pick_text(
        normalized.get("parent_command_id"),
        normalized.get("parentcommandid"),
        normalized.get("parentCommandId"),
        command_id,
    )

    normalized["flow_id"] = flow_id
    normalized["root_event_id"] = root_event_id
    normalized["source_event_id"] = source_event_id
    normalized["event_id"] = source_event_id or root_event_id or flow_id
    normalized["workspace_id"] = workspace_id
    normalized["workspace"] = workspace_id
    normalized["run_record_id"] = run_record_id
    normalized["linked_run"] = linked_run
    normalized["command_id"] = command_id
    normalized["parent_command_id"] = parent_command_id
    normalized["step_index"] = _to_int(
        normalized.get("step_index")
        if normalized.get("step_index") is not None
        else normalized.get("stepindex")
        if normalized.get("stepindex") is not None
        else normalized.get("stepIndex"),
        0,
    )
    normalized["_depth"] = _to_int(
        normalized.get("_depth")
        if normalized.get("_depth") is not None
        else normalized.get("depth"),
        0,
    )

    return normalized


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    **kwargs: Any,
) -> Dict[str, Any]:

    if req is not None and hasattr(req, "input"):
        payload = getattr(req, "input", {}) or {}
    elif isinstance(req, dict):
        payload = req
    else:
        payload = {}

    if isinstance(payload, str):
        payload = _json_load_maybe(payload) or {}

    if not isinstance(payload, dict):
        payload = {}

    payload = _normalize_payload(payload)

    flow_id = _pick_text(payload.get("flow_id"))
    root_event_id = _pick_text(payload.get("root_event_id"), flow_id)
    source_event_id = _pick_text(payload.get("source_event_id"), root_event_id, flow_id)
    workspace_id = _pick_text(payload.get("workspace_id"), "production")

    incoming_run_record_id = _pick_text(payload.get("run_record_id"))
    linked_run = _pick_text(payload.get("linked_run"), incoming_run_record_id, run_record_id)
    effective_run_record_id = _pick_text(run_record_id, incoming_run_record_id, linked_run)

    command_id = _pick_text(payload.get("command_id"))
    parent_command_id = _pick_text(payload.get("parent_command_id"), command_id)

    incident_record_id = _pick_text(
        payload.get("incident_record_id"),
        payload.get("incidentrecordid"),
    )

    severity = _pick_text(payload.get("severity")).strip().lower()
    final_failure = _to_bool(
        payload.get("final_failure")
        if payload.get("final_failure") is not None
        else payload.get("finalfailure"),
        False,
    )

    current_step_index = _to_int(payload.get("step_index"), 0)
    current_depth = _to_int(payload.get("_depth"), 0)

    auto_resolve = False
    decision = "keep_escalated"
    next_commands = []

    next_input_base = {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "event_id": source_event_id or root_event_id or flow_id,
        "workspace_id": workspace_id,
        "workspace": workspace_id,
        "run_record_id": effective_run_record_id,
        "linked_run": linked_run or effective_run_record_id,
        "incident_record_id": incident_record_id,
        "parent_command_id": command_id or parent_command_id,
        "command_id": command_id,
        "step_index": current_step_index + 1,
        "_depth": current_depth + 1,
        "severity": severity,
        "final_failure": final_failure,
    }

    if incident_record_id and severity in {"low", "medium"} and not final_failure:
        auto_resolve = True
        decision = "auto_resolve"
        next_commands.append(
            {
                "capability": "resolve_incident",
                "priority": 1,
                "input": dict(next_input_base),
            }
        )

    return {
        "ok": True,
        "capability": "complete_flow_incident",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "incident_record_id": incident_record_id,
        "completed": True,
        "message": "incident_flow_completed",
        "closed_at": _now_ts(),
        "run_record_id": effective_run_record_id,
        "linked_run": linked_run or effective_run_record_id,
        "workspace_id": workspace_id,
        "command_id": command_id,
        "decision": decision,
        "auto_resolve": auto_resolve,
        "severity": severity,
        "final_failure": final_failure,
        "next_commands": next_commands,
        "terminal": len(next_commands) == 0,
        "spawn_summary": {
            "ok": True,
            "spawned": len(next_commands),
            "skipped": 0,
            "errors": [],
        },
    }
