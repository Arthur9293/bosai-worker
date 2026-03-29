from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _try_update_one(
    airtable_update,
    table_name: str,
    record_id: str,
    fields: Dict[str, Any],
) -> Dict[str, Any]:
    try:
        print("[RESOLVE_INCIDENT] table =", table_name)
        print("[RESOLVE_INCIDENT] record_id =", record_id)
        print("[RESOLVE_INCIDENT] fields =", fields)
        airtable_update(table_name, record_id, fields)
        return {"ok": True, "fields": fields}
    except Exception as e:
        print("[RESOLVE_INCIDENT] update failed =", repr(e))
        return {"ok": False, "fields": fields, "error": repr(e)}


def _best_effort_resolve_incident(
    airtable_update,
    incidents_table_name: str,
    incident_record_id: str,
    run_record_id: str,
    resolution_note: str,
    *,
    flow_id: str = "",
    root_event_id: str = "",
    parent_command_id: str = "",
    workspace_id: str = "",
) -> Dict[str, Any]:
    resolved_at = _now_ts()

    attempts: List[Dict[str, Any]] = [
        {
            "Status_select": "Resolved",
            "Resolved_At": resolved_at,
            "Last_Action": "resolve_incident",
            "Run_Record_ID": run_record_id,
            "Linked_Run": [run_record_id] if run_record_id else [],
            "Command_ID": parent_command_id,
            "Linked_Command": [parent_command_id] if parent_command_id else [],
            "Flow_ID": flow_id,
            "Root_Event_ID": root_event_id,
            "Workspace_ID": workspace_id,
            "Updated_At": resolved_at,
            "Resolution_Note": resolution_note,
        },
        {
            "Status_select": "Resolved",
            "Resolved_At": resolved_at,
            "Last_Action": "resolve_incident",
            "Run_Record_ID": run_record_id,
            "Command_ID": parent_command_id,
            "Flow_ID": flow_id,
            "Root_Event_ID": root_event_id,
            "Workspace_ID": workspace_id,
            "Updated_At": resolved_at,
            "Resolution_Note": resolution_note,
        },
        {
            "Status_select": "Resolved",
            "Resolved_At": resolved_at,
            "Last_Action": "resolve_incident",
            "Run_Record_ID": run_record_id,
            "Updated_At": resolved_at,
            "Resolution_Note": resolution_note,
        },
        {
            "Status_select": "Resolved",
            "Resolved_At": resolved_at,
            "Resolution_Note": resolution_note,
        },
        {
            "Status_select": "Resolved",
            "Resolved_At": resolved_at,
        },
        {
            "Status_select": "Resolved",
        },
        {
            "Status": "Resolved",
        },
        {
            "status": "Resolved",
        },
        {
            "Resolved_At": resolved_at,
        },
        {
            "Resolution_Note": resolution_note,
        } if resolution_note else {},
    ]

    results: List[Dict[str, Any]] = []

    for fields in attempts:
        if not fields:
            continue

        clean_fields = {
            k: v for k, v in fields.items()
            if v not in ("", None)
        }

        res = _try_update_one(
            airtable_update=airtable_update,
            table_name=incidents_table_name,
            record_id=incident_record_id,
            fields=clean_fields,
        )
        results.append(res)

        if res.get("ok"):
            return {
                "ok": True,
                "chosen_fields": clean_fields,
                "attempts": results,
                "resolved_at": resolved_at,
            }

    return {
        "ok": False,
        "chosen_fields": {},
        "attempts": results,
        "resolved_at": resolved_at,
    }


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    *,
    airtable_update,
    incidents_table_name: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    if req is not None and hasattr(req, "input"):
        payload = getattr(req, "input", {}) or {}
    elif isinstance(req, dict):
        payload = req
    else:
        payload = {}

    incident_record_id = _to_str(
        payload.get("incident_record_id")
        or payload.get("incidentrecordid")
        or payload.get("Incident_Record_ID")
        or ""
    ).strip()

    flow_id = _to_str(
        payload.get("flow_id")
        or payload.get("flowid")
        or ""
    ).strip()

    root_event_id = _to_str(
        payload.get("root_event_id")
        or payload.get("rooteventid")
        or payload.get("event_id")
        or payload.get("eventid")
        or ""
    ).strip()

    parent_command_id = _to_str(
        payload.get("parent_command_id")
        or payload.get("parentcommandid")
        or payload.get("parentCommandId")
        or payload.get("command_id")
        or payload.get("commandid")
        or payload.get("Command_ID")
        or ""
    ).strip()

    workspace_id = _to_str(
        payload.get("workspace_id")
        or payload.get("workspaceid")
        or payload.get("workspaceId")
        or payload.get("Workspace_ID")
        or "production"
    ).strip()

    resolution_note = _to_str(
        payload.get("resolution_note")
        or payload.get("resolutionnote")
        or payload.get("note")
        or payload.get("message")
        or "incident_resolved"
    ).strip()

    if not incident_record_id:
        return {
            "ok": False,
            "capability": "resolve_incident",
            "error": "missing_incident_record_id",
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "terminal": True,
            "spawn_summary": {
                "ok": True,
                "spawned": 0,
                "skipped": 0,
                "errors": [],
            },
        }

    update_res = _best_effort_resolve_incident(
        airtable_update=airtable_update,
        incidents_table_name=incidents_table_name,
        incident_record_id=incident_record_id,
        run_record_id=_to_str(run_record_id),
        resolution_note=resolution_note,
        flow_id=flow_id,
        root_event_id=root_event_id,
        parent_command_id=parent_command_id,
        workspace_id=workspace_id,
    )

    if not update_res.get("ok"):
        return {
            "ok": False,
            "capability": "resolve_incident",
            "error": "resolve_incident_failed",
            "incident_record_id": incident_record_id,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "run_record_id": _to_str(run_record_id),
            "update_res": update_res,
            "terminal": True,
            "spawn_summary": {
                "ok": True,
                "spawned": 0,
                "skipped": 0,
                "errors": [],
            },
        }

    return {
        "ok": True,
        "capability": "resolve_incident",
        "status": "done",
        "incident_record_id": incident_record_id,
        "message": "incident_resolved",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "run_record_id": _to_str(run_record_id),
        "resolved_at": update_res.get("resolved_at", _now_ts()),
        "resolution_note": resolution_note,
        "next_commands": [],
        "terminal": True,
        "spawn_summary": {
            "ok": True,
            "spawned": 0,
            "skipped": 0,
            "errors": [],
        },
    }
