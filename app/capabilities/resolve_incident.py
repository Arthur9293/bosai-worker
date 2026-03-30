from __future__ import annotations

import time
from typing import Any, Dict, Optional


DEFAULT_MAX_DEPTH = 8


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _extract_input(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    for key in ("input", "command_input", "incident"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            merged = dict(payload)
            merged.update(nested)
            return merged

    return dict(payload)


def _extract_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "flow_id": _to_str(
            payload.get("flow_id")
            or payload.get("flowid")
            or payload.get("flowId")
            or ""
        ).strip(),
        "root_event_id": _to_str(
            payload.get("root_event_id")
            or payload.get("rooteventid")
            or payload.get("rootEventId")
            or payload.get("event_id")
            or payload.get("eventid")
            or payload.get("eventId")
            or ""
        ).strip(),
        "parent_command_id": _to_str(
            payload.get("parent_command_id")
            or payload.get("parentcommand_id")
            or payload.get("parentCommandId")
            or ""
        ).strip(),
        "command_id": _to_str(
            payload.get("command_id")
            or payload.get("commandid")
            or payload.get("commandId")
            or payload.get("parent_command_id")
            or payload.get("parentcommand_id")
            or payload.get("parentCommandId")
            or ""
        ).strip(),
        "run_record_id": _to_str(
            payload.get("run_record_id")
            or payload.get("runrecordid")
            or payload.get("runRecordId")
            or payload.get("linked_run")
            or payload.get("Linked_Run")
            or payload.get("run_id")
            or payload.get("runid")
            or payload.get("runId")
            or ""
        ).strip(),
        "workspace_id": _to_str(
            payload.get("workspace_id")
            or payload.get("workspaceid")
            or payload.get("workspaceId")
            or "production"
        ).strip(),
        "tenant_id": _to_str(
            payload.get("tenant_id")
            or payload.get("tenantid")
            or payload.get("tenantId")
            or ""
        ).strip(),
        "app_name": _to_str(
            payload.get("app_name")
            or payload.get("appname")
            or payload.get("appName")
            or ""
        ).strip(),
        "step_index": _to_int(
            payload.get("step_index")
            if payload.get("step_index") is not None
            else payload.get("stepindex")
            if payload.get("stepindex") is not None
            else payload.get("stepIndex"),
            0,
        ),
        "depth": _to_int(
            payload.get("depth")
            if payload.get("depth") is not None
            else payload.get("_depth")
            if payload.get("_depth") is not None
            else 0,
            0,
        ),
    }


def _pick_incident_record_id(data: Dict[str, Any]) -> str:
    return _to_str(
        data.get("incident_record_id")
        or data.get("incidentrecordid")
        or data.get("Incident_Record_ID")
        or data.get("incident_id")
        or data.get("incidentid")
        or data.get("Incident_ID")
        or ""
    ).strip()


def _pick_resolution_note(data: Dict[str, Any]) -> str:
    return _to_str(
        data.get("resolution_note")
        or data.get("resolutionnote")
        or data.get("Resolution_Note")
        or data.get("note")
        or data.get("resolution")
        or "Auto-resolved by BOSAI"
    ).strip()


def _best_effort_update_incident(
    *,
    airtable_update,
    incidents_table_name: str,
    incident_record_id: str,
    full_fields: Dict[str, Any],
) -> Dict[str, Any]:
    attempts = []

    candidate_payloads = [
        dict(full_fields),
        {
            k: v
            for k, v in full_fields.items()
            if k in {
                "Status_select",
                "Closed_At",
                "Resolution_Note",
                "Last_Action",
                "Last_Seen_At",
                "Updated_At",
            }
        },
        {
            k: v
            for k, v in full_fields.items()
            if k in {
                "Status_select",
                "Closed_At",
                "Updated_At",
            }
        },
        {
            "Status_select": "Resolved",
        },
    ]

    seen = set()

    for fields in candidate_payloads:
        clean_fields = {k: v for k, v in fields.items() if v not in ("", None, [])}
        signature = tuple(sorted(clean_fields.keys()))
        if not clean_fields or signature in seen:
            continue
        seen.add(signature)

        try:
            res = airtable_update(incidents_table_name, incident_record_id, clean_fields)
            return {
                "ok": True,
                "fields": clean_fields,
                "response": res,
                "attempts": attempts,
            }
        except Exception as exc:
            attempts.append(
                {
                    "ok": False,
                    "fields": clean_fields,
                    "error": repr(exc),
                }
            )

    return {
        "ok": False,
        "attempts": attempts,
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

    data = _extract_input(payload)
    meta = _extract_meta(data)

    depth = _to_int(meta.get("depth"), 0)
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "resolve_incident",
            "error": "max_depth_reached",
            "flow_id": meta.get("flow_id", ""),
            "root_event_id": meta.get("root_event_id", ""),
            "run_record_id": meta.get("run_record_id", "") or run_record_id,
            "terminal": True,
            "spawn_summary": {
                "ok": True,
                "spawned": 0,
                "skipped": 0,
                "errors": [],
            },
        }

    effective_flow_id = _to_str(meta.get("flow_id", "")).strip()
    effective_root_event_id = _to_str(meta.get("root_event_id", "")).strip()
    effective_run_record_id = _to_str(
        run_record_id
        or meta.get("run_record_id")
        or data.get("run_record_id")
        or data.get("runrecordid")
        or data.get("linked_run")
        or data.get("Linked_Run")
        or ""
    ).strip()
    effective_command_id = _to_str(
        meta.get("command_id")
        or data.get("command_id")
        or data.get("commandid")
        or data.get("commandId")
        or meta.get("parent_command_id")
        or data.get("parent_command_id")
        or data.get("parentcommandid")
        or ""
    ).strip()

    incident_record_id = _pick_incident_record_id(data)
    if not incident_record_id:
        return {
            "ok": False,
            "capability": "resolve_incident",
            "error": "missing_incident_record_id",
            "flow_id": effective_flow_id,
            "root_event_id": effective_root_event_id,
            "run_record_id": effective_run_record_id,
            "terminal": True,
            "spawn_summary": {
                "ok": True,
                "spawned": 0,
                "skipped": 0,
                "errors": [],
            },
        }

    now_ts = _now_ts()
    resolution_note = _pick_resolution_note(data)
    auto_resolve = _to_bool(
        data.get("auto_resolve")
        if data.get("auto_resolve") is not None
        else data.get("autoresolve"),
        True,
    )

    incident_update_fields = {
        "Status_select": "Resolved",
        "Closed_At": now_ts,
        "Resolution_Note": resolution_note,
        "Last_Action": "resolve_incident",
        "Last_Seen_At": now_ts,
        "Updated_At": now_ts,
        "Run_Record_ID": effective_run_record_id,
        "Command_ID": effective_command_id,
        "Flow_ID": effective_flow_id,
        "Root_Event_ID": effective_root_event_id,
        "Workspace_ID": _to_str(meta.get("workspace_id", "")).strip(),
    }

    incident_update_res = _best_effort_update_incident(
        airtable_update=airtable_update,
        incidents_table_name=incidents_table_name,
        incident_record_id=incident_record_id,
        full_fields=incident_update_fields,
    )

    if not incident_update_res.get("ok"):
        return {
            "ok": False,
            "capability": "resolve_incident",
            "error": "incident_update_failed",
            "flow_id": effective_flow_id,
            "root_event_id": effective_root_event_id,
            "incident_record_id": incident_record_id,
            "run_record_id": effective_run_record_id,
            "incident_update_res": incident_update_res,
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
        "flow_id": effective_flow_id,
        "root_event_id": effective_root_event_id,
        "incident_record_id": incident_record_id,
        "run_record_id": effective_run_record_id,
        "command_id": effective_command_id,
        "auto_resolve": auto_resolve,
        "resolved_at": now_ts,
        "resolution_note": resolution_note,
        "incident_update_ok": True,
        "incident_update_res": incident_update_res,
        "next_commands": [],
        "terminal": True,
        "spawn_summary": {
            "ok": True,
            "spawned": 0,
            "skipped": 0,
            "errors": [],
        },
    }
