from __future__ import annotations

import time
from typing import Any, Dict, Optional


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
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

    flow_id = _to_str(data.get("flow_id")).strip()
    root_event_id = _to_str(data.get("root_event_id")).strip()
    command_id = _to_str(
        data.get("command_id")
        or data.get("commandid")
        or data.get("commandId")
        or data.get("parent_command_id")
        or data.get("parentcommandid")
        or data.get("parentCommandId")
        or ""
    ).strip()

    incident_record_id = _pick_incident_record_id(data)
    if not incident_record_id:
        return {
            "ok": False,
            "capability": "resolve_incident",
            "error": "missing_incident_record_id",
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "run_record_id": run_record_id,
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

    incident_update_fields = {
        "Status_select": "Resolved",
        "Closed_At": now_ts,
        "Resolution_Note": resolution_note,
        "Last_Action": "resolve_incident",
        "Last_Seen_At": now_ts,
        "Updated_At": now_ts,
        "Run_Record_ID": _to_str(run_record_id).strip(),
        "Command_ID": command_id,
        "Flow_ID": flow_id,
        "Root_Event_ID": root_event_id,
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
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "incident_record_id": incident_record_id,
            "run_record_id": run_record_id,
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
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "incident_record_id": incident_record_id,
        "run_record_id": run_record_id,
        "command_id": command_id,
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
