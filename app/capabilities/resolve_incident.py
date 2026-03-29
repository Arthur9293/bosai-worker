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


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    *,
    airtable_update=None,
    incidents_table_name: str = "",
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

    if not incident_record_id:
        return {
            "ok": False,
            "capability": "resolve_incident",
            "error": "missing_incident_record_id",
            "payload_debug": payload,
            "terminal": True,
        }

    try:
        if airtable_update and incidents_table_name:
            airtable_update(
                incidents_table_name,
                incident_record_id,
                {
                    "Status_select": "Resolved",
                    "Last_Action": "resolve_incident",
                    "Resolved_At": _now_ts(),
                    "Run_Record_ID": _to_str(run_record_id),
                },
            )
    except Exception as e:
        return {
            "ok": False,
            "capability": "resolve_incident",
            "error": f"resolve_incident_failed:{repr(e)}",
            "incident_record_id": incident_record_id,
            "payload_debug": payload,
            "terminal": True,
        }

    return {
        "ok": True,
        "capability": "resolve_incident",
        "status": "done",
        "incident_record_id": incident_record_id,
        "message": "incident_resolved",
        "run_record_id": _to_str(run_record_id),
        "next_commands": [],
        "terminal": True,
    }
