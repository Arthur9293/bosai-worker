from __future__ import annotations

import json
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


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return "{}"


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


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
        ),
        "root_event_id": _to_str(
            payload.get("root_event_id")
            or payload.get("rooteventid")
            or payload.get("rootEventId")
            or payload.get("event_id")
            or payload.get("eventid")
            or payload.get("eventId")
            or ""
        ),
        "parent_command_id": _to_str(
            payload.get("parent_command_id")
            or payload.get("parentcommand_id")
            or payload.get("parentCommandId")
            or ""
        ),
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
        "workspace_id": _to_str(
            payload.get("workspace_id")
            or payload.get("workspaceid")
            or payload.get("workspaceId")
            or "production"
        ),
        "run_record_id": _to_str(
            payload.get("run_record_id")
            or payload.get("runrecordid")
            or payload.get("runRecordId")
            or ""
        ),
        "tenant_id": _to_str(
            payload.get("tenant_id")
            or payload.get("tenantid")
            or payload.get("tenantId")
            or ""
        ),
        "app_name": _to_str(
            payload.get("app_name")
            or payload.get("appname")
            or payload.get("appName")
            or ""
        ),
    }


def _build_update_candidates(data: Dict[str, Any], meta: Dict[str, Any]) -> list[Dict[str, Any]]:
    now_ts = _now_ts()

    error_message = _to_str(
        data.get("error")
        or data.get("error_message")
        or data.get("errormessage")
        or ""
    )

    base = {
        "Last_Seen_At": now_ts,
        "Last_Action": "incident_update",
        "Run_Record_ID": _to_str(meta.get("run_record_id")),
        "Payload_JSON": _safe_json(data),
        "Error_Message": error_message,
        "Reason": _to_str(data.get("reason") or "incident_updated"),
        "Severity": _to_str(data.get("severity") or "medium"),
        "Category": _to_str(data.get("category") or "unknown_incident"),
        "HTTP_Status": _to_int(data.get("http_status"), 0),
        "Failed_URL": _to_str(
            data.get("failed_url")
            or data.get("target_url")
            or ""
        ),
        "Failed_Method": _to_str(
            data.get("failed_method")
            or data.get("method")
            or ""
        ).upper(),
        "Final_Failure": _to_bool(data.get("final_failure"), False),
        "Workspace_ID": _to_str(meta.get("workspace_id")),
        "Tenant_ID": _to_str(meta.get("tenant_id")),
        "App_Name": _to_str(meta.get("app_name")),
    }

    return [
        {
            **base,
            "Status_select": "Investigating",
        },
        base,
        {
            "Last_Seen_At": now_ts,
        },
    ]


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
            "capability": "incident_update",
            "error": "max_depth_reached",
            "flow_id": meta.get("flow_id", ""),
            "root_event_id": meta.get("root_event_id", ""),
            "run_record_id": run_record_id or meta.get("run_record_id", ""),
            "terminal": True,
        }

    effective_run_record_id = _to_str(run_record_id or meta.get("run_record_id") or "")
    incident_record_id = _to_str(
        data.get("incident_record_id")
        or data.get("incidentrecordid")
        or ""
    ).strip()

    if not incident_record_id:
        return {
            "ok": False,
            "capability": "incident_update",
            "error": "missing_incident_record_id",
            "flow_id": meta.get("flow_id", ""),
            "root_event_id": meta.get("root_event_id", ""),
            "run_record_id": effective_run_record_id,
            "terminal": True,
        }

    updated = False
    update_error = ""

    for candidate in _build_update_candidates(data, meta):
        try:
            airtable_update(incidents_table_name, incident_record_id, candidate)
            updated = True
            break
        except Exception as e:
            update_error = repr(e)

    if not updated:
        return {
            "ok": False,
            "capability": "incident_update",
            "error": f"incident_update_failed:{update_error}",
            "incident_record_id": incident_record_id,
            "flow_id": meta.get("flow_id", ""),
            "root_event_id": meta.get("root_event_id", ""),
            "run_record_id": effective_run_record_id,
            "terminal": True,
        }

    # SAFE PATCH: stop propre après update pour éviter boucle indirecte
    return {
        "ok": True,
        "capability": "incident_update",
        "status": "done",
        "flow_id": meta.get("flow_id", ""),
        "root_event_id": meta.get("root_event_id", ""),
        "incident_record_id": incident_record_id,
        "message": "incident_updated",
        "run_record_id": effective_run_record_id,
        "updated": True,
        "next_commands": [],
        "terminal": True,
        "spawn_summary": {
            "ok": True,
            "spawned": 0,
            "skipped": 1,
            "errors": [],
        },
    }
