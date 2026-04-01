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
        "flow_id": _to_str(payload.get("flow_id") or "").strip(),
        "root_event_id": _to_str(payload.get("root_event_id") or "").strip(),
        "workspace_id": _to_str(payload.get("workspace_id") or "production").strip(),
        "run_record_id": _to_str(payload.get("run_record_id") or "").strip(),
        "command_id": _to_str(payload.get("command_id") or "").strip(),
        "step_index": _to_int(payload.get("step_index"), 0),
        "depth": _to_int(payload.get("_depth"), 0),
    }


def _build_incident_name(data: Dict[str, Any]) -> str:
    category = _to_str(data.get("category")).strip()
    failed_url = _to_str(data.get("failed_url")).strip()

    if category and failed_url:
        return f"{category.upper()} | {failed_url[:80]}"

    return "Incident"


def _normalize_decision_block(data: Dict[str, Any]) -> Dict[str, Any]:
    decision_status = _to_str(data.get("decision_status")).strip()

    if not decision_status:
        decision_status = "Monitor"

    return {
        "decision_status": decision_status,
        "decision_reason": _to_str(data.get("decision_reason")),
        "next_action": _to_str(data.get("next_action") or "complete_flow_incident"),
        "auto_executable": False,
        "priority_score": 10,
    }


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    *,
    airtable_create,
    airtable_update_by_field=None,
    incidents_table_name: str,
    **kwargs: Any,
) -> Dict[str, Any]:

    if req is not None and hasattr(req, "input"):
        payload = getattr(req, "input", {}) or {}
    elif isinstance(req, dict):
        payload = req
    else:
        payload = {}

    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            payload = {}

    if not isinstance(payload, dict):
        payload = {}

    data = _extract_input(payload)

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}

    if not isinstance(data, dict):
        data = {}

    meta = _extract_meta(data)

    print("[incident_create] payload type =", type(payload).__name__, flush=True)
    print("[incident_create] data type =", type(data).__name__, flush=True)
    print("[incident_create] payload repr =", repr(payload), flush=True)

    depth = _to_int(meta.get("depth"), 0)
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "incident_create",
            "error": "max_depth_reached",
            "terminal": True,
        }

    flow_id = meta.get("flow_id")
    root_event_id = meta.get("root_event_id") or flow_id
    workspace_id = meta.get("workspace_id")

    now_ts = _now_ts()

    # ------------------------------------------------------------
    # CREATE INCIDENT
    # ------------------------------------------------------------
    incident_fields = {
        "Name": _build_incident_name(data),
        "Status_select": "Open",
        "Severity": "High",
        "Category": _to_str(data.get("category") or "unknown"),
        "Reason": _to_str(data.get("reason") or "incident"),
        "Flow_ID": flow_id,
        "Root_Event_ID": root_event_id,
        "Workspace_ID": workspace_id,
        "Run_Record_ID": run_record_id,
        "Created_By_Capability": "incident_create",
        "Opened_At": now_ts,
        "Updated_At": now_ts,
        "Payload_JSON": _safe_json(data),
    }

    try:
        create_res = airtable_create(incidents_table_name, incident_fields)
    except Exception as e:
        return {
            "ok": False,
            "capability": "incident_create",
            "error": f"incident_create_failed:{repr(e)}",
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "run_record_id": run_record_id,
            "terminal": True,
        }

    incident_record_id = ""

    try:
        if isinstance(create_res, dict):
            incident_record_id = _to_str(create_res.get("id") or "").strip()

            if not incident_record_id:
                records_obj = create_res.get("records")
                if isinstance(records_obj, list) and records_obj:
                    first_record = records_obj[0]
                    if isinstance(first_record, dict):
                        incident_record_id = _to_str(first_record.get("id") or "").strip()

            if not incident_record_id:
                incident_record_id = _to_str(create_res.get("record_id") or "").strip()
        else:
            incident_record_id = _to_str(create_res).strip()
    except Exception as e:
        print("[incident_create] incident_record_id parse error =", repr(e), flush=True)
        incident_record_id = ""

    print("[incident_create] created =", incident_record_id, flush=True)

    # ------------------------------------------------------------
    # LINK INCIDENT → MONITORED ENDPOINT
    # ------------------------------------------------------------
    try:
        endpoint_name = _to_str(
            data.get("endpoint_name") or data.get("endpoint")
        ).strip()

        if endpoint_name and incident_record_id and callable(airtable_update_by_field):
            airtable_update_by_field(
                table="Monitored_Endpoints",
                field="Name",
                value=endpoint_name,
                fields={
                    "Last_Incident_ID": incident_record_id,
                    "Last_Error": _to_str(data.get("reason")),
                    "Last_Check_At": now_ts,
                },
            )
            print("[incident_create] endpoint linked =", endpoint_name, flush=True)
        else:
            print("[incident_create] skip endpoint update", flush=True)

    except Exception as e:
        print("[incident_create] endpoint link error =", repr(e), flush=True)

    # ------------------------------------------------------------
    # NEXT STEP
    # ------------------------------------------------------------
    decision_block = _normalize_decision_block(data)

    next_input = {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "incident_record_id": incident_record_id,
        "decision_status": decision_block["decision_status"],
        "decision_reason": decision_block["decision_reason"],
        "next_action": decision_block["next_action"],
        "auto_executable": decision_block["auto_executable"],
        "priority_score": decision_block["priority_score"],
    }

    return {
        "ok": True,
        "capability": "incident_create",
        "status": "done",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "incident_record_id": incident_record_id,
        "run_record_id": run_record_id,
        "decision_status": decision_block["decision_status"],
        "decision_reason": decision_block["decision_reason"],
        "next_action": decision_block["next_action"],
        "auto_executable": decision_block["auto_executable"],
        "priority_score": decision_block["priority_score"],
        "next_commands": [
            {
                "capability": "complete_flow_incident",
                "priority": 1,
                "input": next_input,
            }
        ],
        "terminal": False,
    }
