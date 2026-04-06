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


def _first_non_empty(data: Dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = data.get(key)
        text = _to_str(value).strip()
        if text:
            return text
    return default


def _first_int(data: Dict[str, Any], *keys: str, default: int = 0) -> int:
    for key in keys:
        value = data.get(key)
        if value is None or value == "":
            continue
        parsed = _to_int(value, default)
        return parsed
    return default


def _extract_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    flow_id = _first_non_empty(
        payload,
        "flow_id",
        "flowId",
        "flowid",
    )

    root_event_id = _first_non_empty(
        payload,
        "root_event_id",
        "rootEventId",
        "rooteventid",
        "event_id",
        "eventId",
        "source_event_id",
        "sourceEventId",
        "sourceeventid",
        default=flow_id,
    )

    source_event_id = _first_non_empty(
        payload,
        "source_event_id",
        "sourceEventId",
        "sourceeventid",
        "event_id",
        "eventId",
        default=root_event_id,
    )

    workspace_id = _first_non_empty(
        payload,
        "workspace_id",
        "workspaceId",
        "workspaceid",
        "Workspace_ID",
        "workspace",
        default="production",
    )

    run_record_id = _first_non_empty(
        payload,
        "run_record_id",
        "runRecordId",
        "runrecordid",
        "linked_run",
        "linkedRun",
        "linkedrun",
    )

    command_id = _first_non_empty(
        payload,
        "command_id",
        "commandId",
        "commandid",
    )

    parent_command_id = _first_non_empty(
        payload,
        "parent_command_id",
        "parentCommandId",
        "parentcommandid",
        default=command_id,
    )

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "workspace_id": workspace_id,
        "run_record_id": run_record_id,
        "command_id": command_id,
        "parent_command_id": parent_command_id,
        "step_index": _first_int(
            payload,
            "step_index",
            "stepIndex",
            "stepindex",
            default=0,
        ),
        "depth": _first_int(
            payload,
            "_depth",
            "depth",
            default=0,
        ),
    }


def _build_incident_name(data: Dict[str, Any]) -> str:
    category = _to_str(data.get("category")).strip()
    failed_url = _to_str(data.get("failed_url") or data.get("url") or data.get("http_target")).strip()

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
    print("[incident_create] meta =", meta, flush=True)

    depth = _to_int(meta.get("depth"), 0)
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "incident_create",
            "error": "max_depth_reached",
            "terminal": True,
        }

    flow_id = _to_str(meta.get("flow_id")).strip()
    root_event_id = _to_str(meta.get("root_event_id")).strip() or flow_id
    source_event_id = _to_str(meta.get("source_event_id")).strip() or root_event_id
    workspace_id = _to_str(meta.get("workspace_id")).strip() or "production"

    effective_run_record_id = _to_str(run_record_id).strip() or _to_str(meta.get("run_record_id")).strip()
    parent_command_id = _to_str(meta.get("parent_command_id")).strip()
    current_step_index = _to_int(meta.get("step_index"), 0)

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
        "Run_Record_ID": effective_run_record_id,
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
            "source_event_id": source_event_id,
            "run_record_id": effective_run_record_id,
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
        "source_event_id": source_event_id,
        "event_id": source_event_id,
        "workspace_id": workspace_id,
        "run_record_id": effective_run_record_id,
        "linked_run": effective_run_record_id,
        "incident_record_id": incident_record_id,
        "parent_command_id": parent_command_id,
        "step_index": current_step_index + 1,
        "decision_status": decision_block["decision_status"],
        "decision_reason": decision_block["decision_reason"],
        "next_action": decision_block["next_action"],
        "auto_executable": decision_block["auto_executable"],
        "priority_score": decision_block["priority_score"],
        "category": _to_str(data.get("category")),
        "reason": _to_str(data.get("reason")),
        "severity": _to_str(data.get("severity")),
        "method": _to_str(data.get("method")),
        "failed_url": _to_str(data.get("failed_url") or data.get("url") or data.get("http_target")),
        "url": _to_str(data.get("url") or data.get("failed_url") or data.get("http_target")),
        "http_target": _to_str(data.get("http_target") or data.get("url") or data.get("failed_url")),
    }

    print("[incident_create] next_input =", next_input, flush=True)

    return {
        "ok": True,
        "capability": "incident_create",
        "status": "done",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "incident_record_id": incident_record_id,
        "run_record_id": effective_run_record_id,
        "linked_run": effective_run_record_id,
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
