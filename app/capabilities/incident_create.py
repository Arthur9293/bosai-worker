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
        "command_id": _to_str(
            payload.get("command_id")
            or payload.get("commandid")
            or payload.get("commandId")
            or payload.get("parent_command_id")
            or payload.get("parentcommand_id")
            or payload.get("parentCommandId")
            or ""
        ),
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


def _build_incident_name(data: Dict[str, Any]) -> str:
    category = _to_str(data.get("category") or "").strip()
    code = _to_str(data.get("incident_code") or data.get("incidentcode") or "").strip()
    failed_url = _to_str(
        data.get("failed_url")
        or data.get("failedurl")
        or data.get("target_url")
        or data.get("targeturl")
        or ""
    ).strip()
    http_status = _to_int(
        data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus"),
        0,
    )

    if category and failed_url:
        short_url = failed_url[:80]
        return f"{category.upper()} | {short_url}"

    if code and http_status:
        return f"{code} | {http_status}"

    if code:
        return code

    return "Incident"


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    *,
    airtable_create,
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
            "error": "max_depth_reached",
            "flow_id": meta.get("flow_id", ""),
            "root_event_id": meta.get("root_event_id", ""),
            "run_record_id": meta.get("run_record_id", "") or run_record_id,
            "terminal": True,
        }

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

    parent_command_id = _to_str(
        meta.get("parent_command_id")
        or data.get("parent_command_id")
        or data.get("parentcommandid")
        or data.get("parentCommandId")
        or effective_command_id
        or ""
    ).strip()

    linked_run_ids = (
        [effective_run_record_id]
        if effective_run_record_id.startswith("rec")
        else []
    )

    linked_command_ids = (
        [effective_command_id]
        if effective_command_id.startswith("rec")
        else []
    )

    effective_flow_id = _to_str(meta.get("flow_id", "")).strip()
    effective_root_event_id = _to_str(meta.get("root_event_id", "")).strip()

    error_message = _to_str(
        data.get("error")
        or data.get("error_message")
        or data.get("errormessage")
        or ""
    )

    incident_key = _to_str(data.get("incident_key") or "")
    deduplicate_action = _to_str(data.get("deduplicate_action") or "")
    final_failure = _to_bool(
        data.get("final_failure")
        if data.get("final_failure") is not None
        else data.get("finalfailure"),
        False,
    )

    failed_capability = _to_str(
        data.get("failed_capability")
        or data.get("failedcapability")
        or data.get("original_capability")
        or data.get("originalcapability")
        or ""
    )

    now_ts = _now_ts()

    incident_fields = {
        "Name": _build_incident_name(data),
        "Status_select": "Open",
        "Severity": _to_str(data.get("severity") or "medium").strip().title() or "Medium",
        "Category": _to_str(data.get("category") or "unknown_incident").strip(),
        "Reason": _to_str(data.get("reason") or "incident_create").strip(),
        "HTTP_Status": _to_int(
            data.get("http_status")
            or data.get("httpstatus"),
            0,
        ),
        "Original_Capability": _to_str(
            data.get("original_capability")
            or data.get("originalcapability")
            or failed_capability
            or ""
        ).strip(),
        "Failed_Capability": failed_capability.strip(),
        "Failed_URL": _to_str(
            data.get("failed_url")
            or data.get("failedurl")
            or data.get("target_url")
            or data.get("targeturl")
            or "",
        ).strip(),
        "Failed_Method": _to_str(
            data.get("failed_method")
            or data.get("failedmethod")
            or data.get("method")
            or "",
        ).upper().strip(),
        "Error_Message": error_message.strip(),
        "Flow_ID": effective_flow_id,
        "Root_Event_ID": effective_root_event_id,
        "Workspace_ID": _to_str(meta.get("workspace_id", "")).strip(),
        "Tenant_ID": _to_str(meta.get("tenant_id", "")).strip(),
        "App_Name": _to_str(meta.get("app_name", "")).strip(),
        "Run_Record_ID": effective_run_record_id,
        "Linked_Run": linked_run_ids,
        "Command_ID": effective_command_id,
        "Linked_Command": linked_command_ids,
        "Payload_JSON": _safe_json(data),
        "Created_By_Capability": "incident_create",
        "Opened_At": now_ts,
        "Updated_At": now_ts,
        "Incident_Key": incident_key.strip(),
        "Last_Seen_At": now_ts,
        "Occurrences_Count": 1,
        "Deduplicate_Action": deduplicate_action.strip(),
        "Final_Failure": final_failure,
        "SLA_Status": "Open",
    }

    clean_fields = {
        k: v for k, v in incident_fields.items()
        if v not in ("", None, [])
    }

    try:
        create_res = airtable_create(incidents_table_name, clean_fields)

        incident_record_id = ""

        if isinstance(create_res, dict):
            incident_record_id = _to_str(
                create_res.get("id")
                or create_res.get("record_id")
                or (
                    create_res.get("records")[0].get("id")
                    if isinstance(create_res.get("records"), list)
                    and create_res.get("records")
                    and isinstance(create_res.get("records")[0], dict)
                    else ""
                )
            ).strip()
        else:
            incident_record_id = _to_str(create_res).strip()

        print("[incident_create] created incident_record_id =", incident_record_id)
        print("[incident_create] linked flow_id =", effective_flow_id)
        print("[incident_create] linked root_event_id =", effective_root_event_id)
        print("[incident_create] linked command_id =", effective_command_id)
        print("[incident_create] linked run_record_id =", effective_run_record_id)

    except Exception as e:
        return {
            "ok": False,
            "error": f"incident_create_failed:{repr(e)}",
            "flow_id": effective_flow_id,
            "root_event_id": effective_root_event_id,
            "run_record_id": effective_run_record_id,
            "terminal": True,
        }

    if not effective_flow_id and incident_record_id:
        effective_flow_id = f"flow_{incident_record_id}"

    if not effective_root_event_id:
        effective_root_event_id = effective_flow_id

    next_input = {
        "flow_id": effective_flow_id,
        "root_event_id": effective_root_event_id,
        "step_index": _to_int(meta.get("step_index"), 0) + 1,
        "_depth": depth + 1,
        "workspace_id": meta.get("workspace_id", ""),
        "tenant_id": meta.get("tenant_id", ""),
        "app_name": meta.get("app_name", ""),
        "goal": "incident_escalation",
        "decision": _to_str(data.get("decision") or ""),
        "reason": _to_str(data.get("reason") or "incident_created"),
        "severity": _to_str(data.get("severity") or "medium"),
        "category": _to_str(data.get("category") or "unknown_incident"),
        "error": error_message,
        "error_message": error_message,
        "incident_code": _to_str(
            data.get("incident_code")
            or data.get("incidentcode")
            or "",
        ),
        "final_failure": final_failure,
        "original_capability": _to_str(
            data.get("original_capability")
            or data.get("originalcapability")
            or failed_capability
            or ""
        ),
        "failed_capability": failed_capability,
        "failed_url": _to_str(
            data.get("failed_url")
            or data.get("failedurl")
            or data.get("target_url")
            or data.get("targeturl")
            or "",
        ),
        "target_url": _to_str(
            data.get("target_url")
            or data.get("targeturl")
            or data.get("failed_url")
            or data.get("failedurl")
            or "",
        ),
        "failed_method": _to_str(
            data.get("failed_method")
            or data.get("failedmethod")
            or data.get("method")
            or "",
        ).upper(),
        "method": _to_str(
            data.get("method")
            or data.get("failed_method")
            or data.get("failedmethod")
            or "",
        ).upper(),
        "retry_count": _to_int(
            data.get("retry_count")
            if data.get("retry_count") is not None
            else data.get("retrycount"),
            0,
        ),
        "retry_max": _to_int(
            data.get("retry_max")
            if data.get("retry_max") is not None
            else data.get("retrymax"),
            0,
        ),
        "http_status": _to_int(
            data.get("http_status")
            if data.get("http_status") is not None
            else data.get("httpstatus"),
            0,
        ),
        "incident_record_id": incident_record_id,
        "log_record_id": _to_str(
            data.get("log_record_id") or data.get("logrecordid") or ""
        ),
        "run_record_id": effective_run_record_id,
        "linked_run": effective_run_record_id,
        "command_id": effective_command_id,
        "linked_command": effective_command_id,
        "incident_key": incident_key,
        "deduplicate_action": deduplicate_action,
        "parent_command_id": effective_command_id,
    }

    return {
        "ok": True,
        "capability": "incident_create",
        "status": "done",
        "flow_id": effective_flow_id,
        "root_event_id": effective_root_event_id,
        "incident_record_id": incident_record_id,
        "message": "incident_created",
        "run_record_id": effective_run_record_id,
        "command_id": effective_command_id,
        "next_commands": [
            {
                "capability": "internal_escalate",
                "priority": 1,
                "input": next_input,
            }
        ],
        "terminal": False,
        "spawn_summary": {
            "ok": True,
            "spawned": 1,
            "skipped": 0,
            "errors": [],
        },
    }
