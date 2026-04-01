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
        return f"{category.upper()} | {failed_url[:80]}"

    if code and http_status:
        return f"{code} | {http_status}"

    if code:
        return code

    return "Incident"


def _normalize_decision_block(data: Dict[str, Any]) -> Dict[str, Any]:
    decision_status = _to_str(
        data.get("decision_status")
        or data.get("decisionstatus")
        or ""
    ).strip()

    decision_reason = _to_str(
        data.get("decision_reason")
        or data.get("decisionreason")
        or ""
    ).strip()

    next_action = _to_str(
        data.get("next_action")
        or data.get("nextaction")
        or ""
    ).strip()

    auto_executable = _to_bool(
        data.get("auto_executable")
        if data.get("auto_executable") is not None
        else data.get("autoexecutable"),
        False,
    )

    priority_score = _to_int(
        data.get("priority_score")
        if data.get("priority_score") is not None
        else data.get("priorityscore"),
        0,
    )

    severity = _to_str(data.get("severity") or "").strip().lower()
    category = _to_str(data.get("category") or "").strip().lower()
    reason = _to_str(data.get("reason") or "").strip().lower()
    sla_status = _to_str(data.get("sla_status") or "").strip().lower()
    final_failure = _to_bool(
        data.get("final_failure")
        if data.get("final_failure") is not None
        else data.get("finalfailure"),
        False,
    )
    http_status = _to_int(
        data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus"),
        0,
    )

    if not decision_status:
        if next_action == "internal_escalate":
            decision_status = "Escalate"
        elif next_action == "resolve_incident":
            decision_status = "Resolved"
        elif final_failure and (
            category == "http_failure"
            or reason == "http_5xx_exhausted"
            or http_status >= 500
            or severity in {"high", "critical"}
            or sla_status == "breached"
        ):
            decision_status = "Escalate"
        elif severity in {"low"}:
            decision_status = "No_Action"
        else:
            decision_status = "Monitor"

    normalized_decision_status = decision_status.strip().lower()

    if not next_action:
        if normalized_decision_status in {"escalate", "escalated"}:
            next_action = "internal_escalate"
        elif normalized_decision_status in {"resolved", "resolve"}:
            next_action = "resolve_incident"
        else:
            next_action = "complete_flow_incident"

    if not auto_executable and next_action in {"internal_escalate", "resolve_incident"}:
        auto_executable = True

    if priority_score <= 0:
        if next_action == "internal_escalate":
            if severity == "critical" or sla_status == "breached":
                priority_score = 95
            elif severity == "high":
                priority_score = 80
            else:
                priority_score = 70
        elif next_action == "resolve_incident":
            priority_score = 20
        else:
            priority_score = 10

    return {
        "decision_status": decision_status,
        "decision_reason": decision_reason,
        "next_action": next_action,
        "auto_executable": auto_executable,
        "priority_score": priority_score,
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

    data = _extract_input(payload)
    meta = _extract_meta(data)

    depth = _to_int(meta.get("depth"), 0)
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "incident_create",
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

    linked_run_ids = [effective_run_record_id] if effective_run_record_id.startswith("rec") else []
    linked_command_ids = [effective_command_id] if effective_command_id.startswith("rec") else []

    effective_flow_id = _to_str(meta.get("flow_id", "")).strip()
    effective_root_event_id = _to_str(meta.get("root_event_id", "")).strip()

    error_message = _to_str(
        data.get("error")
        or data.get("error_message")
        or data.get("errormessage")
        or ""
    ).strip()

    incident_key = _to_str(data.get("incident_key") or "").strip()
    deduplicate_action = _to_str(data.get("deduplicate_action") or "").strip()

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
    ).strip()

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
        "Failed_Capability": failed_capability,
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
        "Error_Message": error_message,
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
        "Incident_Key": incident_key,
        "Last_Seen_At": now_ts,
        "Occurrences_Count": 1,
        "Deduplicate_Action": deduplicate_action,
        "Final_Failure": final_failure,
        "SLA_Status": "Open",
    }

    clean_fields = {k: v for k, v in incident_fields.items() if v not in ("", None, [])}

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

        # ------------------------------------------------------------
        # LINK INCIDENT -> MONITORED ENDPOINT
        # ------------------------------------------------------------
        try:
            endpoint_name = _to_str(
                data.get("endpoint_name")
                or data.get("endpoint")
                or ""
            ).strip()

            if endpoint_name and incident_record_id and callable(airtable_update_by_field):
                airtable_update_by_field(
                    table="Monitored_Endpoints",
                    field="Name",
                    value=endpoint_name,
                    fields={
                        "Last_Incident_ID": incident_record_id,
                        "Last_Error": _to_str(data.get("reason") or ""),
                        "Last_Check_At": now_ts,
                    },
                )
                print("[incident_create] linked to Monitored_Endpoints =", endpoint_name, flush=True)
            else:
                print(
                    "[incident_create] skip monitored_endpoints update (missing helper or endpoint_name)",
                    flush=True,
                )

        except Exception as e:
            print("[incident_create] monitored_endpoints_update_error =", str(e), flush=True)

    except Exception as e:
        return {
            "ok": False,
            "capability": "incident_create",
            "error": f"incident_create_failed:{repr(e)}",
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

    if not effective_flow_id and incident_record_id:
        effective_flow_id = f"flow_{incident_record_id}"

    if not effective_root_event_id:
        effective_root_event_id = effective_flow_id

    decision_block = _normalize_decision_block(data)
    decision_status = decision_block["decision_status"]
    decision_reason = decision_block["decision_reason"]
    next_action = decision_block["next_action"]
    auto_executable = decision_block["auto_executable"]
    priority_score = decision_block["priority_score"]

    next_input = {
        "flow_id": effective_flow_id,
        "root_event_id": effective_root_event_id,
        "event_id": effective_root_event_id,
        "step_index": _to_int(meta.get("step_index"), 0) + 1,
        "_depth": depth + 1,
        "workspace_id": meta.get("workspace_id", ""),
        "workspace": meta.get("workspace_id", ""),
        "tenant_id": meta.get("tenant_id", ""),
        "app_name": meta.get("app_name", ""),
        "goal": _to_str(data.get("goal") or "incident_created"),
        "decision": _to_str(data.get("decision") or ""),
        "decision_status": decision_status,
        "decision_reason": decision_reason,
        "next_action": next_action,
        "auto_executable": auto_executable,
        "priority_score": priority_score,
        "reason": _to_str(data.get("reason") or "incident_created"),
        "severity": _to_str(data.get("severity") or "medium"),
        "category": _to_str(data.get("category") or "unknown_incident"),
        "sla_status": _to_str(data.get("sla_status") or ""),
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
        "http_target": _to_str(
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
        "parent_command_id": parent_command_id or effective_command_id,
    }

    next_commands = []

    if next_action == "internal_escalate":
        next_commands.append(
            {
                "capability": "internal_escalate",
                "priority": 1,
                "input": next_input,
            }
        )
    elif next_action == "resolve_incident":
        next_commands.append(
            {
                "capability": "resolve_incident",
                "priority": 1,
                "input": next_input,
            }
        )
    else:
        next_commands.append(
            {
                "capability": "complete_flow_incident",
                "priority": 1,
                "input": next_input,
            }
        )

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
        "decision_status": decision_status,
        "decision_reason": decision_reason,
        "next_action": next_action,
        "auto_executable": auto_executable,
        "priority_score": priority_score,
        "next_commands": next_commands,
        "terminal": False,
        "spawn_summary": {
            "ok": True,
            "spawned": len(next_commands),
            "skipped": 0,
            "errors": [],
        },
    }
