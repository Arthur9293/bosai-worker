from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional


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


def _escape_airtable_formula_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


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
            for key in ("id", "name", "value", "text", "url", "method", "status_code"):
                if key in value:
                    text = _pick_text(value.get(key))
                    if text:
                        return text
            continue

        text = _to_str(value).strip()
        if text:
            return text

    return ""


def _pick_int(*values: Any) -> Optional[int]:
    for value in values:
        if value is None or value == "":
            continue
        try:
            return int(value)
        except Exception:
            try:
                return int(str(value).strip())
            except Exception:
                continue
    return None


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
    flow_id = _pick_text(
        payload.get("flow_id"),
        payload.get("flowid"),
        payload.get("flowId"),
    )

    event_id = _pick_text(
        payload.get("event_id"),
        payload.get("eventid"),
        payload.get("eventId"),
    )

    root_event_id = _pick_text(
        payload.get("root_event_id"),
        payload.get("rooteventid"),
        payload.get("rootEventId"),
        event_id,
        flow_id,
    )

    source_event_id = _pick_text(
        payload.get("source_event_id"),
        payload.get("sourceeventid"),
        payload.get("sourceEventId"),
        event_id,
        root_event_id,
        flow_id,
    )

    workspace_id = _pick_text(
        payload.get("workspace_id"),
        payload.get("workspaceid"),
        payload.get("workspaceId"),
        payload.get("Workspace_ID"),
        payload.get("workspace"),
        "production",
    )

    run_record_id = _pick_text(
        payload.get("run_record_id"),
        payload.get("runrecordid"),
        payload.get("runRecordId"),
        payload.get("linked_run"),
        payload.get("linkedrun"),
        payload.get("Linked_Run"),
    )

    return {
        "flow_id": flow_id or root_event_id or source_event_id,
        "root_event_id": root_event_id or source_event_id or flow_id,
        "source_event_id": source_event_id or root_event_id or flow_id,
        "parent_command_id": _pick_text(
            payload.get("parent_command_id"),
            payload.get("parentcommandid"),
            payload.get("parentcommand_id"),
            payload.get("parentCommandId"),
        ),
        "command_id": _pick_text(
            payload.get("command_id"),
            payload.get("commandid"),
            payload.get("commandId"),
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
            payload.get("_depth")
            if payload.get("_depth") is not None
            else payload.get("depth"),
            0,
        ),
        "workspace_id": workspace_id or "production",
        "run_record_id": run_record_id,
        "linked_run": run_record_id,
    }


def _normalize_decision_block(data: Dict[str, Any]) -> Dict[str, Any]:
    decision_status = _pick_text(
        data.get("decision_status"),
        data.get("decisionstatus"),
    )

    decision_reason = _pick_text(
        data.get("decision_reason"),
        data.get("decisionreason"),
    )

    next_action = _pick_text(
        data.get("next_action"),
        data.get("nextaction"),
    )

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

    severity = _pick_text(data.get("severity")).lower()
    category = _pick_text(data.get("category")).lower()
    reason = _pick_text(data.get("reason"), data.get("retry_reason"), data.get("incident_code")).lower()
    sla_status = _pick_text(data.get("sla_status")).lower()

    http_status = _pick_int(
        data.get("http_status"),
        data.get("httpstatus"),
        data.get("status_code"),
        data.get("statuscode"),
        (data.get("response") or {}).get("status_code") if isinstance(data.get("response"), dict) else None,
    )

    input_final_failure = _to_bool(
        data.get("final_failure")
        if data.get("final_failure") is not None
        else data.get("finalfailure"),
        False,
    )

    severe_http_failure = (
        category == "http_failure"
        or reason in {"http_5xx_exhausted", "http_status_error", "forbidden_host", "retry_exhausted", "retry_limit_reached"}
        or (http_status is not None and http_status >= 500)
        or severity in {"high", "critical"}
        or sla_status == "breached"
    )

    normalized_final_failure = input_final_failure or severe_http_failure

    if not decision_status:
        if next_action == "internal_escalate":
            decision_status = "Escalate"
            if not decision_reason:
                decision_reason = "explicit_internal_escalate"

        elif next_action == "resolve_incident":
            decision_status = "Resolved"
            if not decision_reason:
                decision_reason = "explicit_resolve_incident"

        elif severe_http_failure:
            decision_status = "Escalate"
            next_action = "internal_escalate"
            auto_executable = True
            if not decision_reason:
                decision_reason = "escalate_failure_or_severe_signal"

        elif (
            not normalized_final_failure
            and severity in {"low", "medium"}
            and sla_status != "breached"
            and (http_status is None or http_status < 500)
        ):
            decision_status = "Resolved"
            next_action = "resolve_incident"
            auto_executable = True
            if not decision_reason:
                decision_reason = "auto_resolve_non_final_low_or_medium"

        elif severity == "low":
            decision_status = "No_Action"
            if not next_action:
                next_action = "complete_flow_incident"
            if not decision_reason:
                decision_reason = "low_severity_no_action"

        else:
            decision_status = "Monitor"
            if not next_action:
                next_action = "complete_flow_incident"
            if not decision_reason:
                decision_reason = "default_monitor"

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
            elif severity == "high" or (http_status is not None and http_status >= 500):
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
        "normalized_final_failure": normalized_final_failure,
    }


def _canonical_incident_context(
    data: Dict[str, Any],
    meta: Dict[str, Any],
    runtime_run_record_id: str,
    next_step_index: int,
    next_depth: int,
    decision_block: Dict[str, Any],
) -> Dict[str, Any]:
    request_obj = data.get("request") if isinstance(data.get("request"), dict) else {}
    response_obj = data.get("response") if isinstance(data.get("response"), dict) else {}
    original_input = data.get("original_input") if isinstance(data.get("original_input"), dict) else {}

    flow_id = _pick_text(
        meta.get("flow_id"),
        data.get("flow_id"),
        data.get("flowid"),
        data.get("flowId"),
        meta.get("root_event_id"),
        meta.get("source_event_id"),
    )

    root_event_id = _pick_text(
        meta.get("root_event_id"),
        data.get("root_event_id"),
        data.get("rooteventid"),
        data.get("rootEventId"),
        data.get("event_id"),
        data.get("eventid"),
        data.get("eventId"),
        meta.get("source_event_id"),
        flow_id,
    )

    source_event_id = _pick_text(
        meta.get("source_event_id"),
        data.get("source_event_id"),
        data.get("sourceeventid"),
        data.get("sourceEventId"),
        data.get("event_id"),
        data.get("eventid"),
        data.get("eventId"),
        root_event_id,
        flow_id,
    )

    workspace_id = _pick_text(
        meta.get("workspace_id"),
        data.get("workspace_id"),
        data.get("workspaceid"),
        data.get("workspaceId"),
        data.get("workspace"),
        "production",
    )

    run_record_id = _pick_text(
        meta.get("run_record_id"),
        data.get("run_record_id"),
        data.get("runrecordid"),
        data.get("linked_run"),
        data.get("linkedrun"),
        runtime_run_record_id,
    )

    linked_run = _pick_text(
        meta.get("linked_run"),
        data.get("linked_run"),
        data.get("linkedrun"),
        run_record_id,
    )

    original_capability = _pick_text(
        data.get("original_capability"),
        data.get("failed_capability"),
        data.get("source_capability"),
        "http_exec",
    )

    failed_capability = _pick_text(
        data.get("failed_capability"),
        data.get("original_capability"),
        data.get("source_capability"),
        original_capability,
    )

    source_capability = _pick_text(
        data.get("source_capability"),
        original_capability,
        failed_capability,
    )

    method = _pick_text(
        data.get("failed_method"),
        data.get("method"),
        request_obj.get("method"),
        original_input.get("method"),
        "GET",
    ).upper()

    target_url = _pick_text(
        data.get("failed_url"),
        data.get("target_url"),
        data.get("targeturl"),
        data.get("url"),
        data.get("http_target"),
        original_input.get("url"),
        original_input.get("http_target"),
        request_obj.get("url"),
    )

    http_status = _pick_int(
        data.get("http_status"),
        data.get("httpstatus"),
        data.get("status_code"),
        data.get("statuscode"),
        response_obj.get("status_code"),
    )

    status_code = _pick_int(
        data.get("status_code"),
        data.get("statuscode"),
        data.get("http_status"),
        data.get("httpstatus"),
        response_obj.get("status_code"),
    )

    severity = _pick_text(
        data.get("severity"),
        "high" if http_status is not None and http_status >= 500 else "",
    )

    category = _pick_text(
        data.get("category"),
        "http_failure" if target_url else "",
    )

    reason = _pick_text(
        data.get("reason"),
        data.get("retry_reason"),
        data.get("incident_code"),
        data.get("incidentcode"),
        data.get("error"),
        "incident",
    )

    incident_code = _pick_text(
        data.get("incident_code"),
        data.get("incidentcode"),
        data.get("reason"),
        "http_status_error",
    )

    error = _pick_text(
        data.get("error"),
        data.get("error_message"),
    )

    error_message = _pick_text(
        data.get("error_message"),
        data.get("incident_message"),
        data.get("error"),
    )

    normalized_final_failure = _to_bool(
        decision_block.get("normalized_final_failure"),
        False,
    )

    return {
        **data,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "event_id": source_event_id,
        "workspace_id": workspace_id,
        "workspace": workspace_id,
        "run_record_id": run_record_id,
        "linked_run": linked_run,
        "parent_command_id": _pick_text(
            meta.get("parent_command_id"),
            data.get("parent_command_id"),
            data.get("parentcommandid"),
        ),
        "command_id": _pick_text(
            meta.get("command_id"),
            data.get("command_id"),
            data.get("commandid"),
        ),
        "step_index": next_step_index,
        "_depth": next_depth,
        "decision_status": decision_block["decision_status"],
        "decision_reason": decision_block["decision_reason"],
        "next_action": decision_block["next_action"],
        "auto_executable": decision_block["auto_executable"],
        "priority_score": decision_block["priority_score"],
        "category": category,
        "reason": reason,
        "severity": severity,
        "final_failure": normalized_final_failure,
        "original_capability": original_capability,
        "failed_capability": failed_capability,
        "source_capability": source_capability,
        "failed_method": method,
        "method": method,
        "failed_url": target_url,
        "target_url": target_url,
        "url": target_url,
        "http_target": target_url,
        "http_status": http_status,
        "status_code": status_code,
        "incident_code": incident_code,
        "goal": _pick_text(
            data.get("goal"),
            data.get("failed_goal"),
            original_input.get("goal"),
        ),
        "error": error,
        "error_message": error_message,
        "incident_message": _pick_text(
            data.get("incident_message"),
            error_message,
            error,
        ),
        "request": request_obj,
        "response": response_obj,
        "original_input": original_input,
        "retry_reason": _pick_text(data.get("retry_reason"), reason),
        "retry_count": _to_int(data.get("retry_count"), 0),
        "retry_max": _to_int(data.get("retry_max"), 0),
        "tenant_id": _pick_text(data.get("tenant_id")),
        "app_name": _pick_text(data.get("app_name")),
        "source": _pick_text(data.get("source")),
        "incident_record_id": _pick_text(data.get("incident_record_id")),
        "log_record_id": _pick_text(data.get("log_record_id")),
        "endpoint_name": _pick_text(data.get("endpoint_name"), original_input.get("endpoint_name")),
    }


def _build_incident_key(data: Dict[str, Any], meta: Dict[str, Any]) -> str:
    flow_id = _pick_text(meta.get("flow_id"), "no_flow")
    root_event_id = _pick_text(meta.get("root_event_id"), "no_root")
    capability = _pick_text(
        data.get("original_capability"),
        data.get("failed_capability"),
        data.get("source_capability"),
        "no_capability",
    )
    method = _pick_text(
        data.get("failed_method"),
        data.get("method"),
        "GET",
    ).upper()
    target_url = _pick_text(
        data.get("failed_url"),
        data.get("target_url"),
        data.get("url"),
        data.get("http_target"),
    )
    http_status = _pick_text(
        data.get("http_status"),
        data.get("httpstatus"),
        data.get("status_code"),
        "0",
    )
    incident_code = _pick_text(
        data.get("incident_code"),
        data.get("incidentcode"),
        "no_incident_code",
    ).lower()
    reason = _pick_text(
        data.get("reason"),
        data.get("decision_reason"),
        "no_reason",
    ).lower()
    final_flag = "final" if _to_bool(
        data.get("final_failure")
        if data.get("final_failure") is not None
        else data.get("finalfailure"),
        False,
    ) else "not_final"

    return "|".join(
        [
            flow_id or "no_flow",
            root_event_id or "no_root",
            capability or "no_capability",
            method or "GET",
            target_url,
            http_status or "0",
            incident_code or "no_incident_code",
            reason or "no_reason",
            final_flag,
        ]
    )


def _find_existing_incident(
    incidents_table_name: str,
    incident_key: str,
    airtable_list_filtered,
) -> Optional[Dict[str, Any]]:
    try:
        safe_key = _escape_airtable_formula_value(incident_key)
        recs = airtable_list_filtered(
            incidents_table_name,
            formula=f"{{Incident_Key}}='{safe_key}'",
            max_records=1,
        )
        if isinstance(recs, list) and recs:
            return recs[0]
    except Exception:
        pass

    return None


def _update_existing_incident_best_effort(
    *,
    airtable_update,
    incidents_table_name: str,
    existing_id: str,
    meta: Dict[str, Any],
    data: Dict[str, Any],
) -> Dict[str, Any]:
    now_ts = _now_ts()

    run_record_id = _pick_text(meta.get("run_record_id"))
    parent_command_id = _pick_text(
        meta.get("parent_command_id"),
        data.get("parent_command_id"),
        data.get("parentcommandid"),
    )

    linked_run = [run_record_id] if run_record_id.startswith("rec") else []
    linked_command = [parent_command_id] if parent_command_id.startswith("rec") else []

    attempts: List[Dict[str, Any]] = [
        {
            "Last_Seen_At": now_ts,
            "Updated_At": now_ts,
            "Occurrences_Count": 1,
            "Run_Record_ID": run_record_id,
            "Linked_Run": linked_run,
            "Command_ID": parent_command_id,
            "Linked_Command": linked_command,
            "Flow_ID": _pick_text(data.get("flow_id")),
            "Root_Event_ID": _pick_text(data.get("root_event_id")),
            "Source_Event_ID": _pick_text(data.get("source_event_id")),
            "Payload_JSON": _safe_json(data),
        },
        {
            "Last_Seen_At": now_ts,
            "Updated_At": now_ts,
            "Run_Record_ID": run_record_id,
            "Command_ID": parent_command_id,
            "Flow_ID": _pick_text(data.get("flow_id")),
            "Root_Event_ID": _pick_text(data.get("root_event_id")),
            "Source_Event_ID": _pick_text(data.get("source_event_id")),
        },
        {
            "Last_Seen_At": now_ts,
            "Updated_At": now_ts,
        },
    ]

    results: List[Dict[str, Any]] = []
    seen = set()

    for fields in attempts:
        clean_fields = {k: v for k, v in fields.items() if v not in ("", None, [])}
        signature = tuple(sorted(clean_fields.keys()))
        if not clean_fields or signature in seen:
            continue
        seen.add(signature)

        try:
            res = airtable_update(incidents_table_name, existing_id, clean_fields)
            results.append({"ok": True, "fields": clean_fields, "response": res})
            return {
                "ok": True,
                "fields": clean_fields,
                "attempts": results,
            }
        except Exception as exc:
            results.append(
                {
                    "ok": False,
                    "fields": clean_fields,
                    "error": repr(exc),
                }
            )

    return {
        "ok": False,
        "attempts": results,
    }


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    *,
    airtable_list_filtered,
    airtable_update,
    incidents_table_name: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    payload = getattr(req, "input", {}) if hasattr(req, "input") else req or {}
    data = _extract_input(payload)
    meta = _extract_meta(data)

    depth = _to_int(meta.get("depth"), 0)
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "incident_deduplicate",
            "error": "max_depth_reached",
            "terminal": True,
        }

    decision_block = _normalize_decision_block(data)

    canonical_for_key = _canonical_incident_context(
        data=data,
        meta=meta,
        runtime_run_record_id=run_record_id,
        next_step_index=_to_int(meta.get("step_index"), 0) + 1,
        next_depth=depth + 1,
        decision_block=decision_block,
    )

    incident_key = _pick_text(data.get("incident_key")) or _build_incident_key(
        canonical_for_key,
        {
            **meta,
            "flow_id": canonical_for_key.get("flow_id", ""),
            "root_event_id": canonical_for_key.get("root_event_id", ""),
        },
    )

    existing = _find_existing_incident(
        incidents_table_name,
        incident_key,
        airtable_list_filtered,
    )

    if existing:
        existing_id = _pick_text(existing.get("id"))

        update_res = _update_existing_incident_best_effort(
            airtable_update=airtable_update,
            incidents_table_name=incidents_table_name,
            existing_id=existing_id,
            meta=meta,
            data=canonical_for_key,
        )

        next_input = {
            **canonical_for_key,
            "incident_record_id": existing_id,
            "incident_key": incident_key,
            "deduplicate_action": "existing_found",
        }

        next_commands: List[Dict[str, Any]] = []

        if decision_block["next_action"] == "internal_escalate":
            next_commands.append(
                {
                    "capability": "internal_escalate",
                    "priority": 1,
                    "input": next_input,
                }
            )
        elif decision_block["next_action"] == "resolve_incident":
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
            "capability": "incident_deduplicate",
            "status": "done",
            "flow_id": canonical_for_key.get("flow_id", ""),
            "root_event_id": canonical_for_key.get("root_event_id", ""),
            "source_event_id": canonical_for_key.get("source_event_id", ""),
            "workspace_id": canonical_for_key.get("workspace_id", ""),
            "run_record_id": canonical_for_key.get("run_record_id", ""),
            "linked_run": canonical_for_key.get("linked_run", ""),
            "incident_exists": True,
            "incident_record_id": existing_id,
            "incident_key": incident_key,
            "action": "reuse_existing",
            "decision_status": decision_block["decision_status"],
            "decision_reason": decision_block["decision_reason"],
            "next_action": decision_block["next_action"],
            "auto_executable": decision_block["auto_executable"],
            "priority_score": decision_block["priority_score"],
            "update_ok": bool(update_res.get("ok")),
            "update_res": update_res,
            "next_commands": next_commands,
            "terminal": False,
            "spawn_summary": {
                "ok": True,
                "spawned": len(next_commands),
                "skipped": 0,
                "errors": [],
            },
        }

    create_input = {
        **canonical_for_key,
        "incident_key": incident_key,
        "deduplicate_action": "create_new",
    }

    next_commands: List[Dict[str, Any]] = [
        {
            "capability": "incident_create",
            "priority": 1,
            "input": create_input,
        }
    ]

    return {
        "ok": True,
        "capability": "incident_deduplicate",
        "status": "done",
        "flow_id": canonical_for_key.get("flow_id", ""),
        "root_event_id": canonical_for_key.get("root_event_id", ""),
        "source_event_id": canonical_for_key.get("source_event_id", ""),
        "workspace_id": canonical_for_key.get("workspace_id", ""),
        "run_record_id": canonical_for_key.get("run_record_id", ""),
        "linked_run": canonical_for_key.get("linked_run", ""),
        "incident_exists": False,
        "incident_record_id": "",
        "incident_key": incident_key,
        "action": "create_new",
        "decision_status": decision_block["decision_status"],
        "decision_reason": decision_block["decision_reason"],
        "next_action": decision_block["next_action"],
        "auto_executable": decision_block["auto_executable"],
        "priority_score": decision_block["priority_score"],
        "next_commands": next_commands,
        "terminal": False,
        "spawn_summary": {
            "ok": True,
            "spawned": len(next_commands),
            "skipped": 0,
            "errors": [],
        },
    }
