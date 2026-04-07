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
    flow_id = _to_str(
        payload.get("flow_id")
        or payload.get("flowid")
        or payload.get("flowId")
        or ""
    ).strip()

    root_event_id = _to_str(
        payload.get("root_event_id")
        or payload.get("rooteventid")
        or payload.get("rootEventId")
        or payload.get("event_id")
        or payload.get("eventid")
        or payload.get("eventId")
        or ""
    ).strip()

    if not flow_id and root_event_id:
        flow_id = root_event_id

    if not root_event_id and flow_id:
        root_event_id = flow_id

    source_event_id = _to_str(
        payload.get("source_event_id")
        or payload.get("sourceeventid")
        or payload.get("sourceEventId")
        or payload.get("event_id")
        or payload.get("eventid")
        or payload.get("eventId")
        or root_event_id
        or flow_id
        or ""
    ).strip()

    workspace_id = _to_str(
        payload.get("workspace_id")
        or payload.get("workspaceid")
        or payload.get("workspaceId")
        or payload.get("Workspace_ID")
        or payload.get("workspace")
        or "production"
    ).strip()

    run_record_id = _to_str(
        payload.get("run_record_id")
        or payload.get("runrecordid")
        or payload.get("runRecordId")
        or payload.get("linked_run")
        or payload.get("linkedrun")
        or payload.get("Linked_Run")
        or ""
    ).strip()

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "parent_command_id": _to_str(
            payload.get("parent_command_id")
            or payload.get("parentcommandid")
            or payload.get("parentcommand_id")
            or payload.get("parentCommandId")
            or ""
        ).strip(),
        "command_id": _to_str(
            payload.get("command_id")
            or payload.get("commandid")
            or payload.get("commandId")
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
            payload.get("_depth")
            if payload.get("_depth") is not None
            else payload.get("depth"),
            0,
        ),
        "workspace_id": workspace_id,
        "run_record_id": run_record_id,
        "linked_run": run_record_id,
    }


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
            if not decision_reason:
                decision_reason = "explicit_internal_escalate"

        elif next_action == "resolve_incident":
            decision_status = "Resolved"
            if not decision_reason:
                decision_reason = "explicit_resolve_incident"

        elif (
            not final_failure
            and severity in {"low", "medium"}
            and sla_status != "breached"
        ):
            decision_status = "Resolved"
            next_action = "resolve_incident"
            auto_executable = True
            if not decision_reason:
                decision_reason = "auto_resolve_non_final_low_or_medium"

        elif final_failure and (
            category == "http_failure"
            or reason in {"http_5xx_exhausted", "http_status_error", "forbidden_host"}
            or http_status >= 500
            or severity in {"high", "critical"}
            or sla_status == "breached"
        ):
            decision_status = "Escalate"
            next_action = "internal_escalate"
            auto_executable = True
            if not decision_reason:
                decision_reason = "escalate_final_failure_or_severe"

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


def _canonical_incident_context(
    data: Dict[str, Any],
    meta: Dict[str, Any],
    runtime_run_record_id: str,
    next_step_index: int,
    next_depth: int,
    decision_block: Dict[str, Any],
) -> Dict[str, Any]:
    run_record_id = _to_str(meta.get("run_record_id") or runtime_run_record_id).strip()
    linked_run = _to_str(meta.get("linked_run") or run_record_id).strip()

    flow_id = _to_str(meta.get("flow_id") or "").strip()
    root_event_id = _to_str(meta.get("root_event_id") or "").strip()
    source_event_id = _to_str(meta.get("source_event_id") or "").strip()

    if not flow_id and root_event_id:
        flow_id = root_event_id
    if not root_event_id and flow_id:
        root_event_id = flow_id
    if not source_event_id:
        source_event_id = root_event_id or flow_id

    workspace_id = _to_str(meta.get("workspace_id") or "production").strip()

    original_capability = _to_str(
        data.get("original_capability")
        or data.get("failed_capability")
        or data.get("source_capability")
        or "http_exec"
    ).strip()

    failed_capability = _to_str(
        data.get("failed_capability")
        or data.get("original_capability")
        or data.get("source_capability")
        or original_capability
    ).strip()

    method = _to_str(
        data.get("failed_method")
        or data.get("method")
        or "GET"
    ).upper().strip()

    target_url = _to_str(
        data.get("failed_url")
        or data.get("target_url")
        or data.get("targeturl")
        or data.get("url")
        or data.get("http_target")
        or ""
    ).strip()

    http_status = (
        data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus")
        if data.get("httpstatus") is not None
        else data.get("status_code")
    )

    status_code = (
        data.get("status_code")
        if data.get("status_code") is not None
        else data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus")
    )

    request_obj = data.get("request") if isinstance(data.get("request"), dict) else {}
    response_obj = data.get("response") if isinstance(data.get("response"), dict) else {}
    original_input = data.get("original_input") if isinstance(data.get("original_input"), dict) else {}

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "event_id": source_event_id,
        "workspace_id": workspace_id,
        "workspace": workspace_id,
        "run_record_id": run_record_id,
        "linked_run": linked_run,
        "parent_command_id": _to_str(
            meta.get("parent_command_id")
            or data.get("parent_command_id")
            or data.get("parentcommandid")
            or ""
        ).strip(),
        "command_id": _to_str(
            meta.get("command_id")
            or data.get("command_id")
            or data.get("commandid")
            or ""
        ).strip(),
        "step_index": next_step_index,
        "_depth": next_depth,
        "decision_status": decision_block["decision_status"],
        "decision_reason": decision_block["decision_reason"],
        "next_action": decision_block["next_action"],
        "auto_executable": decision_block["auto_executable"],
        "priority_score": decision_block["priority_score"],
        "category": _to_str(data.get("category") or "http_failure").strip(),
        "reason": _to_str(
            data.get("reason")
            or data.get("incident_code")
            or data.get("decision_reason")
            or "incident"
        ).strip(),
        "severity": _to_str(data.get("severity") or "").strip(),
        "final_failure": _to_bool(
            data.get("final_failure")
            if data.get("final_failure") is not None
            else data.get("finalfailure"),
            False,
        ),
        "original_capability": original_capability,
        "failed_capability": failed_capability,
        "source_capability": _to_str(data.get("source_capability") or original_capability).strip(),
        "failed_method": method,
        "method": method,
        "failed_url": target_url,
        "target_url": target_url,
        "url": target_url,
        "http_target": target_url,
        "http_status": http_status,
        "status_code": status_code,
        "incident_code": _to_str(
            data.get("incident_code")
            or data.get("incidentcode")
            or data.get("reason")
            or "http_status_error"
        ).strip(),
        "goal": _to_str(
            data.get("goal")
            or data.get("failed_goal")
            or ""
        ).strip(),
        "retry_reason": _to_str(data.get("retry_reason") or data.get("reason") or "").strip(),
        "retry_count": _to_int(data.get("retry_count"), 0),
        "retry_max": _to_int(data.get("retry_max"), 0),
        "error": _to_str(data.get("error") or "").strip(),
        "error_message": _to_str(data.get("error_message") or "").strip(),
        "incident_message": _to_str(
            data.get("incident_message")
            or data.get("error_message")
            or data.get("error")
            or ""
        ).strip(),
        "source": _to_str(data.get("source") or "").strip(),
        "tenant_id": _to_str(data.get("tenant_id") or "").strip(),
        "app_name": _to_str(data.get("app_name") or "").strip(),
        "endpoint_name": _to_str(data.get("endpoint_name") or "").strip(),
        "request": request_obj,
        "response": response_obj,
        "original_input": original_input,
    }


def _build_incident_key(data: Dict[str, Any], meta: Dict[str, Any]) -> str:
    flow_id = _to_str(meta.get("flow_id") or "no_flow").strip()
    root_event_id = _to_str(meta.get("root_event_id") or "no_root").strip()
    capability = _to_str(
        data.get("original_capability")
        or data.get("failed_capability")
        or data.get("source_capability")
        or "no_capability"
    ).strip()
    method = _to_str(
        data.get("failed_method")
        or data.get("method")
        or "GET"
    ).upper().strip()
    target_url = _to_str(
        data.get("failed_url")
        or data.get("target_url")
        or data.get("targeturl")
        or data.get("url")
        or data.get("http_target")
        or ""
    ).strip()
    http_status = _to_str(
        data.get("http_status")
        or data.get("httpstatus")
        or data.get("status_code")
        or "0"
    ).strip()
    incident_code = _to_str(
        data.get("incident_code")
        or data.get("incidentcode")
        or "no_incident_code"
    ).strip().lower()
    reason = _to_str(
        data.get("reason")
        or data.get("decision_reason")
        or "no_reason"
    ).strip().lower()
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

    run_record_id = _to_str(meta.get("run_record_id") or "").strip()
    parent_command_id = _to_str(
        meta.get("parent_command_id")
        or data.get("parent_command_id")
        or data.get("parentcommandid")
        or ""
    ).strip()

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
            "Flow_ID": _to_str(meta.get("flow_id") or "").strip(),
            "Root_Event_ID": _to_str(meta.get("root_event_id") or "").strip(),
            "Source_Event_ID": _to_str(meta.get("source_event_id") or "").strip(),
            "Payload_JSON": _safe_json(data),
        },
        {
            "Last_Seen_At": now_ts,
            "Updated_At": now_ts,
            "Run_Record_ID": run_record_id,
            "Command_ID": parent_command_id,
            "Flow_ID": _to_str(meta.get("flow_id") or "").strip(),
            "Root_Event_ID": _to_str(meta.get("root_event_id") or "").strip(),
            "Source_Event_ID": _to_str(meta.get("source_event_id") or "").strip(),
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

    incident_key = _to_str(data.get("incident_key")).strip() or _build_incident_key(
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
        existing_id = _to_str(existing.get("id")).strip()

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
