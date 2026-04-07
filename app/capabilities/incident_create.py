from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional


DEFAULT_MAX_DEPTH = 8

ORCHESTRATION_CAPABILITIES = {
    "incident_deduplicate",
    "incident_create",
    "complete_flow_incident",
    "resolve_incident",
    "internal_escalate",
    "incident_router_v2",
    "incident_router",
    "decision_router",
    "retry_router",
    "complete_flow",
    "complete_flow_demo",
}


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


def _json_load_maybe(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    candidates = [text]

    try:
        candidates.append(bytes(text, "utf-8").decode("unicode_escape"))
    except Exception:
        pass

    candidates.append(text.replace('\\"', '"'))
    candidates.append(text.replace("\\_", "_"))
    candidates.append(text.replace('\\"', '"').replace("\\_", "_"))

    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)

        try:
            parsed = json.loads(candidate)
        except Exception:
            continue

        if isinstance(parsed, str):
            inner = parsed.strip()
            if not inner:
                continue
            try:
                parsed2 = json.loads(inner)
                return parsed2
            except Exception:
                return parsed

        return parsed

    return None


def _normalize_keys_deep(value: Any) -> Any:
    mapping = {
        "commandinput": "command_input",
        "targetcapability": "target_capability",
        "originalinput": "original_input",
        "retrycount": "retry_count",
        "retrymax": "retry_max",
        "stepindex": "step_index",
        "maxdepth": "max_depth",
        "workspaceid": "workspace_id",
        "rooteventid": "root_event_id",
        "sourceeventid": "source_event_id",
        "eventid": "event_id",
        "flowid": "flow_id",
        "incidentrecordid": "incident_record_id",
        "requesterror": "request_error",
        "httptarget": "http_target",
        "httpstatus": "http_status",
        "retryreason": "retry_reason",
        "errortype": "error_type",
        "parentcommandid": "parent_command_id",
        "statuscode": "status_code",
        "failedurl": "failed_url",
        "failedmethod": "failed_method",
        "failedgoal": "failed_goal",
        "originalcapability": "original_capability",
        "failedcapability": "failed_capability",
        "sourcecapability": "source_capability",
        "runrecordid": "run_record_id",
        "linkedrun": "linked_run",
        "commandid": "command_id",
        "incidentcode": "incident_code",
        "decisionstatus": "decision_status",
        "decisionreason": "decision_reason",
        "nextaction": "next_action",
        "priorityscore": "priority_score",
        "autoexecutable": "auto_executable",
        "finalfailure": "final_failure",
        "targeturl": "target_url",
        "endpointname": "endpoint_name",
        "errormessage": "error_message",
        "incidentmessage": "incident_message",
        "tenantid": "tenant_id",
        "appname": "app_name",
    }

    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for k, v in value.items():
            key = mapping.get(str(k), str(k))
            normalized[key] = _normalize_keys_deep(v)
        return normalized

    if isinstance(value, list):
        return [_normalize_keys_deep(item) for item in value]

    return value


def _unwrap_command_payload(value: Any) -> Any:
    if not isinstance(value, dict):
        return value

    current = dict(value)

    for key in ("input", "command_input"):
        nested = current.get(key)
        if isinstance(nested, dict):
            merged = dict(current)
            merged.pop(key, None)
            merged.update(nested)
            current = merged

    return current


def _normalize_flow_keys(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    normalized = dict(payload)

    flow_id = str(
        normalized.get("flow_id")
        or normalized.get("flowid")
        or normalized.get("flowId")
        or normalized.get("Flow_ID")
        or normalized.get("FlowId")
        or ""
    ).strip()

    event_id = str(
        normalized.get("event_id")
        or normalized.get("eventid")
        or normalized.get("eventId")
        or normalized.get("Event_ID")
        or ""
    ).strip()

    root_event_id = str(
        normalized.get("root_event_id")
        or normalized.get("rooteventid")
        or normalized.get("rootEventId")
        or normalized.get("root_eventid")
        or normalized.get("Root_Event_ID")
        or normalized.get("RootEventId")
        or ""
    ).strip()

    source_event_id = str(
        normalized.get("source_event_id")
        or normalized.get("sourceeventid")
        or normalized.get("sourceEventId")
        or normalized.get("Source_Event_ID")
        or event_id
        or root_event_id
        or flow_id
        or ""
    ).strip()

    workspace_id = str(
        normalized.get("workspace_id")
        or normalized.get("workspaceid")
        or normalized.get("workspaceId")
        or normalized.get("Workspace_ID")
        or normalized.get("workspace")
        or ""
    ).strip()

    run_record_id = str(
        normalized.get("run_record_id")
        or normalized.get("runrecordid")
        or normalized.get("runRecordId")
        or normalized.get("linked_run")
        or normalized.get("linkedrun")
        or normalized.get("Linked_Run")
        or ""
    ).strip()

    linked_run = str(
        normalized.get("linked_run")
        or normalized.get("linkedrun")
        or normalized.get("run_record_id")
        or normalized.get("runrecordid")
        or normalized.get("runRecordId")
        or ""
    ).strip()

    parent_command_id = str(
        normalized.get("parent_command_id")
        or normalized.get("parentcommandid")
        or normalized.get("parentCommandId")
        or normalized.get("Parent_Command_ID")
        or ""
    ).strip()

    command_id = str(
        normalized.get("command_id")
        or normalized.get("commandid")
        or normalized.get("commandId")
        or normalized.get("Command_ID")
        or ""
    ).strip()

    raw_step_index = (
        normalized.get("step_index")
        if normalized.get("step_index") is not None
        else normalized.get("stepindex")
        if normalized.get("stepindex") is not None
        else normalized.get("stepIndex")
        if normalized.get("stepIndex") is not None
        else normalized.get("Step_Index")
        if normalized.get("Step_Index") is not None
        else normalized.get("StepIndex")
    )

    step_index = 0
    try:
        if raw_step_index is not None and str(raw_step_index).strip() != "":
            step_index = int(raw_step_index)
    except Exception:
        step_index = 0

    raw_depth = normalized.get("_depth") if normalized.get("_depth") is not None else normalized.get("depth")
    depth = _to_int(raw_depth, 0)

    if flow_id:
        normalized["flow_id"] = flow_id
    if event_id:
        normalized["event_id"] = event_id
    if root_event_id:
        normalized["root_event_id"] = root_event_id
    elif event_id:
        normalized["root_event_id"] = event_id
    if source_event_id:
        normalized["source_event_id"] = source_event_id
    elif event_id:
        normalized["source_event_id"] = event_id
    if workspace_id:
        normalized["workspace_id"] = workspace_id
        normalized["workspace"] = workspace_id
    if run_record_id:
        normalized["run_record_id"] = run_record_id
    if linked_run:
        normalized["linked_run"] = linked_run
    elif run_record_id:
        normalized["linked_run"] = run_record_id
    if parent_command_id:
        normalized["parent_command_id"] = parent_command_id
    if command_id:
        normalized["command_id"] = command_id

    normalized["step_index"] = step_index
    normalized["_depth"] = depth

    for legacy_key in (
        "flowid",
        "flowId",
        "Flow_ID",
        "FlowId",
        "eventid",
        "eventId",
        "Event_ID",
        "rooteventid",
        "rootEventId",
        "root_eventid",
        "Root_Event_ID",
        "RootEventId",
        "sourceeventid",
        "sourceEventId",
        "Source_Event_ID",
        "workspaceid",
        "workspaceId",
        "Workspace_ID",
        "runrecordid",
        "runRecordId",
        "Run_Record_ID",
        "linkedrun",
        "Linked_Run",
        "parentcommandid",
        "parentCommandId",
        "Parent_Command_ID",
        "commandid",
        "commandId",
        "Command_ID",
        "stepindex",
        "stepIndex",
        "Step_Index",
        "StepIndex",
        "depth",
    ):
        normalized.pop(legacy_key, None)

    return normalized


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


def _pick_capability(*values: Any, fallback: str = "") -> str:
    first_non_empty = ""

    for value in values:
        text = _pick_text(value)
        if not text:
            continue

        if not first_non_empty:
            first_non_empty = text

        if text not in ORCHESTRATION_CAPABILITIES:
            return text

    return first_non_empty or fallback


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

    command_id = _pick_text(
        payload.get("command_id"),
        payload.get("commandid"),
        payload.get("commandId"),
    )

    parent_command_id = _pick_text(
        payload.get("parent_command_id"),
        payload.get("parentcommandid"),
        payload.get("parentCommandId"),
        command_id,
    )

    return {
        "flow_id": flow_id or root_event_id or source_event_id,
        "root_event_id": root_event_id or source_event_id or flow_id,
        "source_event_id": source_event_id or root_event_id or flow_id,
        "workspace_id": workspace_id or "production",
        "run_record_id": run_record_id,
        "command_id": command_id,
        "parent_command_id": parent_command_id,
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
    }


def _build_incident_name(data: Dict[str, Any]) -> str:
    category = _pick_text(data.get("category"))
    failed_url = _pick_text(
        data.get("failed_url"),
        data.get("url"),
        data.get("http_target"),
    )
    endpoint_name = _pick_text(data.get("endpoint_name"))

    if category and failed_url:
        return f"{category.upper()} | {failed_url[:80]}"

    if endpoint_name and category:
        return f"{category.upper()} | {endpoint_name[:80]}"

    return "Incident"


def _normalize_decision_block(data: Dict[str, Any]) -> Dict[str, Any]:
    decision_status = _pick_text(
        data.get("decision_status"),
        "Monitor",
    )
    decision_reason = _pick_text(data.get("decision_reason"))
    next_action = _pick_text(
        data.get("next_action"),
        "complete_flow_incident",
    )
    auto_executable = _to_bool(data.get("auto_executable"), False)
    priority_score = _to_int(data.get("priority_score"), 10)

    return {
        "decision_status": decision_status,
        "decision_reason": decision_reason,
        "next_action": next_action,
        "auto_executable": auto_executable,
        "priority_score": priority_score,
    }


def _strip_runtime_keys(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    cleaned = dict(value)

    for noisy_key in (
        "next_commands",
        "spawn_summary",
        "terminal",
        "ok",
        "status",
        "route",
        "ts",
        "action",
        "deduplicate_action",
    ):
        cleaned.pop(noisy_key, None)

    return cleaned


def _canonical_incident_context(
    data: Dict[str, Any],
    meta: Dict[str, Any],
    runtime_run_record_id: str,
    next_step_index: int,
    next_depth: int,
    decision_block: Dict[str, Any],
    incident_record_id: str = "",
) -> Dict[str, Any]:
    request_obj = data.get("request") if isinstance(data.get("request"), dict) else {}
    response_obj = data.get("response") if isinstance(data.get("response"), dict) else {}
    original_input = data.get("original_input") if isinstance(data.get("original_input"), dict) else {}

    original_input = _normalize_keys_deep(original_input)
    original_input = _unwrap_command_payload(original_input)
    original_input = _normalize_flow_keys(original_input)

    flow_id = _pick_text(
        meta.get("flow_id"),
        data.get("flow_id"),
        original_input.get("flow_id"),
    )

    root_event_id = _pick_text(
        meta.get("root_event_id"),
        data.get("root_event_id"),
        data.get("event_id"),
        original_input.get("root_event_id"),
        original_input.get("event_id"),
        flow_id,
    )

    source_event_id = _pick_text(
        meta.get("source_event_id"),
        data.get("source_event_id"),
        data.get("event_id"),
        original_input.get("source_event_id"),
        original_input.get("event_id"),
        root_event_id,
        flow_id,
    )

    workspace_id = _pick_text(
        meta.get("workspace_id"),
        data.get("workspace_id"),
        data.get("workspace"),
        original_input.get("workspace_id"),
        "production",
    )

    # IMPORTANT:
    # On garde le run hérité en priorité pour la continuité de flow,
    # puis on garde le run local seulement en dernier fallback.
    run_record_id = _pick_text(
        meta.get("run_record_id"),
        data.get("run_record_id"),
        data.get("linked_run"),
        original_input.get("run_record_id"),
        original_input.get("linked_run"),
        runtime_run_record_id,
    )

    linked_run = _pick_text(
        data.get("linked_run"),
        original_input.get("linked_run"),
        run_record_id,
    )

    target_url = _pick_text(
        data.get("failed_url"),
        data.get("target_url"),
        data.get("url"),
        data.get("http_target"),
        original_input.get("failed_url"),
        original_input.get("target_url"),
        original_input.get("url"),
        original_input.get("http_target"),
        request_obj.get("url"),
    )

    original_capability = _pick_capability(
        data.get("original_capability"),
        original_input.get("original_capability"),
        data.get("failed_capability"),
        original_input.get("failed_capability"),
        data.get("source_capability"),
        original_input.get("source_capability"),
        fallback="http_exec" if target_url else "",
    )

    failed_capability = _pick_capability(
        data.get("failed_capability"),
        original_input.get("failed_capability"),
        original_capability,
        data.get("source_capability"),
        original_input.get("source_capability"),
        fallback=original_capability,
    )

    source_capability = _pick_capability(
        data.get("source_capability"),
        original_input.get("source_capability"),
        original_capability,
        failed_capability,
        fallback=original_capability,
    )

    method = _pick_text(
        data.get("failed_method"),
        data.get("method"),
        original_input.get("failed_method"),
        original_input.get("method"),
        request_obj.get("method"),
        "GET",
    ).upper()

    http_status = _pick_int(
        data.get("http_status"),
        data.get("status_code"),
        response_obj.get("status_code"),
    )

    status_code = _pick_int(
        data.get("status_code"),
        data.get("http_status"),
        response_obj.get("status_code"),
    )

    base = _strip_runtime_keys(data)

    canonical = {
        **base,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "event_id": source_event_id,
        "workspace_id": workspace_id,
        "workspace": workspace_id,
        "run_record_id": run_record_id,
        "linked_run": linked_run or run_record_id,
        "incident_record_id": incident_record_id or _pick_text(data.get("incident_record_id")),
        "incident_key": _pick_text(data.get("incident_key")),
        "parent_command_id": _pick_text(
            meta.get("parent_command_id"),
            data.get("parent_command_id"),
        ),
        "command_id": _pick_text(
            meta.get("command_id"),
            data.get("command_id"),
        ),
        "step_index": next_step_index,
        "_depth": next_depth,
        "decision_status": decision_block["decision_status"],
        "decision_reason": decision_block["decision_reason"],
        "next_action": decision_block["next_action"],
        "auto_executable": decision_block["auto_executable"],
        "priority_score": decision_block["priority_score"],
        "category": _pick_text(data.get("category"), original_input.get("category")),
        "reason": _pick_text(data.get("reason"), original_input.get("reason")),
        "severity": _pick_text(data.get("severity"), original_input.get("severity")),
        "final_failure": _to_bool(
            data.get("final_failure")
            if data.get("final_failure") is not None
            else original_input.get("final_failure"),
            False,
        ),
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
        "incident_code": _pick_text(
            data.get("incident_code"),
            original_input.get("incident_code"),
        ),
        "goal": _pick_text(
            data.get("goal"),
            data.get("failed_goal"),
            original_input.get("goal"),
            original_input.get("failed_goal"),
        ),
        "error": _pick_text(data.get("error"), original_input.get("error")),
        "error_message": _pick_text(data.get("error_message"), original_input.get("error_message")),
        "incident_message": _pick_text(data.get("incident_message"), original_input.get("incident_message")),
        "request": request_obj,
        "response": response_obj,
        "original_input": original_input,
        "retry_reason": _pick_text(data.get("retry_reason"), original_input.get("retry_reason")),
        "retry_count": _to_int(
            data.get("retry_count")
            if data.get("retry_count") is not None
            else original_input.get("retry_count"),
            0,
        ),
        "retry_max": _to_int(
            data.get("retry_max")
            if data.get("retry_max") is not None
            else original_input.get("retry_max"),
            0,
        ),
        "tenant_id": _pick_text(data.get("tenant_id"), original_input.get("tenant_id")),
        "app_name": _pick_text(data.get("app_name"), original_input.get("app_name")),
        "source": _pick_text(data.get("source"), original_input.get("source")),
        "log_record_id": _pick_text(data.get("log_record_id")),
        "endpoint_name": _pick_text(data.get("endpoint_name"), original_input.get("endpoint_name")),
    }

    canonical = _normalize_keys_deep(canonical)
    canonical = _unwrap_command_payload(canonical)
    canonical = _normalize_flow_keys(canonical)

    return canonical


def _build_incident_fields_candidates(
    *,
    data: Dict[str, Any],
    meta: Dict[str, Any],
    incident_record_payload: Dict[str, Any],
    now_ts: str,
) -> List[Dict[str, Any]]:
    flow_id = _pick_text(incident_record_payload.get("flow_id"))
    root_event_id = _pick_text(incident_record_payload.get("root_event_id"))
    source_event_id = _pick_text(incident_record_payload.get("source_event_id"))
    workspace_id = _pick_text(incident_record_payload.get("workspace_id"), "production")
    run_record_id = _pick_text(incident_record_payload.get("run_record_id"))
    parent_command_id = _pick_text(incident_record_payload.get("parent_command_id"))
    incident_key = _pick_text(incident_record_payload.get("incident_key"))

    severity_value = _pick_text(incident_record_payload.get("severity"), "High")
    category_value = _pick_text(incident_record_payload.get("category"), "unknown")
    reason_value = _pick_text(incident_record_payload.get("reason"), "incident")

    payload_json = _safe_json(incident_record_payload)

    linked_run = [run_record_id] if run_record_id.startswith("rec") else []
    linked_command = [parent_command_id] if parent_command_id.startswith("rec") else []

    minimal = {
        "Name": _build_incident_name(incident_record_payload),
        "Status_select": "Open",
        "Severity": severity_value or "High",
        "Category": category_value,
        "Reason": reason_value,
        "Opened_At": now_ts,
        "Updated_At": now_ts,
        "Payload_JSON": payload_json,
    }

    rich = {
        **minimal,
        "Flow_ID": flow_id,
        "Root_Event_ID": root_event_id,
        "Source_Event_ID": source_event_id,
        "Workspace_ID": workspace_id,
        "Run_Record_ID": run_record_id,
        "Command_ID": parent_command_id,
        "Incident_Key": incident_key,
        "Created_By_Capability": "incident_create",
    }

    if linked_run:
        rich["Linked_Run"] = linked_run
    if linked_command:
        rich["Linked_Command"] = linked_command

    candidates: List[Dict[str, Any]] = [dict(rich)]

    if "Linked_Run" in rich or "Linked_Command" in rich:
        no_links = dict(rich)
        no_links.pop("Linked_Run", None)
        no_links.pop("Linked_Command", None)
        candidates.append(no_links)

    mid = dict(minimal)
    if flow_id:
        mid["Flow_ID"] = flow_id
    if root_event_id:
        mid["Root_Event_ID"] = root_event_id
    if workspace_id:
        mid["Workspace_ID"] = workspace_id
    if run_record_id:
        mid["Run_Record_ID"] = run_record_id
    candidates.append(mid)

    candidates.append(dict(minimal))

    unique: List[Dict[str, Any]] = []
    seen = set()

    for candidate in candidates:
        clean = {k: v for k, v in candidate.items() if v not in ("", None, [])}
        signature = json.dumps(clean, sort_keys=True, ensure_ascii=False)
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(clean)

    return unique


def _create_incident_best_effort(
    *,
    airtable_create,
    incidents_table_name: str,
    candidates: List[Dict[str, Any]],
) -> Dict[str, Any]:
    attempts: List[Dict[str, Any]] = []

    for fields in candidates:
        try:
            res = airtable_create(incidents_table_name, fields)
            return {
                "ok": True,
                "response": res,
                "fields": fields,
                "attempts": attempts,
            }
        except Exception as exc:
            attempts.append(
                {
                    "ok": False,
                    "fields": fields,
                    "error": repr(exc),
                }
            )

    return {
        "ok": False,
        "attempts": attempts,
        "error": "all_create_attempts_failed",
    }


def _extract_created_record_id(create_res: Any) -> str:
    try:
        if isinstance(create_res, dict):
            record_id = _pick_text(
                create_res.get("id"),
                create_res.get("record_id"),
            )
            if record_id:
                return record_id

            records = create_res.get("records")
            if isinstance(records, list) and records:
                first = records[0]
                if isinstance(first, dict):
                    return _pick_text(first.get("id"))
        return _pick_text(create_res)
    except Exception:
        return ""


def _build_next_input(base: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    payload = _strip_runtime_keys(base)
    payload.update(extra)
    payload = _normalize_keys_deep(payload)
    payload = _unwrap_command_payload(payload)
    payload = _normalize_flow_keys(payload)
    return payload


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

    payload = _normalize_keys_deep(payload)
    payload = _unwrap_command_payload(payload)
    payload = _normalize_flow_keys(payload)

    data = _extract_input(payload)

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}

    if not isinstance(data, dict):
        data = {}

    data = _normalize_keys_deep(data)
    data = _unwrap_command_payload(data)
    data = _normalize_flow_keys(data)

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

    now_ts = _now_ts()

    flow_id = _pick_text(meta.get("flow_id"))
    root_event_id = _pick_text(meta.get("root_event_id"), flow_id)
    source_event_id = _pick_text(meta.get("source_event_id"), root_event_id)
    workspace_id = _pick_text(meta.get("workspace_id"), "production")
    effective_run_record_id = _pick_text(meta.get("run_record_id"), run_record_id)
    parent_command_id = _pick_text(meta.get("parent_command_id"))
    current_step_index = _to_int(meta.get("step_index"), 0)

    decision_block = _normalize_decision_block(data)

    incident_payload = _canonical_incident_context(
        data=data,
        meta=meta,
        runtime_run_record_id=effective_run_record_id,
        next_step_index=current_step_index + 1,
        next_depth=depth + 1,
        decision_block=decision_block,
        incident_record_id="",
    )

    incident_fields_candidates = _build_incident_fields_candidates(
        data=data,
        meta=meta,
        incident_record_payload=incident_payload,
        now_ts=now_ts,
    )

    create_best_effort_res = _create_incident_best_effort(
        airtable_create=airtable_create,
        incidents_table_name=incidents_table_name,
        candidates=incident_fields_candidates,
    )

    if not create_best_effort_res.get("ok"):
        return {
            "ok": False,
            "capability": "incident_create",
            "error": f"incident_create_failed:{create_best_effort_res.get('error')}",
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "source_event_id": source_event_id,
            "run_record_id": effective_run_record_id,
            "terminal": True,
            "create_attempts": create_best_effort_res.get("attempts", []),
        }

    create_res = create_best_effort_res.get("response")
    incident_record_id = _extract_created_record_id(create_res)

    print("[incident_create] created =", incident_record_id, flush=True)

    try:
        endpoint_name = _pick_text(
            incident_payload.get("endpoint_name"),
            data.get("endpoint_name"),
            data.get("endpoint"),
        )

        if endpoint_name and incident_record_id and callable(airtable_update_by_field):
            airtable_update_by_field(
                table="Monitored_Endpoints",
                field="Name",
                value=endpoint_name,
                fields={
                    "Last_Incident_ID": incident_record_id,
                    "Last_Error": _pick_text(
                        incident_payload.get("reason"),
                        incident_payload.get("error_message"),
                        incident_payload.get("error"),
                    ),
                    "Last_Check_At": now_ts,
                },
            )
            print("[incident_create] endpoint linked =", endpoint_name, flush=True)
        else:
            print("[incident_create] skip endpoint update", flush=True)

    except Exception as e:
        print("[incident_create] endpoint link error =", repr(e), flush=True)

    next_input = _build_next_input(
        incident_payload,
        incident_record_id=incident_record_id,
        parent_command_id=parent_command_id,
        command_id=parent_command_id,
        step_index=current_step_index + 1,
        _depth=depth + 1,
    )

    print("[incident_create] next_input =", next_input, flush=True)

    return {
        "ok": True,
        "capability": "incident_create",
        "status": "done",
        "flow_id": _pick_text(next_input.get("flow_id")),
        "root_event_id": _pick_text(next_input.get("root_event_id")),
        "source_event_id": _pick_text(next_input.get("source_event_id")),
        "workspace_id": _pick_text(next_input.get("workspace_id")),
        "incident_record_id": incident_record_id,
        "run_record_id": _pick_text(next_input.get("run_record_id")),
        "linked_run": _pick_text(next_input.get("linked_run")),
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
