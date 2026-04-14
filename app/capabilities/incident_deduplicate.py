from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional


DEFAULT_MAX_DEPTH = 8

# Capabilities d’orchestration qu’on ne veut PAS utiliser comme origine métier
# si une vraie capability source existe déjà (ex: http_exec).
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

# Clés legacy / bruit qu’on ne veut plus voir dans les payloads stockés.
LEGACY_OR_NOISY_KEYS = {
    "flowid",
    "flowId",
    "Flow_ID",
    "FlowId",
    "rooteventid",
    "rootEventId",
    "root_eventid",
    "Root_Event_ID",
    "RootEventId",
    "sourceeventid",
    "sourceEventId",
    "Source_Event_ID",
    "eventid",
    "eventId",
    "Event_ID",
    "workspaceid",
    "workspaceId",
    "Workspace_ID",
    "runrecordid",
    "runRecordId",
    "Run_Record_ID",
    "linkedrun",
    "linkedRun",
    "Linked_Run",
    "commandid",
    "commandId",
    "Command_ID",
    "parentcommandid",
    "parentCommandId",
    "Parent_Command_ID",
    "parentcommand_id",
    "incidentrecordid",
    "incidentRecordId",
    "Incident_Record_ID",
    "stepindex",
    "stepIndex",
    "Step_Index",
    "StepIndex",
    "retrycount",
    "retrymax",
    "retryreason",
    "targeturl",
    "failedurl",
    "failedmethod",
    "httptarget",
    "httpstatus",
    "statuscode",
    "incidentcode",
    "decisionstatus",
    "decisionreason",
    "nextaction",
    "priorityscore",
    "autoexecutable",
    "finalfailure",
    "targetcapability",
    "originalcapability",
    "failedcapability",
    "sourcecapability",
    "tenantid",
    "appname",
    "endpointname",
    # bruit runtime
    "next_commands",
    "spawn_summary",
    "terminal",
    "ok",
    "status",
    "route",
    "ts",
    "update_res",
    "incident_exists",
    "deduplicate_action",
    "action",
    "update_ok",
    "update_reason",
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


def _escape_airtable_formula_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


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
                return json.loads(inner)
            except Exception:
                return parsed

        return parsed

    return None


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
            for key in (
                "id",
                "name",
                "value",
                "text",
                "url",
                "method",
                "status_code",
                "flow_id",
                "root_event_id",
                "source_event_id",
                "event_id",
                "workspace_id",
                "run_record_id",
                "linked_run",
                "command_id",
                "parent_command_id",
            ):
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

    return fallback or first_non_empty


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


def _materialize_json_like_strings(value: Any) -> Any:
    if isinstance(value, str):
        parsed = _json_load_maybe(value)
        if isinstance(parsed, (dict, list)):
            return _materialize_json_like_strings(parsed)
        return value

    if isinstance(value, list):
        return [_materialize_json_like_strings(item) for item in value]

    if isinstance(value, dict):
        return {k: _materialize_json_like_strings(v) for k, v in value.items()}

    return value


def _unwrap_command_payload(value: Any) -> Any:
    if not isinstance(value, dict):
        return value

    current = dict(value)

    for key in ("input", "command_input"):
        nested = current.get(key)

        if isinstance(nested, str):
            nested = _json_load_maybe(nested)

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
        or normalized.get("parentcommand_id")
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

    raw_depth = (
        normalized.get("_depth")
        if normalized.get("_depth") is not None
        else normalized.get("depth")
    )
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
        "parentcommand_id",
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


def _drop_legacy_and_empty_deep(value: Any) -> Any:
    if isinstance(value, str):
        parsed = _json_load_maybe(value)
        if isinstance(parsed, (dict, list)):
            return _drop_legacy_and_empty_deep(parsed)
        return value

    if isinstance(value, list):
        cleaned_list: List[Any] = []
        for item in value:
            cleaned_item = _drop_legacy_and_empty_deep(item)
            if cleaned_item not in ("", None, [], {}):
                cleaned_list.append(cleaned_item)
        return cleaned_list

    if isinstance(value, dict):
        cleaned_dict: Dict[str, Any] = {}
        for key, nested in value.items():
            if key in LEGACY_OR_NOISY_KEYS:
                continue
            cleaned_nested = _drop_legacy_and_empty_deep(nested)
            if cleaned_nested in ("", None, [], {}):
                continue
            cleaned_dict[key] = cleaned_nested
        return cleaned_dict

    return value


def _extract_input(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    normalized = dict(payload)

    for key in ("input", "command_input", "incident"):
        nested = normalized.get(key)

        if isinstance(nested, str):
            nested = _json_load_maybe(nested)

        if isinstance(nested, dict):
            merged = dict(normalized)
            merged.update(nested)
            normalized = merged

    return normalized


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

    linked_run = _pick_text(
        payload.get("linked_run"),
        payload.get("linkedrun"),
        run_record_id,
    )

    command_id = _pick_text(
        payload.get("command_id"),
        payload.get("commandid"),
        payload.get("commandId"),
    )

    parent_command_id = _pick_text(
        payload.get("parent_command_id"),
        payload.get("parentcommandid"),
        payload.get("parentcommand_id"),
        payload.get("parentCommandId"),
    )

    return {
        "flow_id": flow_id or root_event_id or source_event_id,
        "root_event_id": root_event_id or source_event_id or flow_id,
        "source_event_id": source_event_id or root_event_id or flow_id,
        "parent_command_id": parent_command_id,
        "command_id": command_id,
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
        "linked_run": linked_run or run_record_id,
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

    reason = _pick_text(
        data.get("retry_reason"),
        data.get("incident_code"),
        data.get("reason"),
    ).lower()

    response_obj = data.get("response") if isinstance(data.get("response"), dict) else {}

    http_status = _pick_int(
        data.get("http_status"),
        data.get("httpstatus"),
        data.get("status_code"),
        data.get("statuscode"),
        response_obj.get("status_code"),
    )

    sla_status = _pick_text(data.get("sla_status")).lower()

    input_final_failure = _to_bool(
        data.get("final_failure")
        if data.get("final_failure") is not None
        else data.get("finalfailure"),
        False,
    )

    severe_http_failure = (
        category == "http_failure"
        or reason in {
            "http_5xx_exhausted",
            "http_status_error",
            "forbidden_host",
            "retry_exhausted",
            "retry_limit_reached",
        }
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


def _empty_decision_block() -> Dict[str, Any]:
    return {
        "decision_status": "",
        "decision_reason": "",
        "next_action": "",
        "auto_executable": False,
        "priority_score": 0,
        "normalized_final_failure": False,
    }


def _recompute_decision_from_canonical(canonical: Dict[str, Any]) -> Dict[str, Any]:
    decision_input = dict(canonical)

    for key in (
        "decision_status",
        "decision_reason",
        "next_action",
        "auto_executable",
        "priority_score",
    ):
        decision_input.pop(key, None)

    return _normalize_decision_block(decision_input)


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
        "update_res",
        "incident_exists",
        "deduplicate_action",
        "action",
    ):
        cleaned.pop(noisy_key, None)

    return cleaned


def _compact_request(value: Any) -> Dict[str, Any]:
    parsed = _materialize_json_like_strings(value)
    if not isinstance(parsed, dict):
        return {}

    compact = {
        "method": _pick_text(parsed.get("method"), parsed.get("http_method")),
        "url": _pick_text(parsed.get("url")),
    }

    compact = {k: v for k, v in compact.items() if v not in ("", None)}
    return compact


def _compact_response(value: Any) -> Dict[str, Any]:
    parsed = _materialize_json_like_strings(value)
    if not isinstance(parsed, dict):
        return {}

    compact: Dict[str, Any] = {}

    status_code = _pick_int(parsed.get("status_code"))
    if status_code is not None:
        compact["status_code"] = status_code

    if parsed.get("ok") is not None:
        compact["ok"] = _to_bool(parsed.get("ok"), False)

    elapsed_ms = _pick_int(parsed.get("elapsed_ms"))
    if elapsed_ms is not None:
        compact["elapsed_ms"] = elapsed_ms

    return compact


def _build_storage_payload(canonical: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "flow_id": _pick_text(canonical.get("flow_id")),
        "root_event_id": _pick_text(canonical.get("root_event_id")),
        "source_event_id": _pick_text(canonical.get("source_event_id")),
        "event_id": _pick_text(canonical.get("event_id")),
        "workspace_id": _pick_text(canonical.get("workspace_id")),
        "workspace": _pick_text(canonical.get("workspace")),
        "run_record_id": _pick_text(canonical.get("run_record_id")),
        "linked_run": _pick_text(canonical.get("linked_run")),
        "parent_command_id": _pick_text(canonical.get("parent_command_id")),
        "incident_record_id": _pick_text(canonical.get("incident_record_id")),
        "incident_key": _pick_text(canonical.get("incident_key")),
        "category": _pick_text(canonical.get("category")),
        "severity": _pick_text(canonical.get("severity")),
        "reason": _pick_text(canonical.get("reason")),
        "retry_reason": _pick_text(canonical.get("retry_reason")),
        "decision_status": _pick_text(canonical.get("decision_status")),
        "decision_reason": _pick_text(canonical.get("decision_reason")),
        "next_action": _pick_text(canonical.get("next_action")),
        "auto_executable": _to_bool(canonical.get("auto_executable"), False),
        "priority_score": _to_int(canonical.get("priority_score"), 0),
        "original_capability": _pick_text(canonical.get("original_capability")),
        "failed_capability": _pick_text(canonical.get("failed_capability")),
        "source_capability": _pick_text(canonical.get("source_capability")),
        "failed_url": _pick_text(canonical.get("failed_url")),
        "target_url": _pick_text(canonical.get("target_url")),
        "url": _pick_text(canonical.get("url")),
        "http_target": _pick_text(canonical.get("http_target")),
        "failed_method": _pick_text(canonical.get("failed_method"), canonical.get("method")),
        "method": _pick_text(canonical.get("method"), canonical.get("failed_method")),
        "incident_code": _pick_text(canonical.get("incident_code")),
        "error": _pick_text(canonical.get("error")),
        "error_message": _pick_text(canonical.get("error_message")),
        "incident_message": _pick_text(canonical.get("incident_message")),
        "http_status": _pick_int(canonical.get("http_status"), canonical.get("status_code")),
        "status_code": _pick_int(canonical.get("status_code"), canonical.get("http_status")),
        "retry_count": _to_int(canonical.get("retry_count"), 0),
        "retry_max": _to_int(canonical.get("retry_max"), 0),
        "final_failure": _to_bool(canonical.get("final_failure"), False),
        "tenant_id": _pick_text(canonical.get("tenant_id")),
        "app_name": _pick_text(canonical.get("app_name")),
        "source": _pick_text(canonical.get("source")),
        "goal": _pick_text(canonical.get("goal")),
        "log_record_id": _pick_text(canonical.get("log_record_id")),
        "endpoint_name": _pick_text(canonical.get("endpoint_name")),
        "request": _compact_request(canonical.get("request")),
        "response": _compact_response(canonical.get("response")),
    }

    payload = _normalize_keys_deep(payload)
    payload = _unwrap_command_payload(payload)
    payload = _normalize_flow_keys(payload)
    payload.pop("command_id", None)
    payload.pop("original_input", None)
    payload = _drop_legacy_and_empty_deep(payload)

    return payload if isinstance(payload, dict) else {}


def _canonical_incident_context(
    data: Dict[str, Any],
    meta: Dict[str, Any],
    runtime_run_record_id: str,
    next_step_index: int,
    next_depth: int,
    decision_block: Dict[str, Any],
) -> Dict[str, Any]:
    raw_original_input = _json_load_maybe(data.get("original_input"))
    original_input = raw_original_input if isinstance(raw_original_input, dict) else {}
    original_input = _materialize_json_like_strings(original_input)
    original_input = _normalize_keys_deep(original_input)
    original_input = _unwrap_command_payload(original_input)
    original_input = _normalize_flow_keys(original_input)

    raw_request = _json_load_maybe(data.get("request"))
    request_obj = raw_request if isinstance(raw_request, dict) else {}
    if not request_obj:
        raw_request_from_original = _json_load_maybe(original_input.get("request"))
        request_obj = raw_request_from_original if isinstance(raw_request_from_original, dict) else {}
    request_obj = _materialize_json_like_strings(request_obj)

    raw_response = _json_load_maybe(data.get("response"))
    response_obj = raw_response if isinstance(raw_response, dict) else {}
    if not response_obj:
        raw_response_from_original = _json_load_maybe(original_input.get("response"))
        response_obj = raw_response_from_original if isinstance(raw_response_from_original, dict) else {}
    response_obj = _materialize_json_like_strings(response_obj)

    flow_id = _pick_text(
        meta.get("flow_id"),
        data.get("flow_id"),
        data.get("flowid"),
        data.get("flowId"),
        original_input.get("flow_id"),
        meta.get("root_event_id"),
        meta.get("source_event_id"),
        runtime_run_record_id and f"flow_run_{runtime_run_record_id}",
    )

    root_event_id = _pick_text(
        meta.get("root_event_id"),
        data.get("root_event_id"),
        data.get("rooteventid"),
        data.get("rootEventId"),
        data.get("event_id"),
        data.get("eventid"),
        data.get("eventId"),
        original_input.get("root_event_id"),
        original_input.get("event_id"),
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
        original_input.get("source_event_id"),
        original_input.get("event_id"),
        root_event_id,
        flow_id,
    )

    workspace_id = _pick_text(
        meta.get("workspace_id"),
        data.get("workspace_id"),
        data.get("workspaceid"),
        data.get("workspaceId"),
        data.get("workspace"),
        original_input.get("workspace_id"),
        "production",
    )

    run_record_id = _pick_text(
        meta.get("run_record_id"),
        data.get("run_record_id"),
        data.get("runrecordid"),
        data.get("linked_run"),
        data.get("linkedrun"),
        original_input.get("run_record_id"),
        original_input.get("linked_run"),
        runtime_run_record_id,
    )

    linked_run = _pick_text(
        meta.get("linked_run"),
        data.get("linked_run"),
        data.get("linkedrun"),
        original_input.get("linked_run"),
        run_record_id,
    )

    target_url = _pick_text(
        data.get("failed_url"),
        data.get("target_url"),
        data.get("targeturl"),
        data.get("url"),
        data.get("http_target"),
        original_input.get("failed_url"),
        original_input.get("target_url"),
        original_input.get("url"),
        original_input.get("http_target"),
        request_obj.get("url") if isinstance(request_obj, dict) else "",
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
        request_obj.get("method") if isinstance(request_obj, dict) else "",
        "GET",
    ).upper()

    http_status = _pick_int(
        data.get("http_status"),
        data.get("httpstatus"),
        data.get("status_code"),
        data.get("statuscode"),
        original_input.get("http_status"),
        original_input.get("status_code"),
        response_obj.get("status_code") if isinstance(response_obj, dict) else None,
    )

    status_code = _pick_int(
        data.get("status_code"),
        data.get("statuscode"),
        data.get("http_status"),
        data.get("httpstatus"),
        original_input.get("status_code"),
        original_input.get("http_status"),
        response_obj.get("status_code") if isinstance(response_obj, dict) else None,
        http_status,
    )

    category = _pick_text(
        data.get("category"),
        original_input.get("category"),
        "http_failure" if target_url else "",
    )

    reason = _pick_text(
        data.get("retry_reason"),
        original_input.get("retry_reason"),
        data.get("incident_code"),
        original_input.get("incident_code"),
        data.get("reason"),
        original_input.get("reason"),
        data.get("error"),
        original_input.get("error"),
        "incident",
    )

    severity = _pick_text(
        data.get("severity"),
        original_input.get("severity"),
        "high" if http_status is not None and http_status >= 500 else "",
    )

    incident_code = _pick_text(
        data.get("incident_code"),
        data.get("incidentcode"),
        original_input.get("incident_code"),
        original_input.get("incidentcode"),
        data.get("retry_reason"),
        original_input.get("retry_reason"),
        data.get("reason"),
        "http_status_error",
    )

    error = _pick_text(
        data.get("error"),
        data.get("error_message"),
        original_input.get("error"),
        original_input.get("error_message"),
    )

    error_message = _pick_text(
        data.get("error_message"),
        data.get("incident_message"),
        original_input.get("error_message"),
        original_input.get("incident_message"),
        data.get("error"),
        original_input.get("error"),
    )

    normalized_final_failure = _to_bool(
        data.get("final_failure")
        if data.get("final_failure") is not None
        else original_input.get("final_failure")
        if original_input.get("final_failure") is not None
        else decision_block.get("normalized_final_failure"),
        False,
    )

    if not normalized_final_failure:
        if (
            (http_status is not None and http_status >= 500)
            or reason in {"http_status_error", "http_5xx_exhausted", "retry_exhausted", "retry_limit_reached"}
            or category == "http_failure"
        ):
            normalized_final_failure = True

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
        "parent_command_id": _pick_text(
            meta.get("parent_command_id"),
            data.get("parent_command_id"),
            data.get("parentcommandid"),
            original_input.get("parent_command_id"),
        ),
        "command_id": _pick_text(
            meta.get("command_id"),
            data.get("command_id"),
            data.get("commandid"),
            original_input.get("command_id"),
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
            original_input.get("failed_goal"),
        ),
        "error": error,
        "error_message": error_message,
        "incident_message": _pick_text(
            data.get("incident_message"),
            original_input.get("incident_message"),
            error_message,
            error,
        ),
        "request": request_obj,
        "response": response_obj,
        "original_input": original_input,
        "retry_reason": _pick_text(
            data.get("retry_reason"),
            original_input.get("retry_reason"),
            reason,
        ),
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
        "incident_record_id": _pick_text(data.get("incident_record_id")),
        "log_record_id": _pick_text(data.get("log_record_id")),
        "endpoint_name": _pick_text(data.get("endpoint_name"), original_input.get("endpoint_name")),
    }

    canonical = _normalize_keys_deep(canonical)
    canonical = _materialize_json_like_strings(canonical)
    canonical = _unwrap_command_payload(canonical)
    canonical = _normalize_flow_keys(canonical)
    canonical = _drop_legacy_and_empty_deep(canonical)

    return canonical if isinstance(canonical, dict) else {}


def _build_incident_key(data: Dict[str, Any], meta: Dict[str, Any]) -> str:
    flow_id = _pick_text(data.get("flow_id"), meta.get("flow_id"), "no_flow")
    root_event_id = _pick_text(data.get("root_event_id"), meta.get("root_event_id"), "no_root")

    capability = _pick_capability(
        data.get("original_capability"),
        data.get("failed_capability"),
        data.get("source_capability"),
        data.get("original_input", {}).get("original_capability") if isinstance(data.get("original_input"), dict) else "",
        fallback="no_capability",
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
        data.get("retry_reason"),
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


def _normalize_airtable_records_response(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]

    if isinstance(value, dict):
        records = value.get("records")
        if isinstance(records, list):
            return [item for item in records if isinstance(item, dict)]

        if "id" in value or "fields" in value:
            return [value]

    return []


def _extract_airtable_record_id(record: Any) -> str:
    if isinstance(record, dict):
        return _pick_text(record.get("id"), record.get("record_id"))
    return ""


def _extract_airtable_fields(record: Any) -> Dict[str, Any]:
    if isinstance(record, dict):
        fields = record.get("fields")
        if isinstance(fields, dict):
            return fields
        return record
    return {}


def _build_fallback_formula(candidate: Dict[str, Any]) -> str:
    flow_id = _pick_text(candidate.get("flow_id"))
    root_event_id = _pick_text(candidate.get("root_event_id"))
    workspace_id = _pick_text(candidate.get("workspace_id"))

    parts: List[str] = []

    if flow_id:
        parts.append(f"{{Flow_ID}}='{_escape_airtable_formula_value(flow_id)}'")
    if root_event_id:
        parts.append(f"{{Root_Event_ID}}='{_escape_airtable_formula_value(root_event_id)}'")
    if workspace_id:
        parts.append(f"{{Workspace_ID}}='{_escape_airtable_formula_value(workspace_id)}'")

    if not parts:
        return ""

    if len(parts) == 1:
        return parts[0]

    return f"AND({','.join(parts)})"


def _record_matches_candidate(candidate: Dict[str, Any], record: Dict[str, Any]) -> bool:
    fields = _extract_airtable_fields(record)

    record_key = _pick_text(
        fields.get("Incident_Key"),
        fields.get("incident_key"),
        fields.get("Incident Key"),
    )
    candidate_key = _pick_text(candidate.get("incident_key"))

    if candidate_key and record_key and candidate_key == record_key:
        return True

    payload = _json_load_maybe(fields.get("Payload_JSON"))
    payload = payload if isinstance(payload, dict) else {}
    payload = _materialize_json_like_strings(payload)
    payload = _normalize_keys_deep(payload)
    payload = _unwrap_command_payload(payload)
    payload = _normalize_flow_keys(payload)
    payload = _drop_legacy_and_empty_deep(payload)

    candidate_flow = _pick_text(candidate.get("flow_id"))
    record_flow = _pick_text(fields.get("Flow_ID"), payload.get("flow_id"))

    candidate_root = _pick_text(candidate.get("root_event_id"))
    record_root = _pick_text(fields.get("Root_Event_ID"), payload.get("root_event_id"))

    candidate_workspace = _pick_text(candidate.get("workspace_id"))
    record_workspace = _pick_text(fields.get("Workspace_ID"), payload.get("workspace_id"), payload.get("workspace"))

    candidate_url = _pick_text(
        candidate.get("failed_url"),
        candidate.get("target_url"),
        candidate.get("url"),
        candidate.get("http_target"),
    )
    record_url = _pick_text(
        payload.get("failed_url"),
        payload.get("target_url"),
        payload.get("url"),
        payload.get("http_target"),
    )

    candidate_method = _pick_text(candidate.get("failed_method"), candidate.get("method"), "GET").upper()
    record_method = _pick_text(payload.get("failed_method"), payload.get("method"), "GET").upper()

    candidate_status = _pick_text(candidate.get("http_status"), candidate.get("status_code"))
    record_status = _pick_text(payload.get("http_status"), payload.get("status_code"))

    candidate_code = _pick_text(candidate.get("incident_code"), candidate.get("retry_reason"), candidate.get("reason"))
    record_code = _pick_text(payload.get("incident_code"), payload.get("retry_reason"), payload.get("reason"))

    candidate_capability = _pick_capability(
        candidate.get("original_capability"),
        candidate.get("failed_capability"),
        candidate.get("source_capability"),
        fallback="",
    )
    record_capability = _pick_capability(
        payload.get("original_capability"),
        payload.get("failed_capability"),
        payload.get("source_capability"),
        fallback="",
    )

    if candidate_flow and record_flow and candidate_flow != record_flow:
        return False
    if candidate_root and record_root and candidate_root != record_root:
        return False
    if candidate_workspace and record_workspace and candidate_workspace != record_workspace:
        return False
    if candidate_url and record_url and candidate_url != record_url:
        return False
    if candidate_method and record_method and candidate_method != record_method:
        return False
    if candidate_status and record_status and candidate_status != record_status:
        return False
    if candidate_code and record_code and candidate_code != record_code:
        return False
    if candidate_capability and record_capability and candidate_capability != record_capability:
        return False

    return bool(
        candidate_flow
        and candidate_root
        and candidate_url
        and record_flow
        and record_root
        and record_url
        and candidate_flow == record_flow
        and candidate_root == record_root
        and candidate_url == record_url
    )


def _find_existing_incident(
    incidents_table_name: str,
    incident_key: str,
    canonical_candidate: Dict[str, Any],
    airtable_list_filtered,
) -> Optional[Dict[str, Any]]:
    print("[incident_deduplicate] lookup incident_key =", incident_key, flush=True)

    if not callable(airtable_list_filtered):
        print("[incident_deduplicate] airtable_list_filtered not callable", flush=True)
        return None

    try:
        safe_key = _escape_airtable_formula_value(incident_key)
        exact_formula = f"{{Incident_Key}}='{safe_key}'"

        print("[incident_deduplicate] exact formula =", exact_formula, flush=True)

        exact_raw = airtable_list_filtered(
            incidents_table_name,
            formula=exact_formula,
            max_records=5,
        )
        exact_records = _normalize_airtable_records_response(exact_raw)

        print(
            "[incident_deduplicate] exact raw type =",
            type(exact_raw).__name__,
            "count =",
            len(exact_records),
            "ids =",
            [_extract_airtable_record_id(r) for r in exact_records],
            flush=True,
        )

        if exact_records:
            for record in exact_records:
                fields = _extract_airtable_fields(record)
                print(
                    "[incident_deduplicate] exact candidate:",
                    {
                        "id": _extract_airtable_record_id(record),
                        "Incident_Key": _pick_text(fields.get("Incident_Key")),
                        "Flow_ID": _pick_text(fields.get("Flow_ID")),
                        "Root_Event_ID": _pick_text(fields.get("Root_Event_ID")),
                    },
                    flush=True,
                )
            return exact_records[0]

        fallback_formula = _build_fallback_formula(canonical_candidate)
        print("[incident_deduplicate] fallback formula =", fallback_formula, flush=True)

        if not fallback_formula:
            return None

        fallback_raw = airtable_list_filtered(
            incidents_table_name,
            formula=fallback_formula,
            max_records=20,
        )
        fallback_records = _normalize_airtable_records_response(fallback_raw)

        print(
            "[incident_deduplicate] fallback raw type =",
            type(fallback_raw).__name__,
            "count =",
            len(fallback_records),
            "ids =",
            [_extract_airtable_record_id(r) for r in fallback_records],
            flush=True,
        )

        for record in fallback_records:
            fields = _extract_airtable_fields(record)
            payload = _json_load_maybe(fields.get("Payload_JSON"))
            payload = payload if isinstance(payload, dict) else {}
            payload = _materialize_json_like_strings(payload)

            summary = {
                "id": _extract_airtable_record_id(record),
                "Incident_Key": _pick_text(fields.get("Incident_Key")),
                "Flow_ID": _pick_text(fields.get("Flow_ID")),
                "Root_Event_ID": _pick_text(fields.get("Root_Event_ID")),
                "Workspace_ID": _pick_text(fields.get("Workspace_ID")),
                "payload_url": _pick_text(
                    payload.get("failed_url"),
                    payload.get("target_url"),
                    payload.get("url"),
                    payload.get("http_target"),
                ),
                "payload_status": _pick_text(
                    payload.get("http_status"),
                    payload.get("status_code"),
                ),
            }
            print("[incident_deduplicate] fallback candidate =", summary, flush=True)

            if _record_matches_candidate(canonical_candidate, record):
                print(
                    "[incident_deduplicate] fallback MATCH found id =",
                    _extract_airtable_record_id(record),
                    flush=True,
                )
                return record

    except Exception as exc:
        print("[incident_deduplicate] lookup error =", repr(exc), flush=True)

    print("[incident_deduplicate] no existing incident found", flush=True)
    return None


def _update_existing_incident_best_effort(
    *,
    airtable_update,
    incidents_table_name: str,
    existing_id: str,
    meta: Dict[str, Any],
    data: Dict[str, Any],
) -> Dict[str, Any]:
    if not callable(airtable_update):
        return {
            "ok": False,
            "attempts": [],
            "error": "airtable_update_not_callable",
        }

    now_ts = _now_ts()

    run_record_id = _pick_text(meta.get("run_record_id"))
    parent_command_id = _pick_text(
        meta.get("parent_command_id"),
        data.get("parent_command_id"),
        data.get("parentcommandid"),
    )

    linked_run = [run_record_id] if run_record_id.startswith("rec") else []
    linked_command = [parent_command_id] if parent_command_id.startswith("rec") else []

    storage_payload = _build_storage_payload(data)

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
            "Payload_JSON": _safe_json(storage_payload),
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


def _build_next_input(base: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    transition = _build_storage_payload(base)
    transition.update(extra)
    transition = _normalize_keys_deep(transition)
    transition = _materialize_json_like_strings(transition)
    transition = _unwrap_command_payload(transition)
    transition = _normalize_flow_keys(transition)

    # on évite de propager l'identité de la commande courante au prochain maillon
    transition.pop("command_id", None)

    transition = _drop_legacy_and_empty_deep(transition)
    return transition if isinstance(transition, dict) else {}


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    *,
    airtable_list_filtered,
    airtable_update,
    incidents_table_name: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    raw_payload = getattr(req, "input", {}) if hasattr(req, "input") else req or {}
    raw_payload = _json_load_maybe(raw_payload)
    payload = raw_payload if isinstance(raw_payload, dict) else {}
    payload = _normalize_keys_deep(payload)
    payload = _materialize_json_like_strings(payload)
    payload = _unwrap_command_payload(payload)
    payload = _normalize_flow_keys(payload)

    raw_data = _extract_input(payload)
    raw_data = _json_load_maybe(raw_data)
    data = raw_data if isinstance(raw_data, dict) else {}
    data = _normalize_keys_deep(data)
    data = _materialize_json_like_strings(data)
    data = _unwrap_command_payload(data)
    data = _normalize_flow_keys(data)

    meta = _extract_meta(data)

    depth = _to_int(meta.get("depth"), 0)
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "incident_deduplicate",
            "error": "max_depth_reached",
            "terminal": True,
        }

    seed_decision_block = _empty_decision_block()

    canonical_for_key = _canonical_incident_context(
        data=data,
        meta=meta,
        runtime_run_record_id=run_record_id,
        next_step_index=_to_int(meta.get("step_index"), 0) + 1,
        next_depth=depth + 1,
        decision_block=seed_decision_block,
    )

    decision_block = _recompute_decision_from_canonical(canonical_for_key)

    canonical_for_key = dict(canonical_for_key)
    canonical_for_key["decision_status"] = decision_block["decision_status"]
    canonical_for_key["decision_reason"] = decision_block["decision_reason"]
    canonical_for_key["next_action"] = decision_block["next_action"]
    canonical_for_key["auto_executable"] = decision_block["auto_executable"]
    canonical_for_key["priority_score"] = decision_block["priority_score"]
    canonical_for_key["final_failure"] = (
        _to_bool(canonical_for_key.get("final_failure"), False)
        or _to_bool(decision_block.get("normalized_final_failure"), False)
    )

    canonical_for_key = _normalize_keys_deep(canonical_for_key)
    canonical_for_key = _materialize_json_like_strings(canonical_for_key)
    canonical_for_key = _unwrap_command_payload(canonical_for_key)
    canonical_for_key = _normalize_flow_keys(canonical_for_key)
    canonical_for_key = _drop_legacy_and_empty_deep(canonical_for_key)

    incident_key = _build_incident_key(
        canonical_for_key,
        {
            **meta,
            "flow_id": canonical_for_key.get("flow_id", ""),
            "root_event_id": canonical_for_key.get("root_event_id", ""),
        },
    )

    canonical_for_key["incident_key"] = incident_key

    print(
        "[incident_deduplicate] canonical summary =",
        {
            "flow_id": _pick_text(canonical_for_key.get("flow_id")),
            "root_event_id": _pick_text(canonical_for_key.get("root_event_id")),
            "workspace_id": _pick_text(canonical_for_key.get("workspace_id")),
            "url": _pick_text(
                canonical_for_key.get("failed_url"),
                canonical_for_key.get("target_url"),
                canonical_for_key.get("url"),
            ),
            "method": _pick_text(
                canonical_for_key.get("failed_method"),
                canonical_for_key.get("method"),
                "GET",
            ),
            "http_status": _pick_text(
                canonical_for_key.get("http_status"),
                canonical_for_key.get("status_code"),
            ),
            "incident_code": _pick_text(canonical_for_key.get("incident_code")),
            "incident_key": incident_key,
        },
        flush=True,
    )

    existing = _find_existing_incident(
        incidents_table_name,
        incident_key,
        canonical_for_key,
        airtable_list_filtered,
    )

    if existing:
        existing_id = _extract_airtable_record_id(existing)

        update_res = _update_existing_incident_best_effort(
            airtable_update=airtable_update,
            incidents_table_name=incidents_table_name,
            existing_id=existing_id,
            meta=meta,
            data=canonical_for_key,
        )

        next_input = _build_next_input(
            canonical_for_key,
            incident_record_id=existing_id,
            incident_key=incident_key,
            deduplicate_action="existing_found",
        )

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
            "flow_id": next_input.get("flow_id", ""),
            "root_event_id": next_input.get("root_event_id", ""),
            "source_event_id": next_input.get("source_event_id", ""),
            "workspace_id": next_input.get("workspace_id", ""),
            "run_record_id": next_input.get("run_record_id", ""),
            "linked_run": next_input.get("linked_run", ""),
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
            "terminal": len(next_commands) == 0,
            "spawn_summary": {
                "ok": True,
                "spawned": len(next_commands),
                "skipped": 0,
                "errors": [],
            },
        }

    create_input = _build_next_input(
        canonical_for_key,
        incident_key=incident_key,
        deduplicate_action="create_new",
    )

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
        "flow_id": create_input.get("flow_id", ""),
        "root_event_id": create_input.get("root_event_id", ""),
        "source_event_id": create_input.get("source_event_id", ""),
        "workspace_id": create_input.get("workspace_id", ""),
        "run_record_id": create_input.get("run_record_id", ""),
        "linked_run": create_input.get("linked_run", ""),
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
        "terminal": len(next_commands) == 0,
        "spawn_summary": {
            "ok": True,
            "spawned": len(next_commands),
            "skipped": 0,
            "errors": [],
        },
    }
