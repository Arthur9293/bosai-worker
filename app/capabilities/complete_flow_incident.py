from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional


DEFAULT_MAX_DEPTH = 8

LEGACY_OUTPUT_KEYS = {
    "flowid",
    "flowId",
    "rooteventid",
    "rootEventId",
    "sourceeventid",
    "sourceEventId",
    "eventid",
    "eventId",
    "workspaceid",
    "workspaceId",
    "runrecordid",
    "runRecordId",
    "linkedrun",
    "linkedRun",
    "commandid",
    "commandId",
    "parentcommandid",
    "parentCommandId",
    "incidentrecordid",
    "incidentRecordId",
}


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(v: Any) -> str:
    try:
        text = str(v or "")
    except Exception:
        return ""
    return text.replace("\\_", "_").replace('\\"', '"').strip()


def _to_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return default
        return int(v)
    except Exception:
        try:
            return int(str(v).strip())
        except Exception:
            return default


def _to_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default

    try:
        text = str(v).strip().lower()
    except Exception:
        return default

    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _json_load_maybe(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None:
        return None

    text = _to_str(value)
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


def _is_empty(value: Any) -> bool:
    return value in (None, "", {}, [])


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
                "incident_record_id",
                "record_id",
                "id",
                "flow_id",
                "root_event_id",
                "source_event_id",
                "event_id",
                "workspace_id",
                "run_record_id",
                "linked_run",
                "command_id",
                "parent_command_id",
                "url",
                "method",
                "text",
                "value",
                "name",
            ):
                if key in value:
                    text = _pick_text(value.get(key))
                    if text:
                        return text
            continue

        text = _to_str(value)
        if text:
            return text

    return ""


def _pick_value(*values: Any) -> Any:
    for value in values:
        if not _is_empty(value):
            return value
    return None


def _extract_record_id(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, str):
        text = _to_str(value)
        if text.startswith("rec"):
            return text
        parsed = _json_load_maybe(text)
        if parsed is not None and parsed is not value:
            return _extract_record_id(parsed)
        return ""

    if isinstance(value, list):
        for item in value:
            rid = _extract_record_id(item)
            if rid:
                return rid
        return ""

    if isinstance(value, dict):
        for key in (
            "incident_record_id",
            "record_id",
            "id",
            "Incident_Record_ID",
        ):
            rid = _extract_record_id(value.get(key))
            if rid:
                return rid

        for key in (
            "incident_create_res",
            "incident_result",
            "incident_update_res",
            "response",
            "result",
        ):
            rid = _extract_record_id(value.get(key))
            if rid:
                return rid

    return ""


def _collect_candidate_dicts(value: Any, out: List[Dict[str, Any]]) -> None:
    if value is None:
        return

    if isinstance(value, str):
        parsed = _json_load_maybe(value)
        if parsed is not None and parsed is not value:
            _collect_candidate_dicts(parsed, out)
        return

    if isinstance(value, list):
        for item in value:
            _collect_candidate_dicts(item, out)
        return

    if not isinstance(value, dict):
        return

    out.append(dict(value))

    for key in (
        "input",
        "command_input",
        "incident",
        "incident_create_res",
        "incident_result",
        "incident_update_res",
        "original_input",
        "result",
        "response",
        "payload",
        "body",
        "data",
    ):
        if key in value:
            _collect_candidate_dicts(value.get(key), out)

    # Explore the rest as well, to catch deeply nested Airtable payloads.
    for nested in value.values():
        if isinstance(nested, (dict, list, str)):
            _collect_candidate_dicts(nested, out)


def _extract_search_dicts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    _collect_candidate_dicts(payload, result)
    return result


def _pick_text_from_dicts(dicts: List[Dict[str, Any]], *keys: str, default: str = "") -> str:
    for data in dicts:
        if not isinstance(data, dict):
            continue
        for key in keys:
            if key in data:
                text = _pick_text(data.get(key))
                if text:
                    return text
    return default


def _pick_value_from_dicts(dicts: List[Dict[str, Any]], *keys: str) -> Any:
    for data in dicts:
        if not isinstance(data, dict):
            continue
        for key in keys:
            if key in data and not _is_empty(data.get(key)):
                return data.get(key)
    return None


def _finalize_output_payload(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}
        for key, nested in value.items():
            if key in LEGACY_OUTPUT_KEYS:
                continue
            cleaned[key] = _finalize_output_payload(nested)
        return cleaned

    if isinstance(value, list):
        return [_finalize_output_payload(item) for item in value]

    if isinstance(value, str):
        return value.replace("\\_", "_").replace('\\"', '"')

    return value


def _normalize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    normalized = dict(payload)

    for key in ("input", "command_input"):
        nested = normalized.get(key)
        if isinstance(nested, str):
            nested = _json_load_maybe(nested)
        if isinstance(nested, dict):
            merged = dict(normalized)
            merged.pop(key, None)
            for nested_key, nested_value in nested.items():
                if nested_key not in merged or _is_empty(merged.get(nested_key)):
                    merged[nested_key] = nested_value
            normalized = merged

    search_dicts = _extract_search_dicts(normalized)

    flow_id = _pick_text_from_dicts(search_dicts, "flow_id", "flowid", "flowId", default="")
    root_event_id = _pick_text_from_dicts(
        search_dicts,
        "root_event_id",
        "rooteventid",
        "rootEventId",
        "event_id",
        "eventid",
        "eventId",
        default=flow_id,
    )
    source_event_id = _pick_text_from_dicts(
        search_dicts,
        "source_event_id",
        "sourceeventid",
        "sourceEventId",
        "event_id",
        "eventid",
        "eventId",
        default=root_event_id or flow_id,
    )
    workspace_id = _pick_text_from_dicts(
        search_dicts,
        "workspace_id",
        "workspaceid",
        "workspaceId",
        "workspace",
        default="production",
    )
    run_record_id = _pick_text_from_dicts(
        search_dicts,
        "run_record_id",
        "runrecordid",
        "runRecordId",
        "linked_run",
        "linkedrun",
        default="",
    )
    linked_run = _pick_text_from_dicts(
        search_dicts,
        "linked_run",
        "linkedrun",
        "run_record_id",
        "runrecordid",
        default=run_record_id,
    )
    command_id = _pick_text_from_dicts(search_dicts, "command_id", "commandid", "commandId", default="")
    parent_command_id = _pick_text_from_dicts(
        search_dicts,
        "parent_command_id",
        "parentcommandid",
        "parentCommandId",
        default=command_id,
    )
    incident_record_id = _pick_text_from_dicts(
        search_dicts,
        "incident_record_id",
        "incidentrecordid",
        "Incident_Record_ID",
        default="",
    )

    if not incident_record_id:
        for data in search_dicts:
            incident_record_id = _extract_record_id(data.get("incident_create_res"))
            if incident_record_id:
                break

    if not incident_record_id:
        for data in search_dicts:
            incident_record_id = _extract_record_id(data.get("incident_result"))
            if incident_record_id:
                break

    if not incident_record_id:
        for data in search_dicts:
            incident_record_id = _extract_record_id(data)
            if incident_record_id:
                break

    normalized["flow_id"] = flow_id
    normalized["root_event_id"] = root_event_id
    normalized["source_event_id"] = source_event_id
    normalized["event_id"] = source_event_id or root_event_id or flow_id
    normalized["workspace_id"] = workspace_id
    normalized["workspace"] = workspace_id
    normalized["run_record_id"] = run_record_id
    normalized["linked_run"] = linked_run or run_record_id
    normalized["command_id"] = command_id
    normalized["parent_command_id"] = parent_command_id
    normalized["incident_record_id"] = incident_record_id
    normalized["incident_key"] = _pick_text_from_dicts(search_dicts, "incident_key", default="")
    normalized["step_index"] = _to_int(
        _pick_value_from_dicts(search_dicts, "step_index", "stepindex", "stepIndex"),
        0,
    )
    normalized["_depth"] = _to_int(
        _pick_value_from_dicts(search_dicts, "_depth", "depth"),
        0,
    )

    return normalized


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    **kwargs: Any,
) -> Dict[str, Any]:
    if req is not None and hasattr(req, "input"):
        payload = getattr(req, "input", {}) or {}
    elif isinstance(req, dict):
        payload = req
    else:
        payload = {}

    if isinstance(payload, str):
        payload = _json_load_maybe(payload) or {}

    if not isinstance(payload, dict):
        payload = {}

    payload = _normalize_payload(payload)
    search_dicts = _extract_search_dicts(payload)

    current_depth = _to_int(
        _pick_value_from_dicts(search_dicts, "_depth", "depth"),
        0,
    )

    if current_depth >= DEFAULT_MAX_DEPTH:
        return _finalize_output_payload(
            {
                "ok": False,
                "capability": "complete_flow_incident",
                "error": "max_depth_reached",
                "flow_id": _pick_text_from_dicts(search_dicts, "flow_id", default=""),
                "root_event_id": _pick_text_from_dicts(search_dicts, "root_event_id", default=""),
                "source_event_id": _pick_text_from_dicts(search_dicts, "source_event_id", default=""),
                "incident_record_id": _pick_text_from_dicts(search_dicts, "incident_record_id", default=""),
                "run_record_id": _pick_text_from_dicts(search_dicts, "run_record_id", "linked_run", default=run_record_id),
                "terminal": True,
                "spawn_summary": {
                    "ok": True,
                    "spawned": 0,
                    "skipped": 0,
                    "errors": [],
                },
            }
        )

    flow_id = _pick_text_from_dicts(search_dicts, "flow_id", default="")
    root_event_id = _pick_text_from_dicts(search_dicts, "root_event_id", default=flow_id)
    source_event_id = _pick_text_from_dicts(
        search_dicts,
        "source_event_id",
        default=root_event_id or flow_id,
    )
    workspace_id = _pick_text_from_dicts(
        search_dicts,
        "workspace_id",
        "workspace",
        default="production",
    )
    tenant_id = _pick_text_from_dicts(search_dicts, "tenant_id", "tenantId", default="")
    app_name = _pick_text_from_dicts(search_dicts, "app_name", "appName", default="")
    incident_key = _pick_text_from_dicts(search_dicts, "incident_key", default="")

    incoming_run_record_id = _pick_text_from_dicts(search_dicts, "run_record_id", default="")
    linked_run = _pick_text_from_dicts(
        search_dicts,
        "linked_run",
        default=incoming_run_record_id or run_record_id,
    )
    effective_run_record_id = _pick_text(incoming_run_record_id, linked_run, run_record_id)

    command_id = _pick_text_from_dicts(search_dicts, "command_id", default="")
    parent_command_id = _pick_text_from_dicts(
        search_dicts,
        "parent_command_id",
        default=command_id,
    )

    incident_record_id = _pick_text_from_dicts(
        search_dicts,
        "incident_record_id",
        "incidentrecordid",
        default="",
    )

    if not incident_record_id:
        for data in search_dicts:
            incident_record_id = _extract_record_id(data.get("incident_create_res"))
            if incident_record_id:
                break

    if not incident_record_id:
        for data in search_dicts:
            incident_record_id = _extract_record_id(data.get("incident_result"))
            if incident_record_id:
                break

    if not incident_record_id:
        for data in search_dicts:
            incident_record_id = _extract_record_id(data)
            if incident_record_id:
                break

    severity = _pick_text_from_dicts(search_dicts, "severity", default="").strip().lower()
    category = _pick_text_from_dicts(search_dicts, "category", default="")
    reason = _pick_text_from_dicts(search_dicts, "reason", default="")
    retry_reason = _pick_text_from_dicts(search_dicts, "retry_reason", default="")
    decision_status = _pick_text_from_dicts(search_dicts, "decision_status", default="")
    decision_reason = _pick_text_from_dicts(search_dicts, "decision_reason", default="")
    next_action = _pick_text_from_dicts(search_dicts, "next_action", default="")
    source_capability = _pick_text_from_dicts(search_dicts, "source_capability", default="")
    original_capability = _pick_text_from_dicts(search_dicts, "original_capability", default="")
    failed_capability = _pick_text_from_dicts(
        search_dicts,
        "failed_capability",
        default=source_capability or original_capability,
    )
    target_capability = _pick_text_from_dicts(search_dicts, "target_capability", default="")
    failed_url = _pick_text_from_dicts(
        search_dicts,
        "failed_url",
        "target_url",
        "url",
        "http_target",
        default="",
    )
    failed_method = _pick_text_from_dicts(search_dicts, "failed_method", "method", default="GET").upper()
    incident_code = _pick_text_from_dicts(search_dicts, "incident_code", default="")
    error_message = _pick_text_from_dicts(search_dicts, "error_message", "error", default="")
    incident_message = _pick_text_from_dicts(
        search_dicts,
        "incident_message",
        "error_message",
        "error",
        default=error_message,
    )

    http_status_value = _pick_value_from_dicts(search_dicts, "http_status", "status_code")
    try:
        http_status: Optional[int] = int(http_status_value) if http_status_value not in (None, "") else None
    except Exception:
        http_status = None

    status_code = http_status

    final_failure = _to_bool(
        _pick_value_from_dicts(search_dicts, "final_failure", "finalfailure"),
        False,
    )

    retry_count = _to_int(
        _pick_value_from_dicts(search_dicts, "retry_count", "retrycount"),
        0,
    )
    retry_max = _to_int(
        _pick_value_from_dicts(search_dicts, "retry_max", "retrymax"),
        0,
    )

    current_step_index = _to_int(
        _pick_value_from_dicts(search_dicts, "step_index", "stepindex"),
        0,
    )

    # Inferences défensives pour ne pas perdre le contexte au dernier maillon.
    if not category and (http_status or 0) >= 400:
        category = "http_failure"

    if not incident_code and (http_status or 0) >= 400:
        incident_code = "http_status_error"

    if not severity:
        if (http_status or 0) >= 500:
            severity = "high"
        elif (http_status or 0) >= 400:
            severity = "medium"

    if not final_failure and (http_status or 0) >= 500 and retry_count >= retry_max:
        final_failure = True

    if not decision_status and incident_record_id and final_failure:
        decision_status = "Escalated"

    if not decision_reason and incident_record_id and final_failure:
        decision_reason = "internal_escalation_sent"

    if not next_action:
        next_action = "complete_flow_incident"

    auto_resolve = False
    decision = _pick_text(payload.get("decision"), "keep_escalated")
    next_commands: List[Dict[str, Any]] = []

    next_input_base: Dict[str, Any] = {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "event_id": source_event_id or root_event_id or flow_id,
        "workspace_id": workspace_id,
        "workspace": workspace_id,
        "tenant_id": tenant_id,
        "app_name": app_name,
        "run_record_id": effective_run_record_id,
        "linked_run": linked_run or effective_run_record_id,
        "incident_record_id": incident_record_id,
        "incident_key": incident_key,
        "parent_command_id": command_id or parent_command_id,
        "command_id": command_id,
        "step_index": current_step_index + 1,
        "_depth": current_depth + 1,
        "severity": severity,
        "category": category,
        "reason": reason,
        "retry_reason": retry_reason,
        "decision_status": decision_status,
        "decision_reason": decision_reason,
        "next_action": next_action,
        "source_capability": source_capability,
        "original_capability": original_capability,
        "failed_capability": failed_capability,
        "target_capability": target_capability,
        "failed_url": failed_url,
        "target_url": failed_url,
        "url": failed_url,
        "http_target": failed_url,
        "failed_method": failed_method,
        "method": failed_method,
        "incident_code": incident_code,
        "error_message": error_message,
        "incident_message": incident_message,
        "http_status": http_status,
        "status_code": status_code,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "final_failure": final_failure,
    }

    if incident_record_id and severity in {"low", "medium"} and not final_failure:
        auto_resolve = True
        decision = "auto_resolve"
        next_commands.append(
            {
                "capability": "resolve_incident",
                "priority": 1,
                "input": _finalize_output_payload(dict(next_input_base)),
            }
        )

    return _finalize_output_payload(
        {
            "ok": True,
            "capability": "complete_flow_incident",
            "status": "done",
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "source_event_id": source_event_id,
            "incident_record_id": incident_record_id,
            "incident_key": incident_key,
            "completed": True,
            "message": "incident_flow_completed",
            "closed_at": _now_ts(),
            "run_record_id": effective_run_record_id,
            "linked_run": linked_run or effective_run_record_id,
            "workspace_id": workspace_id,
            "tenant_id": tenant_id,
            "app_name": app_name,
            "command_id": command_id,
            "parent_command_id": parent_command_id,
            "decision": decision,
            "decision_status": decision_status,
            "decision_reason": decision_reason,
            "next_action": next_action,
            "auto_resolve": auto_resolve,
            "severity": severity,
            "category": category,
            "reason": reason,
            "retry_reason": retry_reason,
            "source_capability": source_capability,
            "original_capability": original_capability,
            "failed_capability": failed_capability,
            "target_capability": target_capability,
            "failed_url": failed_url,
            "failed_method": failed_method,
            "incident_code": incident_code,
            "error_message": error_message,
            "incident_message": incident_message,
            "http_status": http_status,
            "status_code": status_code,
            "retry_count": retry_count,
            "retry_max": retry_max,
            "final_failure": final_failure,
            "next_commands": next_commands,
            "terminal": len(next_commands) == 0,
            "spawn_summary": {
                "ok": True,
                "spawned": len(next_commands),
                "skipped": 0,
                "errors": [],
            },
        }
    )
