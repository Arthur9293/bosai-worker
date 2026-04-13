from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(v: Any) -> str:
    try:
        return str(v or "")
    except Exception:
        return ""


def _to_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return default
        return int(v)
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
            for key in ("id", "record_id", "incident_record_id", "name", "value", "text"):
                if key in value:
                    text = _pick_text(value.get(key))
                    if text:
                        return text
            continue

        text = _to_str(value).strip()
        if text:
            return text

    return ""


def _pick_value(*values: Any) -> Any:
    for value in values:
        if not _is_empty(value):
            return value
    return None


def _pick_dict(*values: Any) -> Dict[str, Any]:
    for value in values:
        if isinstance(value, dict) and value:
            return dict(value)
    return {}


def _merge_missing(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(target, dict):
        target = {}
    if not isinstance(source, dict):
        return target

    for key, value in source.items():
        if key not in target or _is_empty(target.get(key)):
            target[key] = value
    return target


def _extract_record_id(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, str):
        text = value.strip()
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

        for key in ("response", "result", "incident_create_res", "incident_result"):
            rid = _extract_record_id(value.get(key))
            if rid:
                return rid

    return ""


def _extract_search_dicts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []

    def _append_candidate(value: Any) -> None:
        if isinstance(value, str):
            value = _json_load_maybe(value)
        if isinstance(value, dict) and value:
            result.append(dict(value))

    if isinstance(payload, dict):
        result.append(dict(payload))

    for key in (
        "incident_result",
        "incident_create_res",
        "incident_update_res",
        "original_input",
        "body",
        "payload",
        "result",
        "input",
        "command_input",
        "incident",
        "response",
    ):
        nested = payload.get(key) if isinstance(payload, dict) else None
        _append_candidate(nested)

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
            merged = _merge_missing(merged, nested)
            normalized = merged

    search_dicts = _extract_search_dicts(normalized)

    flow_id = _pick_text_from_dicts(
        search_dicts,
        "flow_id",
        "flowid",
        "flowId",
        default="",
    )

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

    command_id = _pick_text_from_dicts(
        search_dicts,
        "command_id",
        "commandid",
        "commandId",
        default="",
    )

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
    failed_capability = _pick_text_from_dicts(search_dicts, "failed_capability", default="")
    target_capability = _pick_text_from_dicts(search_dicts, "target_capability", default="")
    failed_url = _pick_text_from_dicts(search_dicts, "failed_url", "target_url", "url", default="")
    failed_method = _pick_text_from_dicts(search_dicts, "failed_method", "method", default="")
    incident_code = _pick_text_from_dicts(search_dicts, "incident_code", default="")
    error_message = _pick_text_from_dicts(search_dicts, "error_message", "error", default="")

    http_status_value = _pick_value_from_dicts(search_dicts, "http_status", "status_code")
    http_status: Optional[int]
    try:
        http_status = int(http_status_value) if http_status_value not in (None, "") else None
    except Exception:
        http_status = None

    final_failure = _to_bool(
        _pick_value_from_dicts(search_dicts, "final_failure", "finalfailure"),
        False,
    )

    retry_count = _to_int(
        _pick_value_from_dicts(search_dicts, "retry_count"),
        0,
    )
    retry_max = _to_int(
        _pick_value_from_dicts(search_dicts, "retry_max"),
        0,
    )

    current_step_index = _to_int(
        _pick_value_from_dicts(search_dicts, "step_index"),
        0,
    )
    current_depth = _to_int(
        _pick_value_from_dicts(search_dicts, "_depth"),
        0,
    )

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
        "run_record_id": effective_run_record_id,
        "linked_run": linked_run or effective_run_record_id,
        "incident_record_id": incident_record_id,
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
        "failed_method": failed_method,
        "incident_code": incident_code,
        "error_message": error_message,
        "http_status": http_status,
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
                "input": dict(next_input_base),
            }
        )

    return {
        "ok": True,
        "capability": "complete_flow_incident",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "incident_record_id": incident_record_id,
        "completed": True,
        "message": "incident_flow_completed",
        "closed_at": _now_ts(),
        "run_record_id": effective_run_record_id,
        "linked_run": linked_run or effective_run_record_id,
        "workspace_id": workspace_id,
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
        "http_status": http_status,
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
