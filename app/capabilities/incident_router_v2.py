from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional


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


def _json_load_maybe(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None:
        return None

    text = _to_str(value).strip()
    if not text:
        return None

    try:
        return json.loads(text)
    except Exception:
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

        text = str(value).strip()
        if text:
            return text

    return ""


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

    return value


def _extract_input(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    normalized = dict(payload)

    for key in ("input", "event", "data", "command_input", "incident"):
        nested = normalized.get(key)

        if isinstance(nested, str):
            nested = _json_load_maybe(nested)

        if isinstance(nested, dict):
            merged = dict(normalized)
            merged.update(nested)
            normalized = merged

    return normalized


def _extract_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}

    original_input = payload.get("original_input")
    if isinstance(original_input, str):
        original_input = _json_load_maybe(original_input)
    if not isinstance(original_input, dict):
        original_input = {}

    flow_id = _pick_text(
        payload.get("flow_id"),
        payload.get("flowid"),
        payload.get("flowId"),
        original_input.get("flow_id"),
        original_input.get("flowid"),
        original_input.get("flowId"),
    )

    root_event_id = _pick_text(
        payload.get("root_event_id"),
        payload.get("rooteventid"),
        payload.get("rootEventId"),
        original_input.get("root_event_id"),
        original_input.get("rooteventid"),
        original_input.get("rootEventId"),
        payload.get("event_id"),
        payload.get("eventid"),
        payload.get("eventId"),
        original_input.get("event_id"),
        original_input.get("eventid"),
        original_input.get("eventId"),
        payload.get("id"),
    )

    source_event_id = _pick_text(
        payload.get("source_event_id"),
        payload.get("sourceeventid"),
        payload.get("sourceEventId"),
        original_input.get("source_event_id"),
        original_input.get("sourceeventid"),
        original_input.get("sourceEventId"),
        payload.get("event_id"),
        payload.get("eventid"),
        payload.get("eventId"),
        original_input.get("event_id"),
        original_input.get("eventid"),
        original_input.get("eventId"),
        root_event_id,
        flow_id,
    )

    run_record_id = _pick_text(
        payload.get("run_record_id"),
        payload.get("runrecordid"),
        payload.get("runRecordId"),
        payload.get("linked_run"),
        payload.get("linkedrun"),
        payload.get("Linked_Run"),
        original_input.get("run_record_id"),
        original_input.get("runrecordid"),
        original_input.get("runRecordId"),
        original_input.get("linked_run"),
        original_input.get("linkedrun"),
        original_input.get("Linked_Run"),
        payload.get("run_id"),
        payload.get("runid"),
        payload.get("runId"),
    )

    linked_run = _pick_text(
        payload.get("linked_run"),
        payload.get("linkedrun"),
        payload.get("Linked_Run"),
        original_input.get("linked_run"),
        original_input.get("linkedrun"),
        original_input.get("Linked_Run"),
        run_record_id,
    )

    command_id = _pick_text(
        payload.get("command_id"),
        payload.get("commandid"),
        payload.get("commandId"),
        original_input.get("command_id"),
        original_input.get("commandid"),
        original_input.get("commandId"),
    )

    parent_command_id = _pick_text(
        payload.get("parent_command_id"),
        payload.get("parentcommandid"),
        payload.get("parentCommandId"),
        original_input.get("parent_command_id"),
        original_input.get("parentcommandid"),
        original_input.get("parentCommandId"),
        command_id,
    )

    workspace_id = _pick_text(
        payload.get("workspace_id"),
        payload.get("workspaceid"),
        payload.get("workspaceId"),
        payload.get("workspace"),
        original_input.get("workspace_id"),
        original_input.get("workspaceid"),
        original_input.get("workspaceId"),
        original_input.get("workspace"),
        "production",
    )

    tenant_id = _pick_text(
        payload.get("tenant_id"),
        payload.get("tenantid"),
        payload.get("tenantId"),
        original_input.get("tenant_id"),
        original_input.get("tenantid"),
        original_input.get("tenantId"),
    )

    app_name = _pick_text(
        payload.get("app_name"),
        payload.get("appname"),
        payload.get("appName"),
        original_input.get("app_name"),
        original_input.get("appname"),
        original_input.get("appName"),
        "bosai-worker",
    )

    step_index = _to_int(
        payload.get("step_index")
        if payload.get("step_index") is not None
        else payload.get("stepindex")
        if payload.get("stepindex") is not None
        else payload.get("stepIndex")
        if payload.get("stepIndex") is not None
        else original_input.get("step_index")
        if original_input.get("step_index") is not None
        else original_input.get("stepindex")
        if original_input.get("stepindex") is not None
        else original_input.get("stepIndex"),
        0,
    )

    depth = _to_int(
        payload.get("_depth")
        if payload.get("_depth") is not None
        else payload.get("depth")
        if payload.get("depth") is not None
        else original_input.get("_depth")
        if original_input.get("_depth") is not None
        else original_input.get("depth"),
        0,
    )

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "run_record_id": run_record_id,
        "linked_run": linked_run or run_record_id,
        "command_id": command_id,
        "parent_command_id": parent_command_id,
        "workspace_id": workspace_id or "production",
        "tenant_id": tenant_id,
        "app_name": app_name or "bosai-worker",
        "step_index": step_index,
        "depth": depth,
        "source": _pick_text(
            payload.get("source"),
            payload.get("Source"),
            original_input.get("source"),
            "incident_router_v2",
        ),
    }


def _normalize_category(data: Dict[str, Any]) -> str:
    category = _to_str(
        data.get("category")
        or data.get("Category")
        or data.get("type")
        or data.get("incident_type")
        or data.get("incidenttype")
        or ""
    ).strip().lower()

    incident_code = _to_str(
        data.get("incident_code")
        or data.get("incidentcode")
        or ""
    ).strip().lower()

    failed_capability = _to_str(
        data.get("failed_capability")
        or data.get("failedcapability")
        or data.get("original_capability")
        or data.get("originalcapability")
        or ""
    ).strip().lower()

    http_status = _to_int(
        data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus"),
        0,
    )

    if category:
        if category in {"httpfailure", "http_failure"}:
            return "http_failure"
        return category

    if http_status >= 400:
        return "http_failure"

    if incident_code in {"http_status_error", "timeout", "forbidden_host"}:
        return "http_failure"

    if failed_capability == "http_exec":
        return "http_failure"

    return "unknown_incident"


def _normalize_reason(data: Dict[str, Any]) -> str:
    reason = _to_str(
        data.get("reason")
        or data.get("Reason")
        or ""
    ).strip().lower()

    if reason:
        return reason

    incident_code = _to_str(
        data.get("incident_code")
        or data.get("incidentcode")
        or ""
    ).strip().lower()

    http_status = _to_int(
        data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus"),
        0,
    )

    if incident_code:
        return incident_code

    if http_status >= 400:
        return "http_status_error"

    return "incident_detected"


def _resolve_final_failure(data: Dict[str, Any]) -> bool:
    if "final_failure" in data:
        return _to_bool(data.get("final_failure"), False)
    if "finalfailure" in data:
        return _to_bool(data.get("finalfailure"), False)

    retry_count = _to_int(
        data.get("retry_count")
        if data.get("retry_count") is not None
        else data.get("retrycount"),
        0,
    )
    retry_max = _to_int(
        data.get("retry_max")
        if data.get("retry_max") is not None
        else data.get("retrymax"),
        0,
    )
    http_status = _to_int(
        data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus"),
        0,
    )

    if http_status >= 400 and retry_count >= retry_max:
        return True

    return False


def _normalize_severity(data: Dict[str, Any]) -> str:
    severity = _to_str(
        data.get("severity")
        or data.get("Severity")
        or ""
    ).strip().lower()

    if severity in {"critical", "high", "medium", "warning", "low"}:
        return "medium" if severity == "warning" else severity

    http_status = _to_int(
        data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus"),
        0,
    )
    final_failure = _resolve_final_failure(data)

    if http_status >= 500 and final_failure:
        return "high"
    if http_status >= 500:
        return "medium"

    return "medium"


def _normalize_event(data: Dict[str, Any]) -> Dict[str, Any]:
    category = _normalize_category(data)
    reason = _normalize_reason(data)
    final_failure = _resolve_final_failure(data)
    severity = _normalize_severity({**data, "final_failure": final_failure})

    error_message = _to_str(
        data.get("error_message")
        or data.get("errormessage")
        or data.get("error")
        or data.get("message")
        or ""
    ).strip()

    failed_url = _to_str(
        data.get("failed_url")
        or data.get("target_url")
        or data.get("http_target")
        or data.get("url")
        or data.get("URL")
        or ""
    ).strip()

    failed_method = _to_str(
        data.get("failed_method")
        or data.get("method")
        or data.get("HTTP_Method")
        or "GET"
    ).strip().upper()

    http_status = _to_int(
        data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus"),
        0,
    )

    incident_code = _to_str(
        data.get("incident_code")
        or data.get("incidentcode")
        or ""
    ).strip().lower()

    if not incident_code and http_status >= 400:
        incident_code = "http_status_error"

    return {
        "category": category,
        "reason": reason,
        "severity": severity,
        "http_status": http_status,
        "final_failure": final_failure,
        "incident_code": incident_code,
        "original_capability": _to_str(
            data.get("original_capability")
            or data.get("originalcapability")
            or data.get("failed_capability")
            or data.get("failedcapability")
            or ""
        ).strip(),
        "failed_capability": _to_str(
            data.get("failed_capability")
            or data.get("failedcapability")
            or data.get("original_capability")
            or data.get("originalcapability")
            or ""
        ).strip(),
        "failed_url": failed_url,
        "failed_method": failed_method,
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
        "incident_record_id": _to_str(
            data.get("incident_record_id")
            or data.get("incidentrecordid")
            or ""
        ).strip(),
        "log_record_id": _to_str(
            data.get("log_record_id")
            or data.get("logrecordid")
            or ""
        ).strip(),
        "error": error_message,
        "error_message": error_message,
    }


def _route(normalized: Dict[str, Any]) -> Dict[str, Any]:
    category = _to_str(normalized.get("category")).strip().lower()
    severity = _to_str(normalized.get("severity")).strip().lower()
    http_status = _to_int(normalized.get("http_status"), 0)
    final_failure = _to_bool(normalized.get("final_failure"), False)

    if category == "http_failure" or http_status >= 500:
        return {
            "route": "incident",
            "reason": "http_failure_detected",
        }

    if severity in {"critical", "high"} and final_failure:
        return {
            "route": "incident",
            "reason": "critical_failure",
        }

    if severity in {"medium", "warning"}:
        return {
            "route": "monitor",
            "reason": "non_blocking_issue",
        }

    return {
        "route": "ignore",
        "reason": "not_an_incident",
    }


def _build_incident_key(
    *,
    flow_id: str,
    root_event_id: str,
    failed_capability: str,
    failed_method: str,
    failed_url: str,
    http_status: int,
    incident_code: str,
    reason: str,
    final_failure: bool,
) -> str:
    parts = [
        flow_id,
        root_event_id,
        failed_capability or "unknown_capability",
        failed_method or "GET",
        failed_url or "unknown_url",
        str(http_status or 0),
        incident_code or "no_code",
        reason or "no_reason",
        "final" if final_failure else "nonfinal",
    ]
    return "|".join(parts)


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    **kwargs: Any,
) -> Dict[str, Any]:
    payload = getattr(req, "input", {}) if hasattr(req, "input") else req or {}

    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            payload = {}

    if not isinstance(payload, dict):
        payload = {}

    data = _extract_input(payload)
    meta = _extract_meta(data)

    depth = meta["depth"]
    if depth >= DEFAULT_MAX_DEPTH:
        return _finalize_output_payload(
            {
                "ok": False,
                "capability": "incident_router_v2",
                "error": "max_depth_reached",
                "flow_id": meta.get("flow_id", ""),
                "root_event_id": meta.get("root_event_id", ""),
                "source_event_id": meta.get("source_event_id", ""),
                "run_record_id": meta.get("run_record_id", "") or run_record_id,
                "linked_run": meta.get("linked_run", "") or run_record_id,
                "terminal": True,
                "spawn_summary": {
                    "ok": True,
                    "spawned": 0,
                    "skipped": 0,
                    "errors": [],
                },
            }
        )

    effective_run_record_id = _to_str(
        run_record_id or meta.get("run_record_id") or meta.get("linked_run") or ""
    ).strip()

    effective_linked_run = _to_str(
        meta.get("linked_run") or effective_run_record_id
    ).strip()

    flow_id = meta["flow_id"] or f"flow_router_{_now_ts()}"
    source_event_id = meta["source_event_id"] or meta["root_event_id"] or flow_id
    root_event_id = meta["root_event_id"] or source_event_id or flow_id

    normalized = _normalize_event(data)
    routing = _route(normalized)

    decision_status = ""
    decision_reason = ""
    next_action = ""
    auto_executable = False
    priority_score = 0

    if routing["route"] == "incident":
        decision_status = "Escalate"
        decision_reason = "escalate_failure_or_severe_signal"
        next_action = "internal_escalate"
        auto_executable = True
        priority_score = 80

    incident_key = _build_incident_key(
        flow_id=flow_id,
        root_event_id=root_event_id,
        failed_capability=normalized["failed_capability"] or normalized["original_capability"],
        failed_method=normalized["failed_method"],
        failed_url=normalized["failed_url"],
        http_status=normalized["http_status"],
        incident_code=normalized["incident_code"],
        reason=normalized["reason"],
        final_failure=normalized["final_failure"],
    )

    next_commands = []

    next_input = _finalize_output_payload(
        {
            **data,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "source_event_id": source_event_id,
            "event_id": source_event_id,
            "workspace_id": meta["workspace_id"],
            "workspace": meta["workspace_id"],
            "tenant_id": meta["tenant_id"],
            "app_name": meta["app_name"],
            "source": meta["source"],
            "step_index": meta["step_index"] + 1,
            "_depth": depth + 1,
            "run_record_id": effective_run_record_id,
            "linked_run": effective_linked_run,
            "parent_command_id": meta["command_id"] or meta["parent_command_id"],
            "command_id": meta["command_id"],
            "incident_record_id": normalized["incident_record_id"],
            "log_record_id": normalized["log_record_id"],
            "category": normalized["category"],
            "reason": normalized["reason"],
            "severity": normalized["severity"],
            "http_status": normalized["http_status"],
            "final_failure": normalized["final_failure"],
            "error": normalized["error"],
            "error_message": normalized["error_message"],
            "incident_message": normalized["error_message"],
            "incident_code": normalized["incident_code"],
            "original_capability": normalized["original_capability"],
            "failed_capability": normalized["failed_capability"],
            "source_capability": (
                normalized["failed_capability"]
                or normalized["original_capability"]
            ),
            "failed_url": normalized["failed_url"],
            "target_url": normalized["failed_url"],
            "http_target": normalized["failed_url"],
            "url": normalized["failed_url"],
            "failed_method": normalized["failed_method"],
            "method": normalized["failed_method"],
            "retry_count": normalized["retry_count"],
            "retry_max": normalized["retry_max"],
            "goal": _to_str(data.get("goal") or "").strip(),
            "decision": _to_str(data.get("decision") or "").strip(),
            "decision_status": decision_status,
            "decision_reason": decision_reason,
            "next_action": next_action,
            "auto_executable": auto_executable,
            "priority_score": priority_score,
            "incident_key": incident_key,
        }
    )

    if routing["route"] == "incident":
        next_commands.append(
            _finalize_output_payload(
                {
                    "capability": "incident_deduplicate",
                    "priority": 1,
                    "input": next_input,
                }
            )
        )

    return _finalize_output_payload(
        {
            "ok": True,
            "capability": "incident_router_v2",
            "status": "done",
            "ts": _now_ts(),
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "source_event_id": source_event_id,
            "run_record_id": effective_run_record_id,
            "linked_run": effective_linked_run,
            "command_id": meta["command_id"],
            "parent_command_id": meta["parent_command_id"],
            "route": routing["route"],
            "reason": routing["reason"],
            "normalized_category": normalized["category"],
            "normalized_reason": normalized["reason"],
            "normalized_severity": normalized["severity"],
            "normalized_http_status": normalized["http_status"],
            "final_failure": normalized["final_failure"],
            "decision_status": decision_status,
            "decision_reason": decision_reason,
            "next_action": next_action,
            "auto_executable": auto_executable,
            "priority_score": priority_score,
            "incident_key": incident_key,
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
