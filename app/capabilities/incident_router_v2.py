# app/capabilities/incident_router_v2.py

from __future__ import annotations

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


def _extract_input(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    for key in ("input", "event", "data", "command_input", "incident"):
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
            or payload.get("id")
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
        "command_id": _to_str(
            payload.get("command_id")
            or payload.get("commandid")
            or payload.get("commandId")
            or ""
        ).strip(),
        "parent_command_id": _to_str(
            payload.get("parent_command_id")
            or payload.get("parentcommandid")
            or payload.get("parentCommandId")
            or payload.get("command_id")
            or payload.get("commandid")
            or payload.get("commandId")
            or ""
        ).strip(),
        "workspace_id": _to_str(
            payload.get("workspace_id")
            or payload.get("workspaceid")
            or payload.get("workspaceId")
            or payload.get("workspace")
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
            or "bosai-worker"
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
            else payload.get("depth")
            if payload.get("depth") is not None
            else 0,
            0,
        ),
        "source": _to_str(
            payload.get("source")
            or payload.get("Source")
            or "incident_router_v2"
        ).strip(),
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
    final_failure = _to_bool(
        data.get("final_failure")
        if data.get("final_failure") is not None
        else data.get("finalfailure"),
        False,
    )

    if http_status >= 500 and (final_failure or retry_count >= retry_max):
        return "http_5xx_exhausted"

    if http_status >= 500:
        return "http_status_error"

    if incident_code:
        return incident_code

    return "incident_detected"


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
    final_failure = _to_bool(
        data.get("final_failure")
        if data.get("final_failure") is not None
        else data.get("finalfailure"),
        False,
    )

    if http_status >= 500 and final_failure:
        return "high"
    if http_status >= 500:
        return "medium"

    return "medium"


def _normalize_event(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "category": _normalize_category(data),
        "reason": _normalize_reason(data),
        "severity": _normalize_severity(data),
        "http_status": _to_int(
            data.get("http_status")
            if data.get("http_status") is not None
            else data.get("httpstatus"),
            0,
        ),
        "final_failure": _to_bool(
            data.get("final_failure")
            if data.get("final_failure") is not None
            else data.get("finalfailure"),
            False,
        ),
        "error": _to_str(
            data.get("error")
            or data.get("error_message")
            or data.get("errormessage")
            or data.get("message")
            or ""
        ).strip(),
        "incident_code": _to_str(
            data.get("incident_code")
            or data.get("incidentcode")
            or ""
        ).strip(),
        "failed_capability": _to_str(
            data.get("failed_capability")
            or data.get("failedcapability")
            or data.get("original_capability")
            or data.get("originalcapability")
            or ""
        ).strip(),
        "failed_url": _to_str(
            data.get("failed_url")
            or data.get("failedurl")
            or data.get("target_url")
            or data.get("targeturl")
            or data.get("http_target")
            or data.get("url")
            or data.get("URL")
            or ""
        ).strip(),
        "failed_method": _to_str(
            data.get("failed_method")
            or data.get("failedmethod")
            or data.get("method")
            or data.get("HTTP_Method")
            or data.get("HTTPMethod")
            or "GET"
        ).strip().upper(),
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
            or data.get("Incident_Record_ID")
            or ""
        ).strip(),
        "log_record_id": _to_str(
            data.get("log_record_id")
            or data.get("logrecordid")
            or ""
        ).strip(),
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


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    **kwargs: Any,
) -> Dict[str, Any]:
    payload = getattr(req, "input", {}) if hasattr(req, "input") else req or {}
    data = _extract_input(payload)
    meta = _extract_meta(data)

    depth = meta["depth"]
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "incident_router_v2",
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
        or ""
    ).strip()

    flow_id = meta["flow_id"] or f"flow_router_{_now_ts()}"
    root_event_id = meta["root_event_id"] or flow_id

    normalized = _normalize_event(data)
    routing = _route(normalized)

    next_commands = []

    next_input = {
        **data,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "event_id": root_event_id,
        "workspace_id": meta["workspace_id"],
        "workspace": meta["workspace_id"],
        "tenant_id": meta["tenant_id"],
        "app_name": meta["app_name"],
        "source": meta["source"],
        "step_index": meta["step_index"] + 1,
        "_depth": depth + 1,
        "run_record_id": effective_run_record_id,
        "parent_command_id": meta["parent_command_id"],
        "command_id": meta["command_id"],
        "incident_record_id": normalized["incident_record_id"],
        "log_record_id": normalized["log_record_id"],
        "category": normalized["category"],
        "reason": normalized["reason"],
        "severity": normalized["severity"],
        "http_status": normalized["http_status"],
        "final_failure": normalized["final_failure"],
        "error": normalized["error"],
        "error_message": normalized["error"],
        "incident_code": normalized["incident_code"],
        "original_capability": normalized["failed_capability"],
        "failed_capability": normalized["failed_capability"],
        "failed_url": normalized["failed_url"],
        "target_url": normalized["failed_url"],
        "http_target": normalized["failed_url"],
        "failed_method": normalized["failed_method"],
        "method": normalized["failed_method"],
        "retry_count": normalized["retry_count"],
        "retry_max": normalized["retry_max"],
        "goal": "incident_router_v2_test",
        "decision": "",
    }

    if routing["route"] == "incident":
        next_commands.append(
            {
                "capability": "incident_deduplicate",
                "priority": 1,
                "input": next_input,
            }
        )

    return {
        "ok": True,
        "capability": "incident_router_v2",
        "status": "done",
        "ts": _now_ts(),
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "run_record_id": effective_run_record_id,
        "route": routing["route"],
        "reason": routing["reason"],
        "normalized_category": normalized["category"],
        "normalized_reason": normalized["reason"],
        "normalized_severity": normalized["severity"],
        "normalized_http_status": normalized["http_status"],
        "final_failure": normalized["final_failure"],
        "next_commands": next_commands,
        "terminal": False,
        "spawn_summary": {
            "ok": True,
            "spawned": len(next_commands),
            "skipped": 0,
            "errors": [],
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "max_depth": DEFAULT_MAX_DEPTH,
        },
    }
