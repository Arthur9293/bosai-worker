from __future__ import annotations

import time
from copy import deepcopy
from typing import Any, Dict, List, Optional

DEFAULT_MAX_DEPTH = 8


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


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


def _to_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


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
        "parent_capability": _to_str(
            payload.get("parent_capability")
            or payload.get("parentcapability")
            or payload.get("parentCapability")
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
        "retry_count": _to_int(
            payload.get("retry_count")
            if payload.get("retry_count") is not None
            else payload.get("retrycount")
            if payload.get("retrycount") is not None
            else payload.get("retryCount"),
            0,
        ),
        "retry_max": _to_int(
            payload.get("retry_max")
            if payload.get("retry_max") is not None
            else payload.get("retrymax")
            if payload.get("retrymax") is not None
            else payload.get("retryMax"),
            0,
        ),
        "depth": _to_int(
            payload.get("depth")
            if payload.get("depth") is not None
            else payload.get("_depth")
            if payload.get("_depth") is not None
            else payload.get("Depth"),
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
        "source": _to_str(payload.get("source") or "incident_router"),
    }


def _normalize_incident(payload: Dict[str, Any]) -> Dict[str, Any]:
    error_obj = _safe_dict(payload.get("error"))
    request_obj = _safe_dict(payload.get("request"))
    response_obj = _safe_dict(payload.get("response"))
    http_meta = _safe_dict(payload.get("http"))
    incident_meta = _safe_dict(payload.get("incident_meta"))
    diagnostics = _safe_dict(payload.get("diagnostics"))
    result_obj = _safe_dict(payload.get("result"))

    http_status = (
        payload.get("http_status")
        if payload.get("http_status") is not None
        else payload.get("httpstatus")
        if payload.get("httpstatus") is not None
        else response_obj.get("status_code")
    )
    if http_status is None:
        http_status = error_obj.get("http_status")
    if http_status is None:
        http_status = http_meta.get("status_code")
    if http_status is None:
        http_status = result_obj.get("http_status")

    incident_code = (
        payload.get("incident_code")
        or payload.get("incidentcode")
        or error_obj.get("incident_code")
        or error_obj.get("code")
        or diagnostics.get("incident_code")
        or incident_meta.get("incident_code")
        or ""
    )

    final_failure = (
        payload.get("final_failure")
        if payload.get("final_failure") is not None
        else payload.get("finalfailure")
        if payload.get("finalfailure") is not None
        else error_obj.get("final_failure")
        if error_obj.get("final_failure") is not None
        else diagnostics.get("final_failure")
        if diagnostics.get("final_failure") is not None
        else False
    )

    incident_code_normalized = _to_str(incident_code).strip()
    incident_code_normalized = incident_code_normalized.replace(" ", "_").lower()

    normalized = {
        "ts": _now_ts(),
        "http_status": _to_int(http_status, 0) if http_status not in (None, "") else 0,
        "incident_code": incident_code_normalized,
        "final_failure": _to_bool(final_failure, False),
        "error_message": _to_str(
            payload.get("incident_message")
            or payload.get("error_message")
            or payload.get("errormessage")
            or payload.get("error")
            or error_obj.get("message")
            or error_obj.get("error")
            or payload.get("message")
            or diagnostics.get("message")
            or diagnostics.get("error")
            or ""
        ),
        "failed_capability": _to_str(
            payload.get("failed_capability")
            or payload.get("failedcapability")
            or payload.get("capability")
            or error_obj.get("capability")
            or payload.get("source_capability")
            or payload.get("original_capability")
            or ""
        ),
        "target_url": _to_str(
            payload.get("target_url")
            or payload.get("targeturl")
            or payload.get("failed_url")
            or payload.get("failedurl")
            or request_obj.get("url")
            or http_meta.get("url")
            or payload.get("url")
            or ""
        ),
        "method": _to_str(
            payload.get("method")
            or payload.get("failed_method")
            or payload.get("failedmethod")
            or request_obj.get("method")
            or http_meta.get("method")
            or "GET"
        ).upper(),
        "log_record_id": _to_str(
            payload.get("log_record_id")
            or payload.get("logrecordid")
            or payload.get("incident_record_id")
            or payload.get("incidentrecordid")
            or ""
        ),
        "raw_payload": deepcopy(payload),
    }

    print("[incident_router] normalized =", normalized)
    return normalized


def _classify_incident(incident: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    http_status = _to_int(incident.get("http_status"), 0)
    incident_code = _to_str(incident.get("incident_code")).strip().lower()
    final_failure = _to_bool(incident.get("final_failure"), False)
    retry_count = _to_int(meta.get("retry_count"), 0)
    retry_max = _to_int(meta.get("retry_max"), 0)

    decision = "log_only"
    reason = "unclassified_incident"
    severity = "medium"
    category = "unknown_incident"

    if 500 <= http_status <= 599:
        if final_failure or retry_count >= retry_max:
            decision = "escalate"
            reason = "http_5xx_exhausted"
            severity = "high"
            category = "http_failure"
        else:
            decision = "retry"
            reason = "http_5xx_retryable"
            severity = "medium"
            category = "http_failure"

    elif incident_code == "timeout":
        if final_failure or retry_count >= retry_max:
            decision = "escalate"
            reason = "timeout_exhausted"
            severity = "high"
            category = "timeout"
        else:
            decision = "retry"
            reason = "timeout_retryable"
            severity = "medium"
            category = "timeout"

    elif http_status == 429:
        if final_failure or retry_count >= retry_max:
            decision = "escalate"
            reason = "rate_limit_exhausted"
            severity = "medium"
            category = "rate_limit"
        else:
            decision = "retry"
            reason = "rate_limit_retryable"
            severity = "low"
            category = "rate_limit"

    elif incident_code in {"auth_error", "permission_denied", "forbidden"}:
        decision = "escalate"
        reason = "authorization_failure"
        severity = "high"
        category = "auth_failure"

    elif 400 <= http_status <= 499:
        decision = "log_only"
        reason = "client_error_non_retryable"
        severity = "low"
        category = "client_error"

    return {
        "decision": decision,
        "reason": reason,
        "severity": severity,
        "category": category,
    }


def _build_incident_key(meta: Dict[str, Any], incident: Dict[str, Any], classification: Dict[str, Any]) -> str:
    return "|".join(
        [
            _to_str(meta.get("flow_id") or "no_flow"),
            _to_str(meta.get("root_event_id") or "no_root"),
            _to_str(incident.get("failed_capability") or "no_cap"),
            _to_str(incident.get("method") or "no_method").upper(),
            _to_str(incident.get("target_url") or "no_url"),
            _to_str(incident.get("http_status") or "no_status"),
            _to_str(incident.get("incident_code") or "no_incident_code"),
            _to_str(classification.get("reason") or "no_reason"),
            "final" if _to_bool(incident.get("final_failure"), False) else "not_final",
        ]
    )


def _build_escalate_command(
    meta: Dict[str, Any],
    incident: Dict[str, Any],
    classification: Dict[str, Any],
) -> Dict[str, Any]:
    incident_key = _build_incident_key(meta, incident, classification)

    return {
        "capability": "incident_deduplicate",
        "priority": 1,
        "input": {
            "flow_id": meta.get("flow_id", ""),
            "root_event_id": meta.get("root_event_id", ""),
            "event_id": meta.get("root_event_id", ""),
            "parent_capability": "incident_router",
            "parent_command_id": meta.get("parent_command_id", ""),
            "step_index": _to_int(meta.get("step_index"), 0) + 1,
            "_depth": _to_int(meta.get("depth"), 0) + 1,
            "workspace_id": meta.get("workspace_id", ""),
            "tenant_id": meta.get("tenant_id", ""),
            "app_name": meta.get("app_name", ""),
            "source": "incident_router",
            "goal": "incident_deduplicate",
            "decision": classification.get("decision", ""),
            "reason": classification.get("reason", ""),
            "severity": classification.get("severity", ""),
            "category": classification.get("category", ""),
            "error": incident.get("error_message", ""),
            "error_message": incident.get("error_message", ""),
            "incident_code": incident.get("incident_code", ""),
            "final_failure": incident.get("final_failure", False),
            "original_capability": incident.get("failed_capability", ""),
            "failed_capability": incident.get("failed_capability", ""),
            "target_url": incident.get("target_url", ""),
            "failed_url": incident.get("target_url", ""),
            "method": incident.get("method", ""),
            "failed_method": incident.get("method", ""),
            "retry_count": _to_int(meta.get("retry_count"), 0),
            "retry_max": _to_int(meta.get("retry_max"), 0),
            "http_status": incident.get("http_status", 0),
            "incident_record_id": "",
            "log_record_id": incident.get("log_record_id", ""),
            "run_record_id": "",
            "incident_key": incident_key,
        },
    }


def _build_next_commands(
    meta: Dict[str, Any],
    incident: Dict[str, Any],
    classification: Dict[str, Any],
) -> List[Dict[str, Any]]:
    decision = _to_str(classification.get("decision"))
    depth = _to_int(meta.get("depth"), 0)

    if depth >= DEFAULT_MAX_DEPTH:
        return []

    if decision == "escalate":
        return [_build_escalate_command(meta, incident, classification)]

    if decision == "retry":
        return []

    return []


def run(
    payload: Optional[Any] = None,
    context: Optional[Any] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    if payload is not None and hasattr(payload, "input"):
        payload = getattr(payload, "input", {}) or {}
    elif not isinstance(payload, dict):
        payload = {}

    data = _extract_input(payload or {})
    meta = _extract_meta(data)
    incident = _normalize_incident(data)
    classification = _classify_incident(incident, meta)

    next_commands = _build_next_commands(meta, incident, classification)

    result = {
        "ok": True,
        "capability": "incident_router",
        "status": "done",
        "run_record_id": _to_str(data.get("run_record_id") or ""),
        "workspace_id": meta.get("workspace_id", ""),
        "flow_id": meta.get("flow_id", ""),
        "root_event_id": meta.get("root_event_id", ""),
        "step_index": meta.get("step_index", 0),
        "goal": _to_str(data.get("goal") or ""),
        "decision": classification.get("decision", "log_only"),
        "reason": classification.get("reason", "unclassified_incident"),
        "severity": classification.get("severity", "medium"),
        "category": classification.get("category", "unknown_incident"),
        "error": incident.get("error_message", ""),
        "incident_code": incident.get("incident_code", ""),
        "final_failure": incident.get("final_failure", False),
        "original_capability": incident.get("failed_capability", ""),
        "failed_url": incident.get("target_url", ""),
        "failed_method": incident.get("method", ""),
        "retry_count": meta.get("retry_count", 0),
        "retry_max": meta.get("retry_max", 0),
        "http_status": incident.get("http_status", 0),
        "incident_record_id": "",
        "log_record_id": incident.get("log_record_id", ""),
        "incident_create_ok": False,
        "spawned_count": len(next_commands),
        "next_commands": next_commands[:1],
        "guards": {
            "max_spawn": 1,
            "never_respawn_incident_router": True,
            "never_retry_http_exec_directly": True,
            "depth_limit": DEFAULT_MAX_DEPTH,
        },
        "ts": _now_ts(),
    }

    print("[incident_router] result =", result)
    return result
