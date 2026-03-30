# app/capabilities/incident_decision_engine.py
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
            or payload.get("parentcommandid")
            or payload.get("parentCommandId")
            or ""
        ).strip(),
        "command_id": _to_str(
            payload.get("command_id")
            or payload.get("commandid")
            or payload.get("commandId")
            or payload.get("parent_command_id")
            or payload.get("parentcommandid")
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
    }


def _normalize_category(data: Dict[str, Any]) -> str:
    return _to_str(
        data.get("category")
        or data.get("Category")
        or "unknown_incident"
    ).strip().lower()


def _normalize_reason(data: Dict[str, Any]) -> str:
    return _to_str(
        data.get("reason")
        or data.get("Reason")
        or ""
    ).strip().lower()


def _normalize_severity(data: Dict[str, Any]) -> str:
    return _to_str(
        data.get("severity")
        or data.get("Severity")
        or "medium"
    ).strip().lower()


def _normalize_sla_status(data: Dict[str, Any]) -> str:
    return _to_str(
        data.get("sla_status")
        or data.get("SLA_Status")
        or data.get("slaStatus")
        or data.get("SLA")
        or ""
    ).strip().lower()


def _decision_for_incident(data: Dict[str, Any]) -> Dict[str, Any]:
    category = _normalize_category(data)
    reason = _normalize_reason(data)
    severity = _normalize_severity(data)
    sla_status = _normalize_sla_status(data)
    final_failure = _to_bool(
        data.get("final_failure")
        if data.get("final_failure") is not None
        else data.get("finalfailure"),
        False,
    )
    auto_resolve = _to_bool(
        data.get("auto_resolve")
        if data.get("auto_resolve") is not None
        else data.get("autoresolve"),
        False,
    )
    http_status = _to_int(
        data.get("http_status")
        if data.get("http_status") is not None
        else data.get("httpstatus"),
        0,
    )

    decision_status = "Monitor"
    decision_reason = "default_monitoring_rule"
    next_action = "none"
    auto_executable = False
    priority_score = 40

    if sla_status == "breached":
        decision_status = "Escalate"
        decision_reason = "sla_breached"
        next_action = "internal_escalate"
        auto_executable = True
        priority_score = 95

    elif category == "http_failure" and reason in {
        "http_5xx_exhausted",
        "http_status_error",
        "forbidden_host",
    }:
        if final_failure or http_status >= 500 or severity in {"critical", "high"}:
            decision_status = "Escalate"
            decision_reason = "http_failure_exhausted_or_severe"
            next_action = "internal_escalate"
            auto_executable = True
            priority_score = 90 if severity == "critical" else 80
        else:
            decision_status = "Action_Required"
            decision_reason = "http_failure_needs_retry_strategy"
            next_action = "retry_with_backoff"
            auto_executable = False
            priority_score = 70

    elif auto_resolve:
        decision_status = "Resolved"
        decision_reason = "auto_resolve_requested"
        next_action = "resolve_incident"
        auto_executable = True
        priority_score = 20

    elif severity in {"medium", "warning"}:
        decision_status = "Monitor"
        decision_reason = "medium_severity_monitoring"
        next_action = "none"
        auto_executable = False
        priority_score = 45

    elif severity in {"low"}:
        decision_status = "No_Action"
        decision_reason = "low_severity_no_action"
        next_action = "none"
        auto_executable = False
        priority_score = 10

    return {
        "decision_status": decision_status,
        "decision_reason": decision_reason,
        "next_action": next_action,
        "auto_executable": auto_executable,
        "priority_score": priority_score,
        "normalized_category": category,
        "normalized_reason": reason,
        "normalized_severity": severity,
        "normalized_sla_status": sla_status,
    }


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

    data = _extract_input(payload)
    meta = _extract_meta(data)

    depth = _to_int(meta.get("depth"), 0)
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
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

    effective_flow_id = _to_str(meta.get("flow_id", "")).strip()
    effective_root_event_id = _to_str(meta.get("root_event_id", "")).strip()
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

    current_incident_record_id = _to_str(
        data.get("incident_record_id")
        or data.get("incidentrecordid")
        or data.get("Incident_Record_ID")
        or ""
    ).strip()

    decision = _decision_for_incident(data)

    next_commands = []
    next_action = decision["next_action"]
    auto_executable = bool(decision["auto_executable"])

    next_input = {
        "flow_id": effective_flow_id,
        "root_event_id": effective_root_event_id,
        "step_index": _to_int(meta.get("step_index"), 0) + 1,
        "_depth": depth + 1,
        "workspace_id": meta.get("workspace_id", ""),
        "tenant_id": meta.get("tenant_id", ""),
        "app_name": meta.get("app_name", ""),
        "run_record_id": effective_run_record_id,
        "command_id": effective_command_id,
        "parent_command_id": effective_command_id,
        "incident_record_id": current_incident_record_id,
        "category": _to_str(data.get("category") or ""),
        "reason": _to_str(data.get("reason") or ""),
        "severity": _to_str(data.get("severity") or ""),
        "sla_status": _to_str(data.get("sla_status") or ""),
        "http_status": data.get("http_status"),
        "failed_url": _to_str(
            data.get("failed_url")
            or data.get("target_url")
            or data.get("url")
            or ""
        ),
        "failed_capability": _to_str(
            data.get("failed_capability")
            or data.get("original_capability")
            or ""
        ),
        "final_failure": _to_bool(
            data.get("final_failure")
            if data.get("final_failure") is not None
            else data.get("finalfailure"),
            False,
        ),
        "decision_status": decision["decision_status"],
        "decision_reason": decision["decision_reason"],
        "next_action": decision["next_action"],
        "auto_executable": decision["auto_executable"],
        "priority_score": decision["priority_score"],
        "normalized_category": decision["normalized_category"],
        "normalized_reason": decision["normalized_reason"],
        "normalized_severity": decision["normalized_severity"],
        "normalized_sla_status": decision["normalized_sla_status"],
    }

    if auto_executable and next_action == "internal_escalate":
        if current_incident_record_id:
            next_commands.append(
                {
                    "capability": "internal_escalate",
                    "priority": 1,
                    "input": next_input,
                }
            )
        else:
            next_commands.append(
                {
                    "capability": "incident_create",
                    "priority": 1,
                    "input": {
                        **next_input,
                        "goal": "create_incident_before_escalation",
                    },
                }
            )

    elif auto_executable and next_action == "resolve_incident":
        if current_incident_record_id:
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
                    "capability": "incident_create",
                    "priority": 1,
                    "input": {
                        **next_input,
                        "goal": "create_incident_before_resolution",
                    },
                }
            )

    return {
        "ok": True,
        "capability": "incident_decision_engine",
        "status": "done",
        "ts": _now_ts(),
        "flow_id": effective_flow_id,
        "root_event_id": effective_root_event_id,
        "run_record_id": effective_run_record_id,
        "command_id": effective_command_id,
        "incident_record_id": current_incident_record_id,
        "decision_status": decision["decision_status"],
        "decision_reason": decision["decision_reason"],
        "next_action": decision["next_action"],
        "auto_executable": decision["auto_executable"],
        "priority_score": decision["priority_score"],
        "normalized_category": decision["normalized_category"],
        "normalized_reason": decision["normalized_reason"],
        "normalized_severity": decision["normalized_severity"],
        "normalized_sla_status": decision["normalized_sla_status"],
        "next_commands": next_commands,
        "terminal": False,
        "spawn_summary": {
            "ok": True,
            "spawned": len(next_commands),
            "skipped": 0,
            "errors": [],
        },
    }
