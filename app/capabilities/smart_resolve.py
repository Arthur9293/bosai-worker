from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    try:
        text = str(value).strip().lower()
    except Exception:
        return default

    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


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

    flow_id = _to_str(
        payload.get("flow_id")
        or payload.get("flowid")
        or ""
    ).strip()

    root_event_id = _to_str(
        payload.get("root_event_id")
        or payload.get("rooteventid")
        or payload.get("event_id")
        or payload.get("eventid")
        or ""
    ).strip()

    incident_record_id = _to_str(
        payload.get("incident_record_id")
        or payload.get("incidentrecordid")
        or payload.get("Incident_Record_ID")
        or ""
    ).strip()

    parent_command_id = _to_str(
        payload.get("parent_command_id")
        or payload.get("parentcommandid")
        or ""
    ).strip()

    step_index = _to_int(
        payload.get("step_index")
        if payload.get("step_index") is not None
        else payload.get("stepindex"),
        0,
    )

    depth = _to_int(
        payload.get("_depth")
        if payload.get("_depth") is not None
        else payload.get("depth"),
        0,
    )

    workspace_id = _to_str(
        payload.get("workspace_id")
        or payload.get("workspaceid")
        or "production"
    ).strip()

    tenant_id = _to_str(
        payload.get("tenant_id")
        or payload.get("tenantid")
        or ""
    ).strip()

    app_name = _to_str(
        payload.get("app_name")
        or payload.get("appname")
        or ""
    ).strip()

    severity = _to_str(payload.get("severity")).strip().lower()
    final_failure = _to_bool(
        payload.get("final_failure")
        if payload.get("final_failure") is not None
        else payload.get("finalfailure"),
        False,
    )

    reason = _to_str(payload.get("reason") or "smart_resolve").strip()
    category = _to_str(payload.get("category") or "").strip()
    failed_url = _to_str(
        payload.get("failed_url")
        or payload.get("target_url")
        or ""
    ).strip()
    http_status = payload.get("http_status")
    resolution_note = _to_str(
        payload.get("resolution_note")
        or payload.get("resolutionnote")
        or ""
    ).strip()

    auto_resolve = severity in {"low", "medium"} and not final_failure

    next_commands: List[Dict[str, Any]] = []

    if auto_resolve:
        next_commands.append(
            {
                "capability": "resolve_incident",
                "priority": 1,
                "input": {
                    "incident_record_id": incident_record_id,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "parent_command_id": parent_command_id,
                    "step_index": step_index + 1,
                    "_depth": depth + 1,
                    "workspace_id": workspace_id,
                    "tenant_id": tenant_id,
                    "app_name": app_name,
                    "resolution_note": resolution_note or "resolved_by_smart_resolve",
                    "reason": reason,
                    "category": category,
                },
            }
        )
        decision = "resolve"
        message = "smart_resolve_routed_to_resolve_incident"
    else:
        next_commands.append(
            {
                "capability": "internal_escalate",
                "priority": 1,
                "input": {
                    "incident_record_id": incident_record_id,
                    "log_record_id": _to_str(
                        payload.get("log_record_id")
                        or payload.get("logrecordid")
                        or incident_record_id
                    ).strip(),
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "parent_command_id": parent_command_id,
                    "step_index": step_index + 1,
                    "_depth": depth + 1,
                    "workspace_id": workspace_id,
                    "tenant_id": tenant_id,
                    "app_name": app_name,
                    "severity": severity or "high",
                    "final_failure": final_failure,
                    "reason": reason or "smart_resolve_escalation",
                    "goal": "incident_escalation",
                    "category": category,
                    "failed_url": failed_url,
                    "http_status": http_status,
                },
            }
        )
        decision = "escalate"
        message = "smart_resolve_routed_to_internal_escalate"

    return {
        "ok": True,
        "capability": "smart_resolve",
        "status": "done",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "incident_record_id": incident_record_id,
        "run_record_id": _to_str(run_record_id),
        "decision": decision,
        "auto_resolve": auto_resolve,
        "severity": severity,
        "final_failure": final_failure,
        "message": message,
        "evaluated_at": _now_ts(),
        "next_commands": next_commands,
        "terminal": False,
        "spawn_summary": {
            "ok": True,
            "spawned": len(next_commands),
            "skipped": 0,
            "errors": [],
        },
    }
