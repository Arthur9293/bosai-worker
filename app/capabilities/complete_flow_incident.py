from __future__ import annotations

import time
from typing import Any, Dict, Optional


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(v: Any) -> str:
    try:
        return str(v or "")
    except Exception:
        return ""


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

    flow_id = _to_str(payload.get("flow_id"))
    root_event_id = _to_str(payload.get("root_event_id"))
    incident_record_id = _to_str(
        payload.get("incident_record_id")
        or payload.get("incidentrecordid")
    ).strip()

    severity = _to_str(payload.get("severity")).strip().lower()
    final_failure = _to_bool(
        payload.get("final_failure")
        if payload.get("final_failure") is not None
        else payload.get("finalfailure"),
        False,
    )

    auto_resolve = False
    decision = "keep_escalated"
    next_commands = []

    if incident_record_id and severity in {"low", "medium"} and not final_failure:
        auto_resolve = True
        decision = "auto_resolve"
        next_commands.append(
            {
                "capability": "resolve_incident",
                "priority": 1,
                "input": {
                    "incident_record_id": incident_record_id,
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                },
            }
        )

    return {
        "ok": True,
        "capability": "complete_flow_incident",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "incident_record_id": incident_record_id,
        "completed": True,
        "message": "incident_flow_completed",
        "closed_at": _now_ts(),
        "run_record_id": run_record_id,
        "decision": decision,
        "auto_resolve": auto_resolve,
        "severity": severity,
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
