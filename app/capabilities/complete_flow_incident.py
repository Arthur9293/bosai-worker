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

    next_commands = []

    if incident_record_id:
        next_commands.append(
            {
                "capability": "resolve_incident",
                "priority": 1,
                "input": {
                    "incident_record_id": incident_record_id,
                },
            }
        )

    return {
        "ok": True,
        "capability": "complete_flow_incident",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "completed": True,
        "message": "incident_flow_completed",
        "closed_at": _now_ts(),
        "run_record_id": run_record_id,
        "next_commands": next_commands,
        "terminal": len(next_commands) == 0,
        "spawn_summary": {
            "ok": True,
            "spawned": len(next_commands),
            "skipped": 0,
            "errors": [],
        },
    }
