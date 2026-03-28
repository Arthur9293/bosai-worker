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

    return {
        "ok": True,
        "capability": "complete_flow_incident",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "completed": True,
        "message": "incident_flow_completed",
        "closed_at": _now_ts(),
        "run_record_id": run_record_id,
        "terminal": True,
        "spawn_summary": {
            "ok": True,
            "spawned": 0,
            "skipped": 0,
            "errors": [],
        },
    }
