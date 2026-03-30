# app/capabilities/incident_router_v2.py

from __future__ import annotations

import time
from typing import Any, Dict, Optional


DEFAULT_MAX_DEPTH = 8


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(v: Any, d: str = "") -> str:
    try:
        return str(v) if v is not None else d
    except:
        return d


def _to_int(v: Any, d: int = 0) -> int:
    try:
        return int(v)
    except:
        return d


def _to_bool(v: Any, d: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return d
    return str(v).lower() in ["1", "true", "yes"]


def _extract_input(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    for k in ("input", "event", "data"):
        if isinstance(payload.get(k), dict):
            merged = dict(payload)
            merged.update(payload[k])
            return merged

    return payload


def _extract_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "flow_id": _to_str(payload.get("flow_id")),
        "root_event_id": _to_str(
            payload.get("root_event_id")
            or payload.get("event_id")
            or payload.get("id")
        ),
        "run_record_id": _to_str(
            payload.get("run_record_id")
            or payload.get("linked_run")
        ),
        "workspace_id": _to_str(payload.get("workspace_id") or "production"),
        "step_index": _to_int(payload.get("step_index"), 0),
        "depth": _to_int(payload.get("_depth") or payload.get("depth"), 0),
    }


# -----------------------------------
# NORMALISATION
# -----------------------------------

def _normalize_event(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "category": _to_str(data.get("category") or data.get("type") or "unknown").lower(),
        "severity": _to_str(data.get("severity") or "medium").lower(),
        "http_status": _to_int(data.get("http_status")),
        "final_failure": _to_bool(data.get("final_failure")),
        "error": _to_str(data.get("error") or data.get("message")),
    }


# -----------------------------------
# ROUTING LOGIC
# -----------------------------------

def _route(normalized: Dict[str, Any]) -> Dict[str, Any]:
    category = normalized["category"]
    severity = normalized["severity"]
    http_status = normalized["http_status"]
    final_failure = normalized["final_failure"]

    # Cas HTTP critique
    if category == "http_failure" or http_status >= 500:
        return {
            "route": "incident",
            "reason": "http_failure_detected"
        }

    # Cas critique
    if severity in ["critical", "high"] and final_failure:
        return {
            "route": "incident",
            "reason": "critical_failure"
        }

    # Cas warning
    if severity in ["medium", "warning"]:
        return {
            "route": "monitor",
            "reason": "non_blocking_issue"
        }

    return {
        "route": "ignore",
        "reason": "not_an_incident"
    }


# -----------------------------------
# MAIN
# -----------------------------------

def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    **kwargs
) -> Dict[str, Any]:

    payload = getattr(req, "input", {}) if hasattr(req, "input") else req or {}
    data = _extract_input(payload)
    meta = _extract_meta(data)

    depth = meta["depth"]
    if depth >= DEFAULT_MAX_DEPTH:
        return {"ok": False, "error": "max_depth_reached", "terminal": True}

    flow_id = meta["flow_id"] or f"flow_router_{_now_ts()}"
    root_event_id = meta["root_event_id"] or flow_id

    normalized = _normalize_event(data)
    routing = _route(normalized)

    next_commands = []

    next_input = {
        **data,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "step_index": meta["step_index"] + 1,
        "_depth": depth + 1,
        "run_record_id": run_record_id,
    }

    if routing["route"] == "incident":
        next_commands.append({
            "capability": "incident_decision_engine",
            "priority": 1,
            "input": next_input
        })

    return {
        "ok": True,
        "capability": "incident_router_v2",
        "status": "done",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "route": routing["route"],
        "reason": routing["reason"],
        "next_commands": next_commands,
        "terminal": False,
        "spawn_summary": {
            "ok": True,
            "spawned": len(next_commands),
            "skipped": 0,
            "errors": []
        }
    }
