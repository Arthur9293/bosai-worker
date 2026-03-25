# app/capabilities/chaos_guard.py
# BOSAI — Chaos Guard V1 (SAFE / READ-ONLY)

from __future__ import annotations

from typing import Any, Dict, List


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _to_str(v: Any) -> str:
    try:
        return str(v or "").strip()
    except Exception:
        return ""


def _safe_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


# ------------------------------------------------------------
# Core Chaos Guard
# ------------------------------------------------------------

def capability_chaos_guard(req, run_record_id: str) -> Dict[str, Any]:
    payload = req.input or {}

    flow_id = _to_str(payload.get("flow_id"))
    root_event_id = _to_str(payload.get("root_event_id"))
    workspace_id = _to_str(payload.get("workspace_id") or "production")

    step_index = _to_int(payload.get("step_index"), 0)
    retry_count = _to_int(payload.get("retry_count"), 0)
    retry_max = _to_int(payload.get("retry_max"), 2)

    last_capability = _to_str(payload.get("original_capability"))
    last_error = _to_str(payload.get("error"))
    http_status = payload.get("http_status")

    failed_url = _to_str(payload.get("failed_url"))

    # ------------------------------------------------------------
    # Default decision
    # ------------------------------------------------------------
    decision = "allow_continue"
    reason = "no_issue_detected"
    risk_level = "low"
    terminal = False
    next_commands: List[Dict[str, Any]] = []

    # ------------------------------------------------------------
    # RULE 1 — Step overflow
    # ------------------------------------------------------------
    if step_index > 10:
        decision = "max_depth_reached"
        reason = "step_index_overflow"
        risk_level = "high"

    # ------------------------------------------------------------
    # RULE 2 — Retry overflow
    # ------------------------------------------------------------
    elif retry_count > retry_max:
        decision = "retry_policy_broken"
        reason = "retry_count_exceeds_max"
        risk_level = "critical"

        next_commands = [
            {
                "capability": "incident_router",
                "priority": 3,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": step_index + 1,
                    "goal": "chaos_retry_violation",
                    "reason": "retry_policy_broken",
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "workspace_id": workspace_id,
                    "run_record_id": run_record_id,
                },
            }
        ]

    # ------------------------------------------------------------
    # RULE 3 — Suspicious retry storm
    # ------------------------------------------------------------
    elif retry_count >= retry_max:
        decision = "retry_limit_reached"
        reason = "retry_exhaustion"
        risk_level = "high"

    # ------------------------------------------------------------
    # RULE 4 — HTTP failure storm
    # ------------------------------------------------------------
    elif http_status is not None:
        try:
            status = int(http_status)
            if status >= 500:
                decision = "server_error_detected"
                reason = f"http_{status}"
                risk_level = "medium"
        except Exception:
            pass

    # ------------------------------------------------------------
    # RULE 5 — Missing critical fields
    # ------------------------------------------------------------
    if last_capability == "http_exec" and not failed_url:
        decision = "invalid_http_exec_payload"
        reason = "missing_url"
        risk_level = "high"

    # ------------------------------------------------------------
    # SAFE OUTPUT
    # ------------------------------------------------------------
    return {
        "ok": True,
        "capability": "chaos_guard",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "step_index": step_index,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "decision": decision,
        "reason": reason,
        "risk_level": risk_level,
        "last_capability": last_capability,
        "http_status": http_status,
        "failed_url": failed_url,
        "next_commands": next_commands,
        "terminal": terminal,
        "run_record_id": run_record_id,
    }
