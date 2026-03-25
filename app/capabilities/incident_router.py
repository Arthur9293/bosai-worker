# app/capabilities/incident_router.py
from __future__ import annotations

from typing import Any, Dict, Optional


# =========================
# Helpers
# =========================

def _to_payload(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    input_attr = getattr(value, "input", None)
    if isinstance(input_attr, dict):
        return input_attr
    return {}


def _to_int(value: Any) -> Optional[int]:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except Exception:
        return None


def _pick(payload: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return default


def _safe(value: str, fallback: str) -> str:
    return (value or fallback or "").strip()


# =========================
# Normalization
# =========================

def _normalize_http_status(payload: Dict[str, Any]) -> Optional[int]:
    http_status = _to_int(
        _pick(payload, "http_status", "status_code", "HTTP_Status")
    )
    if http_status is not None:
        return http_status

    response = payload.get("response")
    if isinstance(response, dict):
        return _to_int(response.get("status_code"))

    return None


def _extract_original_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    return payload.get("request") if isinstance(payload.get("request"), dict) else {}


def _normalize_failed_url(payload, original_input, original_request) -> str:
    return str(
        _pick(
            payload,
            "failed_url",
            "url",
            "http_target",
            default=(
                original_input.get("url")
                or original_request.get("url")
                or ""
            ),
        )
        or ""
    ).strip()


def _normalize_failed_method(payload, original_input, original_request) -> str:
    return str(
        _pick(
            payload,
            "failed_method",
            "method",
            default=(
                original_input.get("method")
                or original_request.get("method")
                or "GET"
            ),
        )
        or "GET"
    ).upper().strip()


# =========================
# CLEAN RETRY INPUT
# =========================

def _build_clean_retry_input(
    *,
    original_input: Dict[str, Any],
    original_request: Dict[str, Any],
    failed_url: str,
    failed_method: str,
    flow_id: str,
    root_event_id: str,
    workspace_id: str,
    retry_count: int,
    retry_max: int,
    http_status: Optional[int],
    error: str,
    reason: str,
    max_depth: int,
) -> Dict[str, Any]:

    retry_input: Dict[str, Any] = {}

    # Safe carry-over
    if isinstance(original_input, dict):
        for key in ("headers", "params", "timeout_seconds", "body", "json"):
            if key in original_input:
                retry_input[key] = original_input[key]

    if isinstance(original_request, dict):
        if "headers" not in retry_input and "headers" in original_request:
            retry_input["headers"] = original_request["headers"]

    # Core http_exec fields
    retry_input["url"] = failed_url
    retry_input["method"] = failed_method

    # BOSAI context
    retry_input["flow_id"] = flow_id
    retry_input["root_event_id"] = root_event_id
    retry_input["workspace_id"] = workspace_id

    # Retry control
    retry_input["retry_count"] = retry_count + 1
    retry_input["retry_max"] = retry_max
    retry_input["step_index"] = 0

    # Anti-chaos
    retry_input["max_depth"] = max_depth

    # Simple backoff
    retry_input["retry_delay"] = min(2 ** retry_count, 30)

    # Diagnostics
    if http_status is not None:
        retry_input["http_status"] = http_status
    if error:
        retry_input["error"] = error
    if reason:
        retry_input["retry_reason"] = reason

    return retry_input


# =========================
# MAIN CAPABILITY
# =========================

def capability_incident_router(payload: Dict[str, Any], run_record_id: str = "") -> Dict[str, Any]:

    goal = _safe(_pick(payload, "goal", "failed_goal"), "")
    error = _safe(_pick(payload, "error", "last_error"), "")
    reason = _safe(_pick(payload, "reason", "retry_reason"), "unknown")

    http_status = _normalize_http_status(payload)

    retry_count = _to_int(_pick(payload, "retry_count")) or 0
    retry_max = _to_int(_pick(payload, "retry_max")) or 0
    max_depth = _to_int(_pick(payload, "max_depth")) or 10

    flow_id = _safe(_pick(payload, "flow_id"), run_record_id)
    root_event_id = _safe(_pick(payload, "root_event_id"), flow_id)
    workspace_id = _safe(_pick(payload, "workspace_id"), "production")

    original_capability = _safe(
        _pick(payload, "original_capability", "source_capability"),
        "http_exec",
    )

    original_input = payload.get("original_input") if isinstance(payload.get("original_input"), dict) else {}
    original_request = _extract_original_request(payload)

    failed_url = _normalize_failed_url(payload, original_input, original_request)
    failed_method = _normalize_failed_method(payload, original_input, original_request)

    # =========================
    # DECISION ENGINE (ANTI-CHAOS)
    # =========================

    decision = "log_only"
    final_reason = reason

    # HARD STOP anti-loop
    if retry_max > 0 and retry_count >= retry_max:
        decision = "escalate"
        final_reason = "retry_exhausted"

    # HARD STOP anti-depth
    elif retry_count >= max_depth:
        decision = "escalate"
        final_reason = "max_depth_reached"

    elif http_status is not None:
        if 500 <= http_status <= 599:
            if retry_count < retry_max:
                decision = "retry"
                final_reason = "http_5xx"
            else:
                decision = "escalate"
                final_reason = "http_5xx_exhausted"

        elif 400 <= http_status <= 499:
            decision = "escalate"
            final_reason = "http_4xx"

    elif "timeout" in error.lower():
        if retry_count < retry_max:
            decision = "retry"
            final_reason = "timeout"
        else:
            decision = "escalate"
            final_reason = "timeout_exhausted"

    elif error:
        decision = "log_only"
        final_reason = "unknown_error"

    # =========================
    # NEXT COMMANDS
    # =========================

    next_commands = []

    if decision == "retry":
        retry_input = _build_clean_retry_input(
            original_input=original_input,
            original_request=original_request,
            failed_url=failed_url,
            failed_method=failed_method,
            flow_id=flow_id,
            root_event_id=root_event_id,
            workspace_id=workspace_id,
            retry_count=retry_count,
            retry_max=retry_max,
            http_status=http_status,
            error=error,
            reason=final_reason,
            max_depth=max_depth,
        )

        next_commands.append({
            "capability": original_capability,
            "input": retry_input,
            "priority": 2,
        })

    elif decision == "escalate":
        next_commands.append({
            "capability": "internal_escalate",
            "input": {
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "goal": goal,
                "reason": final_reason,
                "error": error,
                "http_status": http_status,
                "failed_url": failed_url,
                "failed_method": failed_method,
                "workspace_id": workspace_id,
                "retry_count": retry_count,
                "retry_max": retry_max,
                "run_record_id": run_record_id,
            },
            "priority": 1,
        })

    return {
        "ok": True,
        "capability": "incident_router",
        "status": "incident_escalated" if decision == "escalate" else "incident_logged",
        "decision": decision,
        "reason": final_reason,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "next_commands": next_commands,
        "terminal": False,
    }


def run(req: Any = None, run_record_id: str = "") -> Dict[str, Any]:
    payload = _to_payload(req)
    return capability_incident_router(payload, run_record_id)
