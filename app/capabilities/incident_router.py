# app/capabilities/incident_router.py
from __future__ import annotations

from typing import Any, Dict, Optional


# ============================================================
# Constants
# ============================================================

DEFAULT_WORKSPACE_ID = "production"
DEFAULT_ORIGINAL_CAPABILITY = "http_exec"
DEFAULT_MAX_DEPTH = 10


# ============================================================
# Helpers
# ============================================================

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


def _safe(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback.strip()
    return str(value).strip()


# ============================================================
# Normalization
# ============================================================

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


def _extract_original_input(payload: Dict[str, Any]) -> Dict[str, Any]:
    original_input = payload.get("original_input")
    if isinstance(original_input, dict):
        return original_input
    return {}


def _extract_original_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    request_obj = payload.get("request")
    if isinstance(request_obj, dict):
        return request_obj
    return {}


def _normalize_failed_url(
    payload: Dict[str, Any],
    original_input: Dict[str, Any],
    original_request: Dict[str, Any],
) -> str:
    return _safe(
        _pick(
            payload,
            "failed_url",
            "url",
            "http_target",
            default=(
                original_input.get("url")
                or original_input.get("http_target")
                or original_request.get("url")
                or original_request.get("http_target")
                or ""
            ),
        ),
        "",
    )


def _normalize_failed_method(
    payload: Dict[str, Any],
    original_input: Dict[str, Any],
    original_request: Dict[str, Any],
) -> str:
    return _safe(
        _pick(
            payload,
            "failed_method",
            "method",
            "HTTP_Method",
            default=(
                original_input.get("method")
                or original_input.get("HTTP_Method")
                or original_request.get("method")
                or original_request.get("HTTP_Method")
                or "GET"
            ),
        ),
        "GET",
    ).upper() or "GET"


def _effective_flow_id(flow_id: str, root_event_id: str, run_record_id: str) -> str:
    return (flow_id or root_event_id or run_record_id or "").strip()


def _effective_root_event_id(flow_id: str, root_event_id: str, run_record_id: str) -> str:
    return (root_event_id or flow_id or run_record_id or "").strip()


def _effective_workspace_id(workspace_id: str) -> str:
    return (workspace_id or DEFAULT_WORKSPACE_ID).strip() or DEFAULT_WORKSPACE_ID


# ============================================================
# Error Intelligence V2
# ============================================================

def _classify_error(http_status: Optional[int], error_text: str) -> str:
    error_lower = (error_text or "").lower()

    if http_status is not None:
        if http_status in (401, 403):
            return "auth_error"
        if http_status == 429:
            return "rate_limit"
        if 500 <= http_status <= 599:
            return "http_5xx"
        if 400 <= http_status <= 499:
            return "http_4xx"

    if "timeout" in error_lower:
        return "network_timeout"

    if (
        "schema" in error_lower
        or "field" in error_lower
        or "json" in error_lower
        or "decode" in error_lower
        or "validation" in error_lower
    ):
        return "schema_error"

    if "auth" in error_lower or "unauthorized" in error_lower or "forbidden" in error_lower:
        return "auth_error"

    return "unknown_error"


def _risk_level_for(error_type: str) -> str:
    if error_type in ("auth_error", "schema_error"):
        return "critical"
    if error_type in ("http_5xx", "rate_limit", "http_4xx"):
        return "high"
    if error_type == "network_timeout":
        return "medium"
    return "medium"


def _compute_retry_delay_seconds(error_type: str, retry_count: int) -> int:
    if error_type == "rate_limit":
        schedule = {0: 60, 1: 120, 2: 300}
        return schedule.get(retry_count, 300)

    if error_type == "network_timeout":
        schedule = {0: 15, 1: 30, 2: 60, 3: 120}
        return schedule.get(retry_count, 120)

    if error_type == "http_5xx":
        schedule = {0: 10, 1: 20, 2: 40, 3: 80}
        return schedule.get(retry_count, 80)

    return min(2 ** retry_count, 30)


# ============================================================
# Retry Input Builder
# ============================================================

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
    retry_delay_seconds: int,
    error_type: str,
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

        if "timeout_seconds" not in retry_input and "timeout_seconds" in original_request:
            retry_input["timeout_seconds"] = original_request["timeout_seconds"]

    # Core http_exec fields
    retry_input["url"] = failed_url
    retry_input["http_target"] = failed_url
    retry_input["method"] = failed_method or "GET"

    # BOSAI context
    retry_input["flow_id"] = flow_id
    retry_input["root_event_id"] = root_event_id
    retry_input["workspace_id"] = workspace_id

    # Execution control
    retry_input["retry_count"] = retry_count + 1
    retry_input["retry_max"] = retry_max
    retry_input["step_index"] = 0
    retry_input["max_depth"] = max_depth
    retry_input["retry_delay_seconds"] = retry_delay_seconds

    # Diagnostics
    retry_input["error_type"] = error_type

    if http_status is not None:
        retry_input["http_status"] = http_status

    if error:
        retry_input["error"] = error

    if reason:
        retry_input["retry_reason"] = reason

    return retry_input


# ============================================================
# Main Capability
# ============================================================

def capability_incident_router(payload: Dict[str, Any], run_record_id: str = "") -> Dict[str, Any]:
    goal = _safe(_pick(payload, "goal", "failed_goal"), "")
    error = _safe(_pick(payload, "error", "last_error"), "")
    reason = _safe(_pick(payload, "reason", "retry_reason"), "unknown")

    http_status = _normalize_http_status(payload)

    retry_count = _to_int(_pick(payload, "retry_count")) or 0
    retry_max = _to_int(_pick(payload, "retry_max")) or 0
    max_depth = _to_int(_pick(payload, "max_depth")) or DEFAULT_MAX_DEPTH

    raw_flow_id = _safe(_pick(payload, "flow_id"), "")
    raw_root_event_id = _safe(_pick(payload, "root_event_id"), "")
    raw_workspace_id = _safe(_pick(payload, "workspace_id"), DEFAULT_WORKSPACE_ID)

    flow_id = _effective_flow_id(raw_flow_id, raw_root_event_id, run_record_id)
    root_event_id = _effective_root_event_id(raw_flow_id, raw_root_event_id, run_record_id)
    workspace_id = _effective_workspace_id(raw_workspace_id)

    original_capability = _safe(
        _pick(payload, "original_capability", "source_capability"),
        DEFAULT_ORIGINAL_CAPABILITY,
    ) or DEFAULT_ORIGINAL_CAPABILITY

    original_input = _extract_original_input(payload)
    original_request = _extract_original_request(payload)

    failed_url = _normalize_failed_url(payload, original_input, original_request)
    failed_method = _normalize_failed_method(payload, original_input, original_request)

    error_type = _classify_error(http_status, error)
    risk_level = _risk_level_for(error_type)
    retry_delay_seconds = _compute_retry_delay_seconds(error_type, retry_count)

    # =========================
    # Decision Engine V2
    # =========================

    decision = "log_only"
    final_reason = reason or "unknown"

    # HARD STOP anti-loop
    if retry_max > 0 and retry_count >= retry_max:
        decision = "escalate"
        final_reason = "retry_exhausted"

    # HARD STOP anti-depth
    elif retry_count >= max_depth:
        decision = "escalate"
        final_reason = "max_depth_reached"

    # Smart routing by classified error
    elif error_type == "http_5xx":
        if retry_count < retry_max:
            decision = "retry"
            final_reason = "http_5xx"
        else:
            decision = "escalate"
            final_reason = "http_5xx_exhausted"

    elif error_type == "network_timeout":
        if retry_count < retry_max:
            decision = "retry"
            final_reason = "timeout"
        else:
            decision = "escalate"
            final_reason = "timeout_exhausted"

    elif error_type == "rate_limit":
        if retry_count < retry_max:
            decision = "retry"
            final_reason = "rate_limit"
        else:
            decision = "escalate"
            final_reason = "rate_limit_exhausted"

    elif error_type in ("auth_error", "schema_error", "http_4xx"):
        decision = "escalate"
        final_reason = error_type

    elif error:
        decision = "log_only"
        final_reason = "unknown_error"

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
            retry_delay_seconds=retry_delay_seconds,
            error_type=error_type,
        )

        next_commands.append(
            {
                "capability": original_capability,
                "input": retry_input,
                "priority": 2,
            }
        )

    elif decision == "escalate":
        next_commands.append(
            {
                "capability": "internal_escalate",
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "goal": goal,
                    "reason": final_reason,
                    "error": error,
                    "error_type": error_type,
                    "risk_level": risk_level,
                    "http_status": http_status,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "workspace_id": workspace_id,
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "run_record_id": run_record_id,
                },
                "priority": 1,
            }
        )

    return {
        "ok": True,
        "capability": "incident_router",
        "status": "incident_escalated" if decision == "escalate" else "incident_logged",
        "decision": decision,
        "reason": final_reason,
        "error_type": error_type,
        "risk_level": risk_level,
        "retry_delay_seconds": retry_delay_seconds,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "max_depth": max_depth,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "next_commands": next_commands,
        "terminal": False,
    }


def run(req: Any = None, run_record_id: str = "") -> Dict[str, Any]:
    payload = _to_payload(req)
    return capability_incident_router(payload, run_record_id)
