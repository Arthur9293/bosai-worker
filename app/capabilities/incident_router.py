# app/capabilities/incident_router.py
from __future__ import annotations

from typing import Any, Dict, Optional


def _to_payload(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    input_attr = getattr(value, "input", None)
    if isinstance(input_attr, dict):
        return input_attr

    return {}


def _to_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _pick(payload: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return default


def _normalize_http_status(payload: Dict[str, Any]) -> Optional[int]:
    http_status = _to_int(
        _pick(
            payload,
            "http_status",
            "httpstatus",
            "status_code",
            "statuscode",
            "HTTP_Status",
        )
    )
    if http_status is not None:
        return http_status

    response_obj = payload.get("response")
    if isinstance(response_obj, dict):
        return _to_int(
            response_obj.get("status_code")
            or response_obj.get("statuscode")
        )

    return None


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
    return str(
        _pick(
            payload,
            "failed_url",
            "failedurl",
            "url",
            "http_target",
            "URL",
            default=(
                original_input.get("url")
                or original_input.get("http_target")
                or original_input.get("URL")
                or original_request.get("url")
                or original_request.get("http_target")
                or original_request.get("URL")
                or ""
            ),
        ) or ""
    ).strip()


def _normalize_failed_method(
    payload: Dict[str, Any],
    original_input: Dict[str, Any],
    original_request: Dict[str, Any],
) -> str:
    return str(
        _pick(
            payload,
            "failed_method",
            "failedmethod",
            "method",
            "HTTP_Method",
            default=(
                original_input.get("method")
                or original_input.get("HTTP_Method")
                or original_request.get("method")
                or original_request.get("HTTP_Method")
                or "GET"
            ),
        ) or "GET"
    ).strip().upper()


def _effective_flow_id(flow_id: str, root_event_id: str, run_record_id: str) -> str:
    return (flow_id or root_event_id or run_record_id or "").strip()


def _effective_root_event_id(flow_id: str, root_event_id: str, run_record_id: str) -> str:
    return (root_event_id or flow_id or run_record_id or "").strip()


def _effective_workspace_id(workspace_id: str) -> str:
    return (workspace_id or "production").strip()


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
) -> Dict[str, Any]:
    """
    SAFE PATCH:
    Rebuild a clean http_exec input.
    We do NOT propagate event-style envelopes such as:
    - event_type
    - payload
    This avoids contaminating spawned http_exec commands.
    """
    retry_input: Dict[str, Any] = {}

    if isinstance(original_input, dict):
        headers = original_input.get("headers")
        if isinstance(headers, dict) and headers:
            retry_input["headers"] = headers

        timeout_seconds = original_input.get("timeout_seconds")
        if timeout_seconds not in (None, ""):
            retry_input["timeout_seconds"] = timeout_seconds

        body = original_input.get("body")
        if body is not None:
            retry_input["body"] = body

        json_body = original_input.get("json")
        if json_body is not None:
            retry_input["json"] = json_body

        params = original_input.get("params")
        if isinstance(params, dict) and params:
            retry_input["params"] = params

    if isinstance(original_request, dict):
        if "timeout_seconds" not in retry_input:
            timeout_seconds = original_request.get("timeout_seconds")
            if timeout_seconds not in (None, ""):
                retry_input["timeout_seconds"] = timeout_seconds

        if "headers" not in retry_input:
            headers = original_request.get("headers")
            if isinstance(headers, dict) and headers:
                retry_input["headers"] = headers

    effective_flow = _effective_flow_id(flow_id, root_event_id, "")
    effective_root_event = _effective_root_event_id(flow_id, root_event_id, "")
    effective_workspace = _effective_workspace_id(workspace_id)

    # Champs réseau explicites et plats
    retry_input["url"] = failed_url
    retry_input["http_target"] = failed_url
    retry_input["URL"] = failed_url
    retry_input["method"] = failed_method or "GET"
    retry_input["HTTP_Method"] = failed_method or "GET"

    # Contexte BOSAI
    retry_input["flow_id"] = effective_flow
    retry_input["root_event_id"] = effective_root_event
    retry_input["workspace_id"] = effective_workspace

    # Contrôle d'exécution
    retry_input["step_index"] = 0
    retry_input["retry_count"] = retry_count + 1
    retry_input["retry_max"] = retry_max

    if http_status is not None:
        retry_input["http_status"] = http_status

    if error:
        retry_input["error"] = error

    if reason:
        retry_input["retry_reason"] = reason

    return retry_input


def capability_incident_router(payload: Dict[str, Any], run_record_id: str = "") -> Dict[str, Any]:
    goal = str(
        _pick(
            payload,
            "goal",
            "Goal",
            "failed_goal",
            "failedgoal",
            default="",
        ) or ""
    ).strip()

    error = str(
        _pick(
            payload,
            "error",
            "last_error",
            "Error",
            default="",
        ) or ""
    ).strip()

    reason = str(
        _pick(
            payload,
            "reason",
            "retry_reason",
            "retryreason",
            "Reason",
            default="unknown",
        ) or "unknown"
    ).strip()

    http_status = _normalize_http_status(payload)

    retry_count = _to_int(
        _pick(payload, "retry_count", "retrycount", "Retry_Count")
    ) or 0

    retry_max = _to_int(
        _pick(payload, "retry_max", "retrymax", "Retry_Max")
    ) or 0

    flow_id = str(
        _pick(payload, "flow_id", "flowid", "Flow_ID", default="")
        or ""
    ).strip()

    root_event_id = str(
        _pick(payload, "root_event_id", "rooteventid", "Root_Event_ID", default="")
        or ""
    ).strip()

    workspace_id = str(
        _pick(payload, "workspace_id", "workspaceid", "Workspace_ID", default="")
        or ""
    ).strip()

    original_capability = str(
        _pick(
            payload,
            "original_capability",
            "originalcapability",
            "source_capability",
            default="http_exec",
        ) or "http_exec"
    ).strip() or "http_exec"

    original_input = (
        payload.get("original_input")
        if isinstance(payload.get("original_input"), dict)
        else {}
    )
    original_request = _extract_original_request(payload)

    failed_url = _normalize_failed_url(payload, original_input, original_request)
    failed_method = _normalize_failed_method(payload, original_input, original_request)

    effective_flow = _effective_flow_id(flow_id, root_event_id, run_record_id)
    effective_root_event = _effective_root_event_id(flow_id, root_event_id, run_record_id)
    effective_workspace = _effective_workspace_id(workspace_id)

    decision = "log_only"
    final_reason = reason or "default"

    if retry_max > 0 and retry_count >= retry_max:
        decision = "escalate"
        final_reason = reason or "retry_exhausted"

    elif http_status is not None:
        if 500 <= http_status <= 599:
            if retry_max > 0 and retry_count < retry_max:
                decision = "retry"
                final_reason = reason or "http_5xx"
            else:
                decision = "escalate"
                final_reason = reason or "http_5xx_exhausted"

        elif 400 <= http_status <= 499:
            decision = "escalate"
            final_reason = reason or "http_4xx"

    elif "timeout" in error.lower():
        if retry_max > 0 and retry_count < retry_max:
            decision = "retry"
            final_reason = reason or "timeout"
        else:
            decision = "escalate"
            final_reason = reason or "timeout_exhausted"

    elif error:
        decision = "log_only"
        final_reason = reason or "unknown_error"

    next_commands = []

    if decision == "retry":
        retry_input = _build_clean_retry_input(
            original_input=original_input,
            original_request=original_request,
            failed_url=failed_url,
            failed_method=failed_method,
            flow_id=effective_flow,
            root_event_id=effective_root_event,
            workspace_id=effective_workspace,
            retry_count=retry_count,
            retry_max=retry_max,
            http_status=http_status,
            error=error,
            reason=final_reason,
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
                    "flow_id": effective_flow,
                    "root_event_id": effective_root_event,
                    "goal": goal,
                    "reason": final_reason,
                    "error": error,
                    "http_status": http_status,
                    "status_code": http_status,
                    "source_capability": original_capability,
                    "original_capability": original_capability,
                    "failed_url": failed_url,
                    "failed_method": failed_method,
                    "workspace_id": effective_workspace,
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
        "goal": goal,
        "reason": final_reason,
        "error": error,
        "http_status": http_status,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "flow_id": effective_flow,
        "root_event_id": effective_root_event,
        "workspace_id": effective_workspace,
        "run_record_id": run_record_id,
        "original_capability": original_capability,
        "failed_url": failed_url,
        "failed_method": failed_method,
        "next_commands": next_commands,
        "terminal": False,
    }


def run(req: Any = None, run_record_id: str = "") -> Dict[str, Any]:
    payload = _to_payload(req)
    return capability_incident_router(payload, run_record_id)
