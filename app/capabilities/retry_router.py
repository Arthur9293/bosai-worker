from __future__ import annotations

from typing import Any, Dict, List, Optional


def _to_int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _pick(payload: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return default


def _to_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def run(input_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = input_data or {}

    flow_id = str(payload.get("flow_id") or "").strip()
    root_event_id = str(payload.get("root_event_id") or "").strip()
    workspace_id = str(payload.get("workspace_id") or "").strip()

    original_capability = str(payload.get("original_capability") or "http_exec").strip() or "http_exec"
    original_input = _to_dict(payload.get("original_input"))

    retry_reason = str(payload.get("retry_reason") or payload.get("reason") or "").strip()
    retry_count = _to_int(payload.get("retry_count"), 0)
    retry_max = _to_int(payload.get("retry_max"), 3)
    http_status = payload.get("http_status")
    incident_record_id = payload.get("incident_record_id")

    # Fallback URL/method depuis original_input OU payload courant
    url_value = str(
        _pick(
            original_input,
            "url",
            "http_target",
            "URL",
            default=_pick(payload, "url", "http_target", "URL", default=""),
        ) or ""
    ).strip()

    method_value = str(
        _pick(
            original_input,
            "method",
            "HTTP_Method",
            default=_pick(payload, "method", "HTTP_Method", default="GET"),
        ) or "GET"
    ).strip().upper()

    next_commands: List[Dict[str, Any]] = []
    action = "noop"
    terminal = False

    if retry_count < retry_max:
        action = "retry"

        retry_input: Dict[str, Any] = {
            **original_input,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "workspace_id": workspace_id,
            "retry_count": retry_count + 1,
            "retry_max": retry_max,
            "retry_reason": retry_reason,
            "incident_record_id": incident_record_id,
            "original_capability": original_capability,
        }

        # Garantit les champs critiques pour http_exec
        if url_value:
            retry_input["url"] = url_value
            retry_input["http_target"] = url_value

        retry_input["method"] = method_value

        next_commands.append(
            {
                "capability": original_capability,
                "priority": 2,
                "input": retry_input,
            }
        )

    else:
        action = "escalate"
        terminal = True

        next_commands.append(
            {
                "capability": "internal_escalate",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "workspace_id": workspace_id,
                    "incident_record_id": incident_record_id,
                    "original_capability": original_capability,
                    "original_input": {
                        **original_input,
                        "url": url_value,
                        "http_target": url_value,
                        "method": method_value,
                    },
                    "retry_count": retry_count,
                    "retry_max": retry_max,
                    "retry_reason": retry_reason,
                    "http_status": http_status,
                    "goal": "incident_escalation",
                },
            }
        )

    return {
        "ok": True,
        "capability": "retry_router",
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "action": action,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_reason": retry_reason,
        "http_status": http_status,
        "url": url_value,
        "method": method_value,
        "next_commands": next_commands,
        "terminal": terminal,
    }
