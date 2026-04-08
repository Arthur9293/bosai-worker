# app/capabilities/http_exec.py

from __future__ import annotations

import ipaddress
import json
import socket
import time
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

print("HTTP_EXEC_MODULE_LOADED_V5")

HTTP_EXEC_ENABLED = True
DEFAULT_RETRY_MAX = 3
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_RETRY_DELAY_SECONDS = 10
DEFAULT_MAX_DEPTH = 8

REQUEST_SESSION = requests.Session()

FORBIDDEN_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
}


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _to_float(value: Any, default: float) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def _safe_json_dumps(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        try:
            return json.dumps(str(value), ensure_ascii=False)
        except Exception:
            return "{}"


def _trim_text(value: Any, limit: int = 2000) -> str:
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _pick_text(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _pick_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_method(value: Any) -> str:
    method = str(value or "GET").strip().upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        return "GET"
    return method


def _normalize_headers(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}

    result: Dict[str, str] = {}
    for k, v in value.items():
        key = str(k).strip()
        if not key:
            continue
        result[key] = "" if v is None else str(v)
    return result


def _normalize_params(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return dict(value)


def _normalize_json_body(value: Any) -> Optional[Any]:
    if value is None or value == "":
        return None
    return value


def _normalize_text_body(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list)):
        return _safe_json_dumps(value)
    return str(value)


def _sanitize_headers_for_logs(headers: Dict[str, Any]) -> Dict[str, Any]:
    secret_markers = {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "apikey",
        "cookie",
        "set-cookie",
        "x-auth-token",
    }

    sanitized: Dict[str, Any] = {}
    for k, v in (headers or {}).items():
        key = str(k)
        if key.strip().lower() in secret_markers:
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = v
    return sanitized


def _extract_retry_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    flow_id = str(payload.get("flow_id", "") or "")
    root_event_id = str(payload.get("root_event_id", "") or "")

    source_event_id = str(
        payload.get("source_event_id")
        or payload.get("sourceEventId")
        or payload.get("event_id")
        or payload.get("eventId")
        or root_event_id
        or ""
    )

    workspace_id = str(
        payload.get("workspace_id")
        or payload.get("workspaceId")
        or payload.get("Workspace_ID")
        or payload.get("workspace")
        or ""
    )

    parent_command_id = str(
        payload.get("parent_command_id")
        or payload.get("parent_id")
        or payload.get("linked_command_id")
        or payload.get("parentCommandId")
        or ""
    )

    command_id = str(
        payload.get("command_id")
        or payload.get("commandid")
        or ""
    )

    linked_run = str(
        payload.get("linked_run")
        or payload.get("linkedrun")
        or payload.get("run_record_id")
        or payload.get("runrecordid")
        or ""
    )

    step_index = _to_int(payload.get("step_index"), 0)
    retry_count = _to_int(payload.get("retry_count"), 0)
    retry_max = _to_int(payload.get("retry_max"), DEFAULT_RETRY_MAX)
    retry_delay_seconds = _to_int(
        payload.get("retry_delay_seconds"),
        _to_int(payload.get("retry_delay_sec"), DEFAULT_RETRY_DELAY_SECONDS),
    )

    return {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "workspace_id": workspace_id,
        "parent_command_id": parent_command_id,
        "command_id": command_id,
        "linked_run": linked_run,
        "step_index": step_index,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "retry_delay_seconds": retry_delay_seconds,
    }


def _compute_backoff_seconds(payload: Dict[str, Any], retry_count_after_failure: int) -> int:
    fixed_delay = _to_int(
        payload.get("retry_delay_seconds"),
        _to_int(payload.get("retry_delay_sec"), DEFAULT_RETRY_DELAY_SECONDS),
    )
    base = max(1, fixed_delay)

    if _to_bool(payload.get("retry_backoff_exponential"), False):
        max_delay = max(base, _to_int(payload.get("retry_backoff_max_seconds"), 300))
        return min(base * (2 ** max(0, retry_count_after_failure - 1)), max_delay)

    return base


def _build_next_retry_at(delay_seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + max(0, delay_seconds)))


def _get_depth(payload: Dict[str, Any]) -> int:
    return _to_int(payload.get("_depth"), 0)


def _increment_depth(payload: Dict[str, Any]) -> int:
    return _get_depth(payload) + 1


def _parse_allowlist(payload: Dict[str, Any]) -> List[str]:
    raw = payload.get("allowed_hosts") or payload.get("host_allowlist") or []
    if isinstance(raw, str):
        items = [x.strip() for x in raw.split(",")]
    elif isinstance(raw, list):
        items = [str(x).strip() for x in raw]
    else:
        items = []

    cleaned = [x.lower() for x in items if x]
    return cleaned


def _host_matches_allowlist(host: str, allowlist: List[str]) -> bool:
    if not allowlist:
        return True

    host_l = host.lower()
    for allowed in allowlist:
        if not allowed:
            continue
        if host_l == allowed:
            return True
        if allowed.startswith("*."):
            suffix = allowed[1:]
            if host_l.endswith(suffix) and host_l != suffix.lstrip("."):
                return True
        elif host_l.endswith("." + allowed):
            return True
    return False


def _ip_is_forbidden(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        return bool(
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except Exception:
        return True


def _resolve_host_ips(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []

    ips: List[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if ip and ip not in ips:
            ips.append(ip)
    return ips


def _validate_url(url: str, allowlist: List[str]) -> Tuple[bool, str, Dict[str, Any]]:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().lower()

    debug = {
        "scheme": scheme,
        "host": host,
        "port": parsed.port,
        "path": parsed.path,
    }

    if scheme not in {"http", "https"}:
        return False, "invalid_scheme", debug

    if not host:
        return False, "missing_host", debug

    if host in FORBIDDEN_HOSTS:
        return False, "forbidden_host", debug

    if not _host_matches_allowlist(host, allowlist):
        return False, "host_not_allowed", debug

    ips = _resolve_host_ips(host)
    debug["resolved_ips"] = ips

    if not ips:
        return False, "dns_resolution_failed", debug

    for ip in ips:
        if _ip_is_forbidden(ip):
            debug["blocked_ip"] = ip
            return False, "forbidden_ip", debug

    return True, "ok", debug


def _extract_response_payload(response: requests.Response) -> Dict[str, Any]:
    content_type = str(response.headers.get("Content-Type", "") or "")
    text = response.text if response.text is not None else ""

    body_json: Optional[Any] = None
    if "application/json" in content_type.lower():
        try:
            body_json = response.json()
        except Exception:
            body_json = None

    return {
        "status_code": int(response.status_code),
        "ok": bool(response.ok),
        "content_type": content_type,
        "headers": dict(response.headers),
        "body_text": _trim_text(text, 4000),
        "body_json": body_json,
        "elapsed_ms": int(getattr(response.elapsed, "total_seconds", lambda: 0.0)() * 1000),
    }


def _build_incident_router_command(
    *,
    original_payload: Dict[str, Any],
    meta: Dict[str, Any],
    error_code: str,
    error_message: str,
    http_status: Optional[int],
    request_summary: Dict[str, Any],
    response_summary: Optional[Dict[str, Any]],
    run_record_id: str,
) -> Dict[str, Any]:
    next_depth = _increment_depth(original_payload)

    incident_input = {
        "flow_id": meta["flow_id"],
        "root_event_id": meta["root_event_id"],
        "source_event_id": meta["source_event_id"],
        "event_id": meta["source_event_id"],
        "workspace_id": meta["workspace_id"],
        "run_record_id": run_record_id,
        "linked_run": run_record_id,
        "parent_command_id": meta["parent_command_id"],
        "step_index": meta["step_index"] + 1,
        "_depth": next_depth,
        "source_capability": "http_exec",
        "incident_type": "http_exec_failure",
        "incident_code": error_code,
        "incident_message": error_message,
        "http_status": http_status,
        "request": request_summary,
        "response": response_summary or {},
        "failed_at": _now_ts(),
        "retry_count": meta["retry_count"],
        "retry_max": meta["retry_max"],
        "final_failure": True,
    }

    return {
        "capability": "incident_router_v2",
        "input": incident_input,
    }


def _prune_original_input_for_retry(value: Dict[str, Any]) -> Dict[str, Any]:
    clean = deepcopy(value or {})
    for noisy_key in (
        "next_commands",
        "spawn_summary",
        "terminal",
        "retry_planned",
        "next_retry_at",
        "request",
        "response",
        "error",
        "error_message",
        "incident_message",
        "status",
        "ok",
        "ts",
    ):
        clean.pop(noisy_key, None)
    return clean


def _build_retry_router_input(
    *,
    original_payload: Dict[str, Any],
    meta: Dict[str, Any],
    run_record_id: str,
    retry_count_after_failure: int,
    next_retry_at: str,
    error_code: str,
    error_message: str,
    http_status: Optional[int],
    request_summary: Dict[str, Any],
    response_summary: Optional[Dict[str, Any]],
    request_error_value: str = "",
) -> Dict[str, Any]:
    retry_input = deepcopy(original_payload)

    flow_id = _pick_text(
        retry_input.get("flow_id"),
        meta.get("flow_id"),
        run_record_id and f"flow_run_{run_record_id}",
    )
    root_event_id = _pick_text(
        retry_input.get("root_event_id"),
        meta.get("root_event_id"),
        retry_input.get("event_id"),
        flow_id,
    )
    source_event_id = _pick_text(
        retry_input.get("source_event_id"),
        retry_input.get("sourceEventId"),
        retry_input.get("event_id"),
        retry_input.get("eventId"),
        meta.get("source_event_id"),
        root_event_id,
        flow_id,
    )
    workspace_id = _pick_text(
        retry_input.get("workspace_id"),
        retry_input.get("workspaceId"),
        retry_input.get("Workspace_ID"),
        retry_input.get("workspace"),
        meta.get("workspace_id"),
    )
    linked_run = _pick_text(
        run_record_id,
        retry_input.get("linked_run"),
        retry_input.get("linkedrun"),
        retry_input.get("run_record_id"),
        retry_input.get("runrecordid"),
        meta.get("linked_run"),
    )
    command_id = _pick_text(
        retry_input.get("command_id"),
        retry_input.get("commandid"),
        meta.get("command_id"),
        retry_input.get("parent_command_id"),
        retry_input.get("parentCommandId"),
        meta.get("parent_command_id"),
    )
    parent_command_id = _pick_text(
        retry_input.get("parent_command_id"),
        retry_input.get("parentCommandId"),
        command_id,
        meta.get("parent_command_id"),
    )

    failed_url = _pick_text(
        retry_input.get("failed_url"),
        retry_input.get("target_url"),
        retry_input.get("url"),
        retry_input.get("http_target"),
        request_summary.get("url"),
    )
    failed_method = _pick_text(
        retry_input.get("failed_method"),
        retry_input.get("method"),
        request_summary.get("method"),
        "GET",
    ).upper()

    goal = _pick_text(
        retry_input.get("goal"),
        retry_input.get("failed_goal"),
    )
    failed_goal = _pick_text(
        retry_input.get("failed_goal"),
        retry_input.get("goal"),
        goal,
    )

    original_input = _pick_dict(retry_input.get("original_input"))
    if not original_input:
        original_input = _prune_original_input_for_retry(original_payload)

    retry_input["flow_id"] = flow_id
    retry_input["root_event_id"] = root_event_id
    retry_input["source_event_id"] = source_event_id
    retry_input["event_id"] = source_event_id
    retry_input["workspace_id"] = workspace_id
    retry_input["workspace"] = workspace_id
    retry_input["run_record_id"] = linked_run
    retry_input["linked_run"] = linked_run
    retry_input["parent_command_id"] = parent_command_id
    retry_input["command_id"] = command_id or parent_command_id
    retry_input["retry_count"] = retry_count_after_failure
    retry_input["retry_max"] = _to_int(original_payload.get("retry_max"), meta.get("retry_max", DEFAULT_RETRY_MAX))
    retry_input["retry_delay_seconds"] = _to_int(
        original_payload.get("retry_delay_seconds"),
        _to_int(original_payload.get("retry_delay_sec"), meta.get("retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS)),
    )
    retry_input["next_retry_at"] = next_retry_at
    retry_input["_depth"] = _increment_depth(original_payload)

    retry_input["original_capability"] = "http_exec"
    retry_input["source_capability"] = "http_exec"
    retry_input["failed_capability"] = "http_exec"

    retry_input["goal"] = goal
    retry_input["failed_goal"] = failed_goal

    retry_input["retry_reason"] = error_code
    retry_input["reason"] = error_code
    retry_input["incident_code"] = error_code
    retry_input["error"] = error_code
    retry_input["error_message"] = error_message
    retry_input["incident_message"] = error_message
    retry_input["last_error"] = error_message

    if request_error_value:
        retry_input["request_error"] = request_error_value

    retry_input["failed_url"] = failed_url
    retry_input["target_url"] = failed_url
    retry_input["url"] = failed_url
    retry_input["http_target"] = failed_url

    retry_input["failed_method"] = failed_method
    retry_input["method"] = failed_method

    retry_input["request"] = deepcopy(request_summary) if isinstance(request_summary, dict) else {}
    retry_input["response"] = deepcopy(response_summary) if isinstance(response_summary, dict) else {}
    retry_input["original_input"] = original_input

    if http_status is not None:
        retry_input["http_status"] = http_status
        retry_input["status_code"] = http_status

    return retry_input


def _update_monitored_endpoint_best_effort(
    *,
    original_payload: Dict[str, Any],
    runtime_context: Dict[str, Any],
    status_code: Optional[int],
    error_text: str,
    elapsed_ms: Optional[int],
) -> None:
    try:
        endpoint_name = str(
            original_payload.get("endpoint_name")
            or original_payload.get("endpoint")
            or ""
        ).strip()

        endpoint_record_id = str(
            original_payload.get("endpoint_record_id")
            or original_payload.get("record_id")
            or ""
        ).strip()

        airtable_update_by_field = runtime_context.get("airtable_update_by_field")
        airtable_update = runtime_context.get("airtable_update")
        run_record_id = str(runtime_context.get("run_record_id") or "").strip()

        print("[http_exec][endpoint_update] endpoint_name =", repr(endpoint_name), flush=True)
        print("[http_exec][endpoint_update] endpoint_record_id =", repr(endpoint_record_id), flush=True)
        print("[http_exec][endpoint_update] run_record_id =", repr(run_record_id), flush=True)
        print(
            "[http_exec][endpoint_update] helper_callable_by_field =",
            callable(airtable_update_by_field),
            flush=True,
        )
        print(
            "[http_exec][endpoint_update] helper_callable_update =",
            callable(airtable_update),
            flush=True,
        )
        print(
            "[http_exec][endpoint_update] status_code/error_text/elapsed_ms =",
            {
                "status_code": status_code,
                "error_text": error_text,
                "elapsed_ms": elapsed_ms,
            },
            flush=True,
        )

        fields: Dict[str, Any] = {
            "last_check_at": _now_ts(),
            "last_error": str(error_text or ""),
        }

        if status_code is not None:
            fields["last_status"] = int(status_code)

        if elapsed_ms is not None:
            fields["last_response_time_ms"] = int(elapsed_ms)

        if run_record_id:
            fields["last_run_id"] = run_record_id

        print("[http_exec][endpoint_update] fields =", fields, flush=True)

        if endpoint_record_id and callable(airtable_update):
            airtable_update(
                table_name="Monitored_Endpoints",
                record_id=endpoint_record_id,
                fields=fields,
            )
            print(
                "[http_exec] endpoint runtime updated by record_id =",
                endpoint_record_id,
                flush=True,
            )
            return

        if not endpoint_name:
            print(
                "[http_exec] skip monitored endpoint update: missing endpoint_name and endpoint_record_id",
                flush=True,
            )
            return

        if not callable(airtable_update_by_field):
            print(
                "[http_exec] skip monitored endpoint update: missing helper for fallback by field",
                flush=True,
            )
            return

        res = airtable_update_by_field(
            table="Monitored_Endpoints",
            field="Name",
            value=endpoint_name,
            fields=fields,
        )

        print("[http_exec] endpoint runtime updated by Name =", endpoint_name, flush=True)
        print("[http_exec][endpoint_update] airtable response =", repr(res), flush=True)

    except Exception as e:
        print("[http_exec] endpoint update error =", repr(e), flush=True)


def capability_http_exec(
    payload: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    print("[HTTP_EXEC CORE] entered")
    context = context or {}

    runtime_context: Dict[str, Any] = dict(context) if isinstance(context, dict) else {}

    if "run_record_id" not in runtime_context and kwargs.get("run_record_id"):
        runtime_context["run_record_id"] = kwargs.get("run_record_id")

    if "airtable_update_by_field" not in runtime_context and kwargs.get("airtable_update_by_field"):
        runtime_context["airtable_update_by_field"] = kwargs.get("airtable_update_by_field")

    if "airtable_update" not in runtime_context and kwargs.get("airtable_update"):
        runtime_context["airtable_update"] = kwargs.get("airtable_update")

    if payload is None and isinstance(kwargs.get("input_data"), dict):
        payload = kwargs["input_data"]
    elif payload is None and isinstance(kwargs.get("payload"), dict):
        payload = kwargs["payload"]

    original_payload = deepcopy(payload or {})
    meta = _extract_retry_meta(original_payload)

    run_record_id = str(
        runtime_context.get("run_record_id")
        or original_payload.get("run_record_id")
        or original_payload.get("linked_run")
        or meta.get("linked_run")
        or ""
    ).strip()

    base_result_fields = {
        "flow_id": meta["flow_id"],
        "root_event_id": meta["root_event_id"],
        "source_event_id": meta["source_event_id"],
        "workspace_id": meta["workspace_id"],
        "step_index": meta["step_index"],
        "run_record_id": run_record_id,
        "linked_run": run_record_id,
    }

    def _build_failure_result(
        *,
        status: str,
        error_code: str,
        error_message: str,
        request_summary: Dict[str, Any],
        response_summary: Optional[Dict[str, Any]],
        http_status: Optional[int],
        retry_count_after_failure: Optional[int],
        retryable: bool,
        final_failure: bool,
        next_commands: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        result = {
            "ok": False,
            "status": status,
            "ts": _now_ts(),
            "request": request_summary,
            "response": response_summary
            if isinstance(response_summary, dict)
            else {
                "status_code": http_status,
                "ok": False,
                "content_type": "",
                "headers": {},
                "body_text": "",
                "body_json": None,
                "elapsed_ms": 0,
            },
            "status_code": http_status,
            "http_status": http_status,
            "error": error_code,
            "error_message": error_message,
            "retry_count": retry_count_after_failure
            if retry_count_after_failure is not None
            else meta["retry_count"],
            "retry_max": meta["retry_max"],
            "retry_delay_seconds": meta["retry_delay_seconds"],
            "retryable": bool(retryable),
            "final_failure": bool(final_failure),
            "next_commands": next_commands if isinstance(next_commands, list) else [],
            "event_id": meta["source_event_id"] or meta["root_event_id"] or meta["flow_id"],
            "goal": _pick_text(
                original_payload.get("goal"),
                original_payload.get("failed_goal"),
            ),
            **base_result_fields,
        }
        result["terminal"] = not bool(result["next_commands"])
        return result

    if not HTTP_EXEC_ENABLED:
        result = _build_failure_result(
            status="blocked",
            error_code="http_exec_disabled",
            error_message="http_exec_disabled",
            request_summary={},
            response_summary=None,
            http_status=None,
            retry_count_after_failure=None,
            retryable=False,
            final_failure=True,
            next_commands=[],
        )
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    if _get_depth(original_payload) >= _to_int(original_payload.get("max_depth"), DEFAULT_MAX_DEPTH):
        result = _build_failure_result(
            status="blocked",
            error_code="max_depth_exceeded",
            error_message="max_depth_exceeded",
            request_summary={},
            response_summary=None,
            http_status=None,
            retry_count_after_failure=None,
            retryable=False,
            final_failure=True,
            next_commands=[],
        )
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    url = str(original_payload.get("url") or "").strip()
    method = _normalize_method(original_payload.get("method"))
    timeout_seconds = max(
        1,
        _to_int(original_payload.get("timeout_seconds"), DEFAULT_TIMEOUT_SECONDS),
    )
    params = _normalize_params(original_payload.get("params"))
    headers = _normalize_headers(original_payload.get("headers"))
    json_body = _normalize_json_body(original_payload.get("json"))
    data_body = _normalize_text_body(original_payload.get("data"))
    allow_redirects = _to_bool(original_payload.get("follow_redirects"), False)
    verify_tls = _to_bool(original_payload.get("verify_tls"), True)
    dry_run = _to_bool(original_payload.get("dry_run"), False)

    allowlist = _parse_allowlist(original_payload)

    request_summary = {
        "method": method,
        "url": url,
        "params": params,
        "headers": _sanitize_headers_for_logs(headers),
        "has_json": json_body is not None,
        "has_data": data_body is not None,
        "timeout_seconds": timeout_seconds,
        "follow_redirects": allow_redirects,
        "verify_tls": verify_tls,
    }

    if not url:
        result = _build_failure_result(
            status="error",
            error_code="missing_url",
            error_message="missing_url",
            request_summary=request_summary,
            response_summary=None,
            http_status=None,
            retry_count_after_failure=None,
            retryable=False,
            final_failure=True,
            next_commands=[],
        )
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    allowed, allow_reason, url_debug = _validate_url(url, allowlist)
    request_summary["url_debug"] = url_debug

    if not allowed:
        result = _build_failure_result(
            status="blocked",
            error_code=allow_reason,
            error_message=f"URL blocked: {allow_reason}",
            request_summary=request_summary,
            response_summary=None,
            http_status=None,
            retry_count_after_failure=None,
            retryable=False,
            final_failure=True,
            next_commands=[],
        )
        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=None,
            error_text=allow_reason,
            elapsed_ms=None,
        )
        print("[HTTP_EXEC CORE] error return =", result)
        return result

    if dry_run:
        result = {
            "ok": True,
            "status": "done",
            "dry_run": True,
            "ts": _now_ts(),
            "request": request_summary,
            "response": {
                "status_code": 0,
                "ok": True,
                "content_type": "application/json",
                "headers": {},
                "body_text": "",
                "body_json": {"dry_run": True},
                "elapsed_ms": 0,
            },
            "retryable": False,
            "final_failure": False,
            "next_commands": [],
            "http_status": 0,
            "status_code": 0,
            "terminal": True,
            **base_result_fields,
        }
        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=0,
            error_text="",
            elapsed_ms=0,
        )
        print("[HTTP_EXEC CORE] success return")
        return result

    started_at = time.time()

    try:
        response = REQUEST_SESSION.request(
            method=method,
            url=url,
            params=params or None,
            headers=headers or None,
            json=json_body,
            data=data_body,
            timeout=timeout_seconds,
            allow_redirects=allow_redirects,
            verify=verify_tls,
        )

        elapsed_ms = int((time.time() - started_at) * 1000)
        response_payload = _extract_response_payload(response)
        response_payload["elapsed_ms"] = elapsed_ms

        success_statuses = original_payload.get("success_statuses")
        if isinstance(success_statuses, list) and success_statuses:
            is_success = int(response.status_code) in {
                _to_int(x, -999999) for x in success_statuses
            }
        else:
            is_success = 200 <= int(response.status_code) < 300

        if is_success:
            result = {
                "ok": True,
                "status": "done",
                "ts": _now_ts(),
                "request": request_summary,
                "response": response_payload,
                "status_code": int(response.status_code),
                "http_status": int(response.status_code),
                "retryable": False,
                "final_failure": False,
                "next_commands": [],
                "terminal": True,
                **base_result_fields,
            }
            _update_monitored_endpoint_best_effort(
                original_payload=original_payload,
                runtime_context=runtime_context,
                status_code=int(response.status_code),
                error_text="",
                elapsed_ms=elapsed_ms,
            )
            print("[HTTP_EXEC CORE] success return")
            return result

        retry_count_after_failure = meta["retry_count"] + 1
        retryable = True
        retry_allowed = retry_count_after_failure <= meta["retry_max"]

        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=int(response.status_code),
            error_text="http_status_error",
            elapsed_ms=elapsed_ms,
        )

        next_retry_at = ""
        next_commands: List[Dict[str, Any]] = []

        if retry_allowed:
            delay_seconds = _compute_backoff_seconds(
                original_payload,
                retry_count_after_failure,
            )
            next_retry_at = _build_next_retry_at(delay_seconds)

            retry_router_input = _build_retry_router_input(
                original_payload=original_payload,
                meta=meta,
                run_record_id=run_record_id,
                retry_count_after_failure=retry_count_after_failure,
                next_retry_at=next_retry_at,
                error_code="http_status_error",
                error_message=f"HTTP request failed with status {response.status_code}",
                http_status=int(response.status_code),
                request_summary=request_summary,
                response_summary=response_payload,
            )

            next_commands = [
                {
                    "capability": "retry_router",
                    "input": retry_router_input,
                }
            ]
        else:
            next_commands = [
                _build_incident_router_command(
                    original_payload=original_payload,
                    meta=meta,
                    error_code="http_status_error",
                    error_message=f"HTTP request failed with status {response.status_code}",
                    http_status=int(response.status_code),
                    request_summary=request_summary,
                    response_summary=response_payload,
                    run_record_id=run_record_id,
                )
            ]

        result = _build_failure_result(
            status="error",
            error_code="http_status_error",
            error_message=f"HTTP request failed with status {response.status_code}",
            request_summary=request_summary,
            response_summary=response_payload,
            http_status=int(response.status_code),
            retry_count_after_failure=retry_count_after_failure,
            retryable=retryable,
            final_failure=not retry_allowed,
            next_commands=next_commands,
        )

        result["retry_planned"] = bool(retry_allowed)
        if next_retry_at:
            result["next_retry_at"] = next_retry_at

        print("[HTTP_EXEC CORE] error return =", result)
        return result

    except requests.Timeout as exc:
        elapsed_ms = int((time.time() - started_at) * 1000)
        retry_count_after_failure = meta["retry_count"] + 1
        retryable = True
        retry_allowed = retry_count_after_failure <= meta["retry_max"]
        error_message = _trim_text(str(exc), 1000) or "Request timeout"

        response_payload = {
            "status_code": None,
            "ok": False,
            "content_type": "",
            "headers": {},
            "body_text": "",
            "body_json": None,
            "elapsed_ms": elapsed_ms,
        }

        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=None,
            error_text="timeout",
            elapsed_ms=elapsed_ms,
        )

        next_retry_at = ""
        next_commands: List[Dict[str, Any]] = []

        if retry_allowed:
            delay_seconds = _compute_backoff_seconds(
                original_payload,
                retry_count_after_failure,
            )
            next_retry_at = _build_next_retry_at(delay_seconds)

            retry_router_input = _build_retry_router_input(
                original_payload=original_payload,
                meta=meta,
                run_record_id=run_record_id,
                retry_count_after_failure=retry_count_after_failure,
                next_retry_at=next_retry_at,
                error_code="timeout",
                error_message=error_message,
                http_status=None,
                request_summary=request_summary,
                response_summary=response_payload,
                request_error_value=error_message,
            )

            next_commands = [
                {
                    "capability": "retry_router",
                    "input": retry_router_input,
                }
            ]
        else:
            next_commands = [
                _build_incident_router_command(
                    original_payload=original_payload,
                    meta=meta,
                    error_code="timeout",
                    error_message=error_message,
                    http_status=None,
                    request_summary=request_summary,
                    response_summary=response_payload,
                    run_record_id=run_record_id,
                )
            ]

        result = _build_failure_result(
            status="error",
            error_code="timeout",
            error_message=error_message,
            request_summary=request_summary,
            response_summary=response_payload,
            http_status=None,
            retry_count_after_failure=retry_count_after_failure,
            retryable=retryable,
            final_failure=not retry_allowed,
            next_commands=next_commands,
        )

        result["retry_planned"] = bool(retry_allowed)
        if next_retry_at:
            result["next_retry_at"] = next_retry_at

        print("[HTTP_EXEC CORE] error return =", result)
        return result

    except requests.RequestException as exc:
        elapsed_ms = int((time.time() - started_at) * 1000)
        retry_count_after_failure = meta["retry_count"] + 1
        retryable = True
        retry_allowed = retry_count_after_failure <= meta["retry_max"]
        error_message = _trim_text(str(exc), 1000) or exc.__class__.__name__

        response_payload = {
            "status_code": None,
            "ok": False,
            "content_type": "",
            "headers": {},
            "body_text": "",
            "body_json": None,
            "elapsed_ms": elapsed_ms,
        }

        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=None,
            error_text="request_exception",
            elapsed_ms=elapsed_ms,
        )

        next_retry_at = ""
        next_commands: List[Dict[str, Any]] = []

        if retry_allowed:
            delay_seconds = _compute_backoff_seconds(
                original_payload,
                retry_count_after_failure,
            )
            next_retry_at = _build_next_retry_at(delay_seconds)

            retry_router_input = _build_retry_router_input(
                original_payload=original_payload,
                meta=meta,
                run_record_id=run_record_id,
                retry_count_after_failure=retry_count_after_failure,
                next_retry_at=next_retry_at,
                error_code="request_exception",
                error_message=error_message,
                http_status=None,
                request_summary=request_summary,
                response_summary=response_payload,
                request_error_value=error_message,
            )

            next_commands = [
                {
                    "capability": "retry_router",
                    "input": retry_router_input,
                }
            ]
        else:
            next_commands = [
                _build_incident_router_command(
                    original_payload=original_payload,
                    meta=meta,
                    error_code="request_exception",
                    error_message=error_message,
                    http_status=None,
                    request_summary=request_summary,
                    response_summary=response_payload,
                    run_record_id=run_record_id,
                )
            ]

        result = _build_failure_result(
            status="error",
            error_code="request_exception",
            error_message=error_message,
            request_summary=request_summary,
            response_summary=response_payload,
            http_status=None,
            retry_count_after_failure=retry_count_after_failure,
            retryable=retryable,
            final_failure=not retry_allowed,
            next_commands=next_commands,
        )

        result["retry_planned"] = bool(retry_allowed)
        if next_retry_at:
            result["next_retry_at"] = next_retry_at

        print("[HTTP_EXEC CORE] error return =", result)
        return result

    except Exception as exc:
        elapsed_ms = int((time.time() - started_at) * 1000)
        retry_count_after_failure = meta["retry_count"] + 1
        retryable = True
        retry_allowed = retry_count_after_failure <= meta["retry_max"]
        error_message = _trim_text(f"{exc.__class__.__name__}: {exc}", 1000)

        response_payload = {
            "status_code": None,
            "ok": False,
            "content_type": "",
            "headers": {},
            "body_text": "",
            "body_json": None,
            "elapsed_ms": elapsed_ms,
        }

        _update_monitored_endpoint_best_effort(
            original_payload=original_payload,
            runtime_context=runtime_context,
            status_code=None,
            error_text="unexpected_exception",
            elapsed_ms=elapsed_ms,
        )

        next_retry_at = ""
        next_commands: List[Dict[str, Any]] = []

        if retry_allowed:
            delay_seconds = _compute_backoff_seconds(
                original_payload,
                retry_count_after_failure,
            )
            next_retry_at = _build_next_retry_at(delay_seconds)

            retry_router_input = _build_retry_router_input(
                original_payload=original_payload,
                meta=meta,
                run_record_id=run_record_id,
                retry_count_after_failure=retry_count_after_failure,
                next_retry_at=next_retry_at,
                error_code="unexpected_exception",
                error_message=error_message,
                http_status=None,
                request_summary=request_summary,
                response_summary=response_payload,
                request_error_value=error_message,
            )

            next_commands = [
                {
                    "capability": "retry_router",
                    "input": retry_router_input,
                }
            ]
        else:
            next_commands = [
                _build_incident_router_command(
                    original_payload=original_payload,
                    meta=meta,
                    error_code="unexpected_exception",
                    error_message=error_message,
                    http_status=None,
                    request_summary=request_summary,
                    response_summary=response_payload,
                    run_record_id=run_record_id,
                )
            ]

        result = _build_failure_result(
            status="error",
            error_code="unexpected_exception",
            error_message=error_message,
            request_summary=request_summary,
            response_summary=response_payload,
            http_status=None,
            retry_count_after_failure=retry_count_after_failure,
            retryable=retryable,
            final_failure=not retry_allowed,
            next_commands=next_commands,
        )

        result["retry_planned"] = bool(retry_allowed)
        if next_retry_at:
            result["next_retry_at"] = next_retry_at

        print("[HTTP_EXEC CORE] error return =", result)
        return result


def run(
    payload: Optional[Any] = None,
    context: Optional[Any] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    if payload is not None and hasattr(payload, "input"):
        payload = getattr(payload, "input", {}) or {}
    elif not isinstance(payload, dict):
        payload = {}

    return capability_http_exec(payload=payload, context=context, **kwargs)
