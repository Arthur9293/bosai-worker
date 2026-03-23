# app/capabilities/http_exec.py

from __future__ import annotations

import time
from typing import Any, Dict

import requests

HTTP_EXEC_ENABLED = True
DEFAULT_RETRY_MAX = 3
DEFAULT_TIMEOUT_SECONDS = 20


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_int(v: Any, d: int) -> int:
    try:
        return int(v)
    except Exception:
        return d


def _extract_retry_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "flow_id": str(payload.get("flow_id", "") or ""),
        "root_event_id": str(payload.get("root_event_id", "") or ""),
        "step_index": _to_int(payload.get("step_index"), 0),
        "retry_count": _to_int(payload.get("retry_count"), 0),
        "retry_max": _to_int(payload.get("retry_max"), DEFAULT_RETRY_MAX),
    }


def _retry_meta_block(meta: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "flow_id": meta["flow_id"],
        "root_event_id": meta["root_event_id"],
        "step_index": meta["step_index"],
        "retry_count": meta["retry_count"],
        "retry_max": meta["retry_max"],
        "retry": {
            "count": meta["retry_count"],
            "max": meta["retry_max"],
        },
    }


def _build_retry_input(
    payload: Dict[str, Any],
    flow_id: str,
    root_event_id: str,
    workspace_id: str,
    reason: str,
    error: str = "",
    http_status: int | None = None,
    response_status_code: int | None = None,
) -> Dict[str, Any]:
    retry_input = dict(payload)

    retry_input.update(
        {
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "workspace_id": workspace_id,
            "original_capability": "http_exec",
            "original_input": dict(payload),
            "retry_reason": reason,
        }
    )

    if error:
        retry_input["error"] = error

    if http_status is not None:
        retry_input["http_status"] = http_status

    if response_status_code is not None:
        retry_input["response"] = {
            "status_code": response_status_code,
        }

    return retry_input


def capability_http_exec(
    input_data: Dict[str, Any] | None = None,
    dry_run: bool = False,
    **_: Any,
) -> Dict[str, Any]:
    started_at = _now_ts()
    payload = input_data or {}

    retry_meta = _extract_retry_meta(payload)
    retry_block = _retry_meta_block(retry_meta)

    flow_id = retry_meta["flow_id"]
    root_event_id = retry_meta["root_event_id"]
    workspace_id = str(payload.get("workspace_id", "") or "")

    method = str(payload.get("method", "GET") or "GET").upper()
    url = str(
        payload.get("url")
        or payload.get("http_target")
        or payload.get("URL")
        or ""
    ).strip()
    timeout_seconds = _to_int(payload.get("timeout_seconds"), DEFAULT_TIMEOUT_SECONDS)

    if not HTTP_EXEC_ENABLED:
        error_payload = _build_retry_input(
            payload=payload,
            flow_id=flow_id,
            root_event_id=root_event_id,
            workspace_id=workspace_id,
            reason="capability_disabled",
            error="HTTP_EXEC_ENABLED=0",
        )
        error_payload["retry_count"] = retry_meta["retry_count"]
        error_payload["retry_max"] = retry_meta["retry_max"]
        error_payload["step_index"] = retry_meta["step_index"]

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "disabled",
            "error_code": "http_exec_disabled",
            "error": "HTTP_EXEC_ENABLED=0",
            "started_at": started_at,
            "finished_at": _now_ts(),
            **retry_block,
            "workspace_id": workspace_id,
            "run_record_id": payload.get("run_record_id", ""),
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "capability_disabled",
            "terminal": False,
        }

    if not url:
        error_payload = _build_retry_input(
            payload=payload,
            flow_id=flow_id,
            root_event_id=root_event_id,
            workspace_id=workspace_id,
            reason="missing_url",
            error="HTTP_EXEC missing url (Input_JSON.url / http_target / URL)",
        )
        error_payload["retry_count"] = retry_meta["retry_count"]
        error_payload["retry_max"] = retry_meta["retry_max"]
        error_payload["step_index"] = retry_meta["step_index"]

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error_code": "missing_url",
            "error": "HTTP_EXEC missing url (Input_JSON.url / http_target / URL)",
            "started_at": started_at,
            "finished_at": _now_ts(),
            **retry_block,
            "workspace_id": workspace_id,
            "run_record_id": payload.get("run_record_id", ""),
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "missing_url",
            "terminal": False,
        }

    if dry_run:
        return {
            "ok": True,
            "capability": "http_exec",
            "status": "dry_run",
            "started_at": started_at,
            "finished_at": _now_ts(),
            **retry_block,
            "workspace_id": workspace_id,
            "run_record_id": payload.get("run_record_id", ""),
            "request": {
                "method": method,
                "url": url,
                "timeout_seconds": timeout_seconds,
            },
            "next_commands": [],
            "terminal": True,
        }

    request_started = time.time()

    try:
        response = requests.request(
            method=method,
            url=url,
            timeout=timeout_seconds,
        )
        elapsed = int((time.time() - request_started) * 1000)

        if response.ok:
            return {
                "ok": True,
                "capability": "http_exec",
                "status": "done",
                "started_at": started_at,
                "finished_at": _now_ts(),
                "elapsed_ms": elapsed,
                **retry_block,
                "workspace_id": workspace_id,
                "run_record_id": payload.get("run_record_id", ""),
                "request": {
                    "method": method,
                    "url": url,
                    "timeout_seconds": timeout_seconds,
                },
                "response": {
                    "status_code": response.status_code,
                    "reason": response.reason,
                    "ok_http": response.ok,
                    "final_url": response.url,
                },
                "next_commands": [],
                "terminal": False,
            }

        error_payload = _build_retry_input(
            payload=payload,
            flow_id=flow_id,
            root_event_id=root_event_id,
            workspace_id=workspace_id,
            reason="http_status_error",
            error=f"HTTP {response.status_code}",
            http_status=response.status_code,
            response_status_code=response.status_code,
        )

        error_payload["retry_count"] = retry_meta["retry_count"]
        error_payload["retry_max"] = retry_meta["retry_max"]
        error_payload["step_index"] = retry_meta["step_index"]

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error_code": "http_status_error",
            "error": f"HTTP {response.status_code}",
            "started_at": started_at,
            "finished_at": _now_ts(),
            "elapsed_ms": elapsed,
            **retry_block,
            "workspace_id": workspace_id,
            "run_record_id": payload.get("run_record_id", ""),
            "request": {
                "method": method,
                "url": url,
                "timeout_seconds": timeout_seconds,
            },
            "response": {
                "status_code": response.status_code,
                "reason": response.reason,
                "ok_http": response.ok,
                "final_url": response.url,
            },
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "http_status_error",
            "terminal": False,
        }

    except requests.Timeout as exc:
        elapsed = int((time.time() - request_started) * 1000)

        error_payload = _build_retry_input(
            payload=payload,
            flow_id=flow_id,
            root_event_id=root_event_id,
            workspace_id=workspace_id,
            reason="timeout",
            error=str(exc),
        )
        error_payload["retry_count"] = retry_meta["retry_count"]
        error_payload["retry_max"] = retry_meta["retry_max"]
        error_payload["step_index"] = retry_meta["step_index"]

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error_code": "timeout",
            "error": str(exc),
            "started_at": started_at,
            "finished_at": _now_ts(),
            "elapsed_ms": elapsed,
            **retry_block,
            "workspace_id": workspace_id,
            "run_record_id": payload.get("run_record_id", ""),
            "request": {
                "method": method,
                "url": url,
                "timeout_seconds": timeout_seconds,
            },
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "timeout",
            "terminal": False,
        }

    except requests.RequestException as exc:
        elapsed = int((time.time() - request_started) * 1000)

        error_payload = _build_retry_input(
            payload=payload,
            flow_id=flow_id,
            root_event_id=root_event_id,
            workspace_id=workspace_id,
            reason="request_exception",
            error=str(exc),
        )
        error_payload["retry_count"] = retry_meta["retry_count"]
        error_payload["retry_max"] = retry_meta["retry_max"]
        error_payload["step_index"] = retry_meta["step_index"]

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error_code": "request_exception",
            "error": str(exc),
            "started_at": started_at,
            "finished_at": _now_ts(),
            "elapsed_ms": elapsed,
            **retry_block,
            "workspace_id": workspace_id,
            "run_record_id": payload.get("run_record_id", ""),
            "request": {
                "method": method,
                "url": url,
                "timeout_seconds": timeout_seconds,
            },
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "request_exception",
            "terminal": False,
        }

    except Exception as exc:
        elapsed = int((time.time() - request_started) * 1000)

        error_payload = _build_retry_input(
            payload=payload,
            flow_id=flow_id,
            root_event_id=root_event_id,
            workspace_id=workspace_id,
            reason="unexpected_exception",
            error=str(exc),
        )
        error_payload["retry_count"] = retry_meta["retry_count"]
        error_payload["retry_max"] = retry_meta["retry_max"]
        error_payload["step_index"] = retry_meta["step_index"]

        return {
            "ok": False,
            "capability": "http_exec",
            "status": "error",
            "error_code": "unexpected_exception",
            "error": str(exc),
            "started_at": started_at,
            "finished_at": _now_ts(),
            "elapsed_ms": elapsed,
            **retry_block,
            "workspace_id": workspace_id,
            "run_record_id": payload.get("run_record_id", ""),
            "request": {
                "method": method,
                "url": url,
                "timeout_seconds": timeout_seconds,
            },
            "next_commands": [
                {
                    "capability": "retry_router",
                    "priority": 2,
                    "input": error_payload,
                }
            ],
            "retry_reason": "unexpected_exception",
            "terminal": False,
        }


def run(req: Any = None, run_record_id: str = "") -> Dict[str, Any]:
    payload = req if isinstance(req, dict) else getattr(req, "input", {}) or {}

    if not isinstance(payload, dict):
        payload = {}

    payload = dict(payload)

    if run_record_id:
        payload["run_record_id"] = run_record_id

    return capability_http_exec(payload)
