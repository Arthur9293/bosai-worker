# app/capabilities/http_exec.py

from __future__ import annotations
import ipaddress
import json
import os
import socket
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import requests

HTTP_EXEC_ENABLED = True
DEFAULT_RETRY_MAX = 3


def _now_ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_int(v, d):
    try:
        return int(v)
    except:
        return d


def _extract_retry_meta(payload):
    return {
        "flow_id": payload.get("flow_id", ""),
        "root_event_id": payload.get("root_event_id", ""),
        "step_index": _to_int(payload.get("step_index"), 0),
        "retry_count": _to_int(payload.get("retry_count"), 0),
        "retry_max": _to_int(payload.get("retry_max"), DEFAULT_RETRY_MAX),
    }


def _retry_meta_block(meta):
    return {
        "flow_id": meta["flow_id"],
        "root_event_id": meta["root_event_id"],
        "step_index": meta["step_index"],
        "retry_count": meta["retry_count"],
        "retry_max": meta["retry_max"],
        "retry": {"count": meta["retry_count"], "max": meta["retry_max"]},
    }


def _build_retry_input(payload, flow_id, root_event_id, workspace_id, reason, error="", http_status=None):
    retry_input = dict(payload)

    retry_input.update({
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "original_capability": "http_exec",
        "original_input": dict(payload),
        "retry_reason": reason,
    })

    if error:
        retry_input["error"] = error
    if http_status is not None:
        retry_input["http_status"] = http_status

    return retry_input


def capability_http_exec(input_data=None, dry_run=False, **_):
    started_at = _now_ts()
    payload = input_data or {}

    retry_meta = _extract_retry_meta(payload)
    retry_block = _retry_meta_block(retry_meta)

    flow_id = payload.get("flow_id", "")
    root_event_id = payload.get("root_event_id", "")
    workspace_id = payload.get("workspace_id", "")

    method = payload.get("method", "GET")
    url = payload.get("url")

    try:
        response = requests.request(method, url, timeout=20)
        elapsed = 0

        if response.ok:
            return {
                "ok": True,
                "capability": "http_exec",
                "status": "done",
                "started_at": started_at,
                "finished_at": _now_ts(),
                "elapsed_ms": elapsed,
                **retry_block,
                "response": {
                    "status_code": response.status_code,
                },
                "next_commands": [],
                "terminal": False,
            }

        # ---------------------------
        # ERROR → RETRY ROUTER
        # ---------------------------

        error_payload = _build_retry_input(
            payload,
            flow_id,
            root_event_id,
            workspace_id,
            reason="http_status_error",
            error=f"HTTP {response.status_code}",
            http_status=response.status_code,
        )

        # IMPORTANT: conserver état runtime
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
            **retry_block,
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

    except Exception as exc:

        error_payload = _build_retry_input(
            payload,
            flow_id,
            root_event_id,
            workspace_id,
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
            **retry_block,
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


def run(req=None, run_record_id=""):
    payload = req if isinstance(req, dict) else getattr(req, "input", {}) or {}

    if run_record_id:
        payload["run_record_id"] = run_record_id

    return capability_http_exec(payload)
