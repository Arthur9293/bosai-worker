from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional


DEFAULT_MAX_DEPTH = 8


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _to_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _to_int(value: Any, default: int = 0) -> int:
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


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return "{}"


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _extract_input(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    for key in ("input", "command_input", "incident"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            merged = dict(payload)
            merged.update(nested)
            return merged

    return dict(payload)


def _extract_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "flow_id": _to_str(
            payload.get("flow_id")
            or payload.get("flowid")
            or payload.get("flowId")
            or ""
        ),
        "root_event_id": _to_str(
            payload.get("root_event_id")
            or payload.get("rooteventid")
            or payload.get("rootEventId")
            or payload.get("event_id")
            or payload.get("eventid")
            or payload.get("eventId")
            or ""
        ),
        "parent_command_id": _to_str(
            payload.get("parent_command_id")
            or payload.get("parentcommand_id")
            or payload.get("parentCommandId")
            or ""
        ),
        "step_index": _to_int(
            payload.get("step_index")
            if payload.get("step_index") is not None
            else payload.get("stepindex")
            if payload.get("stepindex") is not None
            else payload.get("stepIndex"),
            0,
        ),
        "depth": _to_int(
            payload.get("depth")
            if payload.get("depth") is not None
            else payload.get("_depth")
            if payload.get("_depth") is not None
            else 0,
            0,
        ),
        "workspace_id": _to_str(
            payload.get("workspace_id")
            or payload.get("workspaceid")
            or payload.get("workspaceId")
            or "production"
        ),
        "run_record_id": _to_str(
            payload.get("run_record_id")
            or payload.get("runrecordid")
            or payload.get("runRecordId")
            or ""
        ),
    }


def _build_incident_key(data: Dict[str, Any], meta: Dict[str, Any]) -> str:
    flow_id = _to_str(meta.get("flow_id"))
    root_event_id = _to_str(meta.get("root_event_id"))
    original_capability = _to_str(
        data.get("original_capability")
        or data.get("failed_capability")
        or "unknown_capability"
    )
    failed_method = _to_str(
        data.get("failed_method")
        or data.get("method")
        or "GET"
    ).upper()
    failed_url = _to_str(
        data.get("failed_url")
        or data.get("target_url")
        or data.get("url")
        or ""
    )
    http_status = _to_str(data.get("http_status") or "")
    incident_code = _to_str(data.get("incident_code") or "").strip().lower()
    reason = _to_str(data.get("reason") or "incident")
    final_failure = _to_bool(data.get("final_failure"), False)

    return "|".join(
        [
            flow_id or "no_flow",
            root_event_id or "no_root",
            original_capability or "no_cap",
            failed_method or "no_method",
            failed_url or "no_url",
            http_status or "no_status",
            incident_code or "no_incident_code",
            reason or "no_reason",
            "final" if final_failure else "not_final",
        ]
    )


def _find_existing_incident(
    incidents_table_name: str,
    incident_key: str,
    airtable_list_filtered,
) -> Optional[Dict[str, Any]]:
    formula_candidates = [
        f"AND({{Incident_Key}}='{incident_key}', OR({{Status_select}}='Open', {{Status_select}}='Investigating', {{Status_select}}='Escalated'))",
        f"AND({{Incident_Key}}='{incident_key}', {{Status_select}}='Open')",
        f"{{Incident_Key}}='{incident_key}'",
    ]

    for formula in formula_candidates:
        try:
            recs = airtable_list_filtered(
                incidents_table_name,
                formula=formula,
                max_records=1,
            )
            if isinstance(recs, list) and recs:
                return recs[0]
        except Exception:
            continue

    return None


def _build_update_candidates(
    existing_fields: Dict[str, Any],
    data: Dict[str, Any],
    meta: Dict[str, Any],
) -> List[Dict[str, Any]]:
    now_ts = _now_ts()

    current_count = _to_int(existing_fields.get("Occurrences_Count"), 0)
    next_count = current_count + 1 if current_count > 0 else 2

    base = {
        "Last_Seen_At": now_ts,
        "Last_Action": "incident_deduplicate_reused",
        "Payload_JSON": _safe_json(data),
        "Run_Record_ID": _to_str(meta.get("run_record_id")),
    }

    candidates: List[Dict[str, Any]] = [
        {
            **base,
            "Occurrences_Count": next_count,
        },
        {
            **base,
            "Occurrences_Count": next_count,
            "Status_select": _to_str(existing_fields.get("Status_select") or "Open"),
        },
        base,
        {
            "Last_Seen_At": now_ts,
        },
    ]

    return candidates


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    *,
    airtable_list_filtered,
    airtable_update,
    incidents_table_name: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    if req is not None and hasattr(req, "input"):
        payload = getattr(req, "input", {}) or {}
    elif isinstance(req, dict):
        payload = req
    else:
        payload = {}

    data = _extract_input(payload)
    meta = _extract_meta(data)

    depth = _to_int(meta.get("depth"), 0)
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "incident_deduplicate",
            "error": "max_depth_reached",
            "flow_id": meta.get("flow_id", ""),
            "root_event_id": meta.get("root_event_id", ""),
            "run_record_id": run_record_id or meta.get("run_record_id", ""),
            "terminal": True,
        }

    effective_run_record_id = _to_str(run_record_id or meta.get("run_record_id") or "")
    incident_key = _to_str(data.get("incident_key") or "").strip()
    if not incident_key:
        incident_key = _build_incident_key(data, meta)

    existing = _find_existing_incident(
        incidents_table_name=incidents_table_name,
        incident_key=incident_key,
        airtable_list_filtered=airtable_list_filtered,
    )

    if existing:
        existing_id = _to_str(existing.get("id") or "")
        existing_fields = _safe_dict(existing.get("fields"))

        updated = False
        update_error = ""

        for candidate in _build_update_candidates(existing_fields, data, meta):
            try:
                airtable_update(incidents_table_name, existing_id, candidate)
                updated = True
                break
            except Exception as e:
                update_error = repr(e)

        next_commands = [
            {
                "capability": "incident_update",
                "priority": 1,
                "input": {
                    "flow_id": meta.get("flow_id", ""),
                    "root_event_id": meta.get("root_event_id", ""),
                    "step_index": _to_int(meta.get("step_index"), 0) + 1,
                    "_depth": depth + 1,
                    "workspace_id": meta.get("workspace_id", ""),
                    "goal": "incident_update_existing",
                    "decision": _to_str(data.get("decision") or ""),
                    "reason": _to_str(data.get("reason") or "incident_reused"),
                    "severity": _to_str(data.get("severity") or "medium"),
                    "category": _to_str(data.get("category") or "unknown_incident"),
                    "error": _to_str(data.get("error") or data.get("error_message") or ""),
                    "incident_code": _to_str(data.get("incident_code") or ""),
                    "final_failure": _to_bool(data.get("final_failure"), False),
                    "original_capability": _to_str(
                        data.get("original_capability")
                        or data.get("failed_capability")
                        or ""
                    ),
                    "failed_url": _to_str(data.get("failed_url") or data.get("target_url") or ""),
                    "failed_method": _to_str(data.get("failed_method") or data.get("method") or "").upper(),
                    "retry_count": _to_int(data.get("retry_count"), 0),
                    "retry_max": _to_int(data.get("retry_max"), 0),
                    "http_status": _to_int(data.get("http_status"), 0),
                    "incident_record_id": existing_id,
                    "log_record_id": _to_str(data.get("log_record_id") or ""),
                    "run_record_id": effective_run_record_id,
                    "incident_key": incident_key,
                    "deduplicate_action": "reuse_existing",
                    "parent_command_id": _to_str(meta.get("parent_command_id") or ""),
                },
                "terminal": False,
            }
        ]

        return {
            "ok": True,
            "capability": "incident_deduplicate",
            "status": "done",
            "flow_id": meta.get("flow_id", ""),
            "root_event_id": meta.get("root_event_id", ""),
            "run_record_id": effective_run_record_id,
            "incident_key": incident_key,
            "incident_exists": True,
            "incident_record_id": existing_id,
            "action": "reuse_existing",
            "updated_existing": updated,
            "update_error": update_error,
            "next_commands": next_commands,
            "terminal": False,
            "spawn_summary": {
                "ok": True,
                "spawned": 1,
                "skipped": 0,
                "errors": [],
            },
        }

    next_commands = [
        {
            "capability": "incident_create",
            "priority": 1,
            "input": {
                "flow_id": meta.get("flow_id", ""),
                "root_event_id": meta.get("root_event_id", ""),
                "step_index": _to_int(meta.get("step_index"), 0) + 1,
                "_depth": depth + 1,
                "workspace_id": meta.get("workspace_id", ""),
                "goal": "incident_create",
                "decision": _to_str(data.get("decision") or ""),
                "reason": _to_str(data.get("reason") or "incident_new"),
                "severity": _to_str(data.get("severity") or "medium"),
                "category": _to_str(data.get("category") or "unknown_incident"),
                "error": _to_str(data.get("error") or data.get("error_message") or ""),
                "error_message": _to_str(data.get("error") or data.get("error_message") or ""),
                "incident_code": _to_str(data.get("incident_code") or ""),
                "final_failure": _to_bool(data.get("final_failure"), False),
                "original_capability": _to_str(
                    data.get("original_capability")
                    or data.get("failed_capability")
                    or ""
                ),
                "failed_capability": _to_str(
                    data.get("failed_capability")
                    or data.get("original_capability")
                    or ""
                ),
                "failed_url": _to_str(data.get("failed_url") or data.get("target_url") or ""),
                "target_url": _to_str(data.get("target_url") or data.get("failed_url") or ""),
                "failed_method": _to_str(data.get("failed_method") or data.get("method") or "").upper(),
                "method": _to_str(data.get("method") or data.get("failed_method") or "").upper(),
                "retry_count": _to_int(data.get("retry_count"), 0),
                "retry_max": _to_int(data.get("retry_max"), 0),
                "http_status": _to_int(data.get("http_status"), 0),
                "incident_record_id": "",
                "log_record_id": _to_str(data.get("log_record_id") or ""),
                "run_record_id": effective_run_record_id,
                "incident_key": incident_key,
                "deduplicate_action": "create_new",
                "parent_command_id": _to_str(meta.get("parent_command_id") or ""),
            },
            "terminal": False,
        }
    ]

    return {
        "ok": True,
        "capability": "incident_deduplicate",
        "status": "done",
        "flow_id": meta.get("flow_id", ""),
        "root_event_id": meta.get("root_event_id", ""),
        "run_record_id": effective_run_record_id,
        "incident_key": incident_key,
        "incident_exists": False,
        "incident_record_id": "",
        "action": "create_new",
        "next_commands": next_commands,
        "terminal": False,
        "spawn_summary": {
            "ok": True,
            "spawned": 1,
            "skipped": 0,
            "errors": [],
        },
    }
