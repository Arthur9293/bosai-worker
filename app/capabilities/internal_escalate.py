from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


DEFAULT_MAX_DEPTH = 8
AIRTABLE_RECORD_ID_RE = re.compile(r"^rec[a-zA-Z0-9]{14}$")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return "{}"


def _to_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
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


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _json_load_maybe(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    candidates = [text]

    try:
        candidates.append(bytes(text, "utf-8").decode("unicode_escape"))
    except Exception:
        pass

    candidates.append(text.replace('\\"', '"'))
    candidates.append(text.replace("\\_", "_"))
    candidates.append(text.replace('\\"', '"').replace("\\_", "_"))

    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)

        try:
            parsed = json.loads(candidate)
        except Exception:
            continue

        if isinstance(parsed, str):
            inner = parsed.strip()
            if not inner:
                continue
            try:
                return json.loads(inner)
            except Exception:
                return parsed

        return parsed

    return None


def _is_empty(value: Any) -> bool:
    return value in ("", None, [], {})


def _is_airtable_record_id(value: Any) -> bool:
    rid = _to_str(value).strip()
    return bool(AIRTABLE_RECORD_ID_RE.match(rid))


def _extract_record_id(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, str):
        text = value.strip()
        if _is_airtable_record_id(text):
            return text

        parsed = _json_load_maybe(text)
        if parsed is not None and parsed is not value:
            return _extract_record_id(parsed)
        return ""

    if isinstance(value, list):
        for item in value:
            rid = _extract_record_id(item)
            if rid:
                return rid
        return ""

    if isinstance(value, dict):
        for key in (
            "incident_record_id",
            "record_id",
            "id",
            "Incident_Record_ID",
        ):
            rid = _extract_record_id(value.get(key))
            if rid:
                return rid

        for key in ("response", "result", "incident_create_res", "incident_result"):
            rid = _extract_record_id(value.get(key))
            if rid:
                return rid

    return ""


def _extract_input(req: Any) -> Dict[str, Any]:
    if req is not None and hasattr(req, "input"):
        payload = getattr(req, "input", {}) or {}
    elif isinstance(req, dict):
        payload = req
    else:
        payload = {}

    if isinstance(payload, str):
        payload = _json_load_maybe(payload) or {}

    if not isinstance(payload, dict):
        return {}

    normalized = dict(payload)

    for key in ("input", "command_input", "incident"):
        nested = normalized.get(key)
        if isinstance(nested, str):
            nested = _json_load_maybe(nested)
        if isinstance(nested, dict):
            merged = dict(normalized)
            merged.update(nested)
            normalized = merged

    return normalized


def _clean_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in fields.items() if v not in ("", None, [])}


def _safe_record_links(record_id: str) -> List[str]:
    rid = _to_str(record_id).strip()
    return [rid] if _is_airtable_record_id(rid) else []


def _normalize_status_for_airtable(value: str) -> str:
    raw = _to_str(value, "Open").strip().lower()

    if raw in {"open", "opened", "active", "new", "en cours"}:
        return "Open"
    if raw in {"escalated", "escalade", "escaladé"}:
        return "Escalated"
    if raw in {"resolved", "closed", "done", "résolu", "resolve"}:
        return "Resolved"

    return "Open"


def _normalize_severity_for_airtable(value: str) -> str:
    raw = _to_str(value, "High").strip().lower()

    if raw in {"critical", "critique"}:
        return "Critical"
    if raw in {"high", "élevé", "eleve"}:
        return "High"
    if raw in {"medium", "moyen", "warning", "warn"}:
        return "Medium"
    if raw in {"low", "faible"}:
        return "Low"

    return "High"


def _normalize_sla_for_airtable(value: str) -> str:
    raw = _to_str(value, "Open").strip().lower()

    if raw in {"open", "opened"}:
        return "Open"
    if raw in {"warning", "warn"}:
        return "Warning"
    if raw in {"ok"}:
        return "OK"
    if raw in {"breached", "breach"}:
        return "Breached"
    if raw in {"resolved", "closed"}:
        return "Resolved"

    return "Open"


def _extract_created_record_id(response: Any) -> str:
    if isinstance(response, dict):
        rid = _to_str(response.get("id")).strip()
        if rid:
            return rid

        rid = _to_str(response.get("record_id")).strip()
        if rid:
            return rid

        records = response.get("records")
        if isinstance(records, list) and records:
            first = records[0]
            if isinstance(first, dict):
                rid = _to_str(first.get("id")).strip()
                if rid:
                    return rid

    return ""


def _build_incident_title(
    *,
    category: str,
    failed_url: str,
    flow_id: str,
    root_event_id: str,
) -> str:
    safe_category = _to_str(category, "incident").strip().upper()
    safe_failed_url = _to_str(failed_url).strip()
    safe_flow_id = _to_str(flow_id).strip()
    safe_root_event_id = _to_str(root_event_id).strip()

    if safe_failed_url:
        return f"{safe_category} | {safe_failed_url}"
    if safe_flow_id:
        return f"{safe_category} | {safe_flow_id}"
    if safe_root_event_id:
        return f"{safe_category} | {safe_root_event_id}"
    return safe_category or "INCIDENT"


def _extract_search_dicts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []

    def _append_candidate(value: Any) -> None:
        if isinstance(value, str):
            value = _json_load_maybe(value)
        if isinstance(value, dict) and value:
            result.append(dict(value))

    if isinstance(payload, dict):
        result.append(dict(payload))

    for key in (
        "incident_result",
        "incident_create_res",
        "incident_update_res",
        "original_input",
        "body",
        "payload",
        "result",
        "response",
        "input",
        "command_input",
        "incident",
    ):
        nested = payload.get(key) if isinstance(payload, dict) else None
        _append_candidate(nested)

    return result


def _pick_text_from_dicts(dicts: List[Dict[str, Any]], *keys: str, default: str = "") -> str:
    for data in dicts:
        if not isinstance(data, dict):
            continue
        for key in keys:
            if key not in data:
                continue

            value = data.get(key)

            rid = _extract_record_id(value)
            if rid:
                return rid

            if isinstance(value, (dict, list)):
                continue

            text = _to_str(value).strip()
            if text:
                return text

    return default


def _pick_value_from_dicts(dicts: List[Dict[str, Any]], *keys: str) -> Any:
    for data in dicts:
        if not isinstance(data, dict):
            continue
        for key in keys:
            if key in data and not _is_empty(data.get(key)):
                return data.get(key)
    return None


def _try_update_one(
    airtable_update,
    table_name: str,
    record_id: str,
    fields: Dict[str, Any],
) -> Dict[str, Any]:
    try:
        print("[TRY_UPDATE_ONE] table =", table_name)
        print("[TRY_UPDATE_ONE] record_id =", record_id)
        print("[TRY_UPDATE_ONE] fields =", _safe_json(fields))
        response = airtable_update(table_name, record_id, fields)
        return {"ok": True, "fields": fields, "response": response}
    except Exception as e:
        print("[TRY_UPDATE_ONE] error =", repr(e))
        return {"ok": False, "fields": fields, "error": repr(e)}


def _try_create_one(
    airtable_create,
    table_name: str,
    fields: Dict[str, Any],
) -> Dict[str, Any]:
    try:
        print("[TRY_CREATE_ONE] table =", table_name)
        print("[TRY_CREATE_ONE] fields =", _safe_json(fields))
        response = airtable_create(table_name, fields)
        record_id = _extract_created_record_id(response)
        return {
            "ok": True,
            "fields": fields,
            "response": response,
            "record_id": record_id,
        }
    except Exception as e:
        print("[TRY_CREATE_ONE] error =", repr(e))
        return {"ok": False, "fields": fields, "error": repr(e), "record_id": ""}


def _best_effort_update_logs_error(
    airtable_update,
    logs_errors_table_name: str,
    log_record_id: str,
    escalation_result: Dict[str, Any],
) -> Dict[str, Any]:
    if not log_record_id:
        return {
            "ok": True,
            "skipped": True,
            "reason": "missing_log_record_id",
            "chosen_fields": {},
            "attempts": [],
        }

    result_json = _safe_json(escalation_result)

    attempts: List[Dict[str, Any]] = [
        {"Result_JSON": result_json},
    ]

    results: List[Dict[str, Any]] = []

    for fields in attempts:
        res = _try_update_one(
            airtable_update=airtable_update,
            table_name=logs_errors_table_name,
            record_id=log_record_id,
            fields=fields,
        )
        results.append(res)

        if res.get("ok"):
            return {
                "ok": True,
                "skipped": False,
                "chosen_fields": fields,
                "attempts": results,
            }

    return {
        "ok": False,
        "skipped": False,
        "chosen_fields": {},
        "attempts": results,
    }


def _best_effort_create_incident(
    airtable_create,
    incidents_table_name: str,
    *,
    title: str,
    status_select: str,
    severity: str,
    sla_status: str,
    category: str,
    reason: str,
    flow_id: str,
    root_event_id: str,
    workspace_id: str,
    run_record_id: str,
    parent_command_id: str,
    last_action: str,
    failed_url: str,
    http_status: Any,
    incident_code: str,
    final_failure: bool,
) -> Dict[str, Any]:
    if not airtable_create:
        return {"ok": False, "reason": "missing_airtable_create", "attempts": []}

    if not incidents_table_name:
        return {"ok": False, "reason": "missing_incidents_table_name", "attempts": []}

    now_ts = utc_now_iso()
    linked_run_ids = _safe_record_links(run_record_id)
    linked_command_ids = _safe_record_links(parent_command_id)

    rich = {
        "Name": title,
        "Status_select": status_select,
        "Severity": severity,
        "SLA_Status": sla_status,
        "Category": category,
        "Reason": reason,
        "Opened_At": now_ts,
        "Updated_At": now_ts,
        "Last_Action": last_action,
        "Workspace_ID": workspace_id,
        "Flow_ID": flow_id,
        "Root_Event_ID": root_event_id,
        "Run_Record_ID": run_record_id,
        "Command_ID": parent_command_id,
        "Failed_URL": failed_url,
        "HTTP_Status": http_status,
        "Incident_Code": incident_code,
        "Final_Failure": final_failure,
    }
    if linked_run_ids:
        rich["Linked_Run"] = linked_run_ids
    if linked_command_ids:
        rich["Linked_Command"] = linked_command_ids

    attempts: List[Dict[str, Any]] = [
        rich,
        {
            "Name": title,
            "Status_select": status_select,
            "Severity": severity,
            "SLA_Status": sla_status,
            "Category": category,
            "Reason": reason,
            "Updated_At": now_ts,
            "Workspace_ID": workspace_id,
            "Flow_ID": flow_id,
            "Root_Event_ID": root_event_id,
            "Run_Record_ID": run_record_id,
            "Command_ID": parent_command_id,
        },
        {
            "Name": title,
            "Status_select": status_select,
            "Severity": severity,
            "Workspace_ID": workspace_id,
            "Flow_ID": flow_id,
            "Root_Event_ID": root_event_id,
        },
        {
            "Name": title,
            "Status_select": status_select,
            "Severity": severity,
        },
        {
            "Name": title,
            "Status_select": status_select,
        },
    ]

    results: List[Dict[str, Any]] = []

    for fields in attempts:
        clean_fields = _clean_fields(fields)

        res = _try_create_one(
            airtable_create=airtable_create,
            table_name=incidents_table_name,
            fields=clean_fields,
        )
        results.append(res)

        if res.get("ok") and res.get("record_id"):
            print("[INCIDENT_CREATE] success with", clean_fields)
            return {
                "ok": True,
                "record_id": res.get("record_id", ""),
                "fields": clean_fields,
                "attempts": results,
            }

    return {"ok": False, "record_id": "", "attempts": results}


def _best_effort_update_incident(
    airtable_update,
    incidents_table_name: str,
    incident_record_id: str,
    run_record_id: str,
    *,
    flow_id: str = "",
    root_event_id: str = "",
    parent_command_id: str = "",
    workspace_id: str = "",
) -> Dict[str, Any]:
    if not incident_record_id:
        return {"ok": False, "reason": "missing_incident_record_id"}

    now_ts = utc_now_iso()
    linked_run_ids = _safe_record_links(run_record_id)
    linked_command_ids = _safe_record_links(parent_command_id)

    attempts: List[Dict[str, Any]] = []

    rich = {
        "Status_select": "Escalated",
        "Last_Action": "internal_escalate",
        "Last_Seen_At": now_ts,
        "Updated_At": now_ts,
        "Run_Record_ID": run_record_id,
        "Command_ID": parent_command_id,
        "Flow_ID": flow_id,
        "Root_Event_ID": root_event_id,
        "Workspace_ID": workspace_id,
    }
    if linked_run_ids:
        rich["Linked_Run"] = linked_run_ids
    if linked_command_ids:
        rich["Linked_Command"] = linked_command_ids
    attempts.append(rich)

    attempts.extend(
        [
            {
                "Status_select": "Escalated",
                "Last_Action": "internal_escalate",
                "Last_Seen_At": now_ts,
                "Updated_At": now_ts,
                "Run_Record_ID": run_record_id,
                "Command_ID": parent_command_id,
                "Flow_ID": flow_id,
                "Root_Event_ID": root_event_id,
                "Workspace_ID": workspace_id,
            },
            {
                "Status_select": "Escalated",
                "Last_Action": "internal_escalate",
                "Last_Seen_At": now_ts,
                "Updated_At": now_ts,
                "Run_Record_ID": run_record_id,
            },
            {
                "Status_select": "Escalated",
                "Last_Action": "internal_escalate",
                "Last_Seen_At": now_ts,
            },
            {
                "Status_select": "Escalated",
            },
        ]
    )

    results: List[Dict[str, Any]] = []

    for fields in attempts:
        clean_fields = _clean_fields(fields)

        res = _try_update_one(
            airtable_update=airtable_update,
            table_name=incidents_table_name,
            record_id=incident_record_id,
            fields=clean_fields,
        )
        results.append(res)

        if res.get("ok"):
            print("[INCIDENT_ESCALATE] success with", clean_fields)
            return {"ok": True, "fields": clean_fields, "attempts": results}

    return {"ok": False, "attempts": results}


def capability_internal_escalate(
    req,
    run_record_id,
    *,
    airtable_update,
    logs_errors_table_name,
    incidents_table_name=None,
    airtable_create=None,
):
    payload = _extract_input(req)
    search_dicts = _extract_search_dicts(payload)

    depth = _to_int(
        _pick_value_from_dicts(search_dicts, "_depth", "depth"),
        0,
    )
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "internal_escalate",
            "status": "error",
            "error": "max_depth_reached",
            "flow_id": _pick_text_from_dicts(search_dicts, "flow_id", default=""),
            "root_event_id": _pick_text_from_dicts(
                search_dicts,
                "root_event_id",
                "event_id",
                "id",
                default="",
            ),
            "run_record_id": _to_str(
                run_record_id
                or _pick_text_from_dicts(search_dicts, "run_record_id", "linked_run", default="")
            ).strip(),
            "terminal": True,
            "spawn_summary": {
                "ok": True,
                "spawned": 0,
                "skipped": 0,
                "errors": [],
            },
        }

    flow_id = _pick_text_from_dicts(
        search_dicts,
        "flow_id",
        "flowid",
        "flowId",
        default="",
    )

    root_event_id = _pick_text_from_dicts(
        search_dicts,
        "root_event_id",
        "rooteventid",
        "rootEventId",
        "event_id",
        "eventid",
        "eventId",
        "id",
        default="",
    )

    source_event_id = _pick_text_from_dicts(
        search_dicts,
        "source_event_id",
        "sourceeventid",
        "sourceEventId",
        "event_id",
        "eventid",
        "eventId",
        default=root_event_id or flow_id,
    )

    incident_record_id = _pick_text_from_dicts(
        search_dicts,
        "incident_record_id",
        "incidentrecordid",
        "Incident_Record_ID",
        default="",
    )
    if not incident_record_id:
        for data in search_dicts:
            incident_record_id = _extract_record_id(data.get("incident_create_res"))
            if incident_record_id:
                break
    if not incident_record_id:
        for data in search_dicts:
            incident_record_id = _extract_record_id(data)
            if incident_record_id:
                break

    log_record_id = _pick_text_from_dicts(
        search_dicts,
        "log_record_id",
        "logrecordid",
        "Log_Record_ID",
        default="",
    )

    incoming_run_record_id = _pick_text_from_dicts(
        search_dicts,
        "run_record_id",
        "runrecordid",
        "runRecordId",
        default="",
    )
    incoming_linked_run = _pick_text_from_dicts(
        search_dicts,
        "linked_run",
        "linkedrun",
        "Linked_Run",
        default="",
    )

    effective_run_record_id = _to_str(
        run_record_id
        or incoming_run_record_id
        or incoming_linked_run
        or ""
    ).strip()

    parent_command_id = _pick_text_from_dicts(
        search_dicts,
        "parent_command_id",
        "parentcommandid",
        "parentCommandId",
        "command_id",
        "commandid",
        "commandId",
        default="",
    )

    reason = _pick_text_from_dicts(search_dicts, "reason", "retry_reason", default="internal_escalation")
    goal = _pick_text_from_dicts(search_dicts, "goal", default="escalation_send")
    severity_raw = _pick_text_from_dicts(search_dicts, "severity", default="high")

    http_status_value = _pick_value_from_dicts(search_dicts, "http_status", "status_code")
    http_status_int = _to_int(http_status_value, 0)
    http_status: Any = http_status_int if http_status_int > 0 else http_status_value

    failed_goal = _pick_text_from_dicts(search_dicts, "failed_goal", default="")
    failed_url = _pick_text_from_dicts(
        search_dicts,
        "failed_url",
        "target_url",
        "http_target",
        "url",
        default="",
    )
    failed_method = _pick_text_from_dicts(search_dicts, "failed_method", "method", default="GET").upper()
    sla_status_raw = _pick_text_from_dicts(search_dicts, "sla_status", default="open")

    final_failure = _to_bool(
        _pick_value_from_dicts(search_dicts, "final_failure", "finalfailure"),
        False,
    )
    if not final_failure:
        if http_status_int >= 500 or _pick_text_from_dicts(search_dicts, "category", default="") == "http_failure":
            final_failure = True

    category = _pick_text_from_dicts(search_dicts, "category", default="http_failure")
    incident_code = _pick_text_from_dicts(
        search_dicts,
        "incident_code",
        "incidentCode",
        "error_code",
        default="",
    )
    if not incident_code and http_status_int >= 400:
        incident_code = "http_status_error"

    error_message = _pick_text_from_dicts(
        search_dicts,
        "error_message",
        "incident_message",
        "error",
        default="",
    )
    incident_message = _pick_text_from_dicts(
        search_dicts,
        "incident_message",
        "error_message",
        "error",
        default=error_message,
    )

    retry_reason = _pick_text_from_dicts(search_dicts, "retry_reason", default=reason)
    retry_count = _to_int(_pick_value_from_dicts(search_dicts, "retry_count"), 0)
    retry_max = _to_int(_pick_value_from_dicts(search_dicts, "retry_max"), 0)

    original_capability = _pick_text_from_dicts(search_dicts, "original_capability", default="")
    failed_capability = _pick_text_from_dicts(search_dicts, "failed_capability", default=original_capability)
    source_capability = _pick_text_from_dicts(search_dicts, "source_capability", default=failed_capability or original_capability)

    workspace_id = _pick_text_from_dicts(
        search_dicts,
        "workspace_id",
        "Workspace_ID",
        "workspaceId",
        "workspace",
        default="production",
    ).strip()

    tenant_id = _pick_text_from_dicts(search_dicts, "tenant_id", "tenantId", default="")
    app_name = _pick_text_from_dicts(search_dicts, "app_name", "appName", default="")

    if not flow_id:
        if incident_record_id:
            flow_id = f"flow_{incident_record_id}"
        elif log_record_id:
            flow_id = f"flow_internal_escalate_{log_record_id}"

    if not root_event_id:
        root_event_id = flow_id

    status_select = _normalize_status_for_airtable("open")
    severity_select = _normalize_severity_for_airtable(severity_raw)
    sla_select = _normalize_sla_for_airtable(sla_status_raw)
    incident_title = _build_incident_title(
        category=category,
        failed_url=failed_url,
        flow_id=flow_id,
        root_event_id=root_event_id,
    )

    incident_create_res: Dict[str, Any] = {"ok": False, "skipped": True}
    incident_created_now = False

    try:
        if not incident_record_id and incidents_table_name and airtable_create:
            incident_create_res = _best_effort_create_incident(
                airtable_create=airtable_create,
                incidents_table_name=incidents_table_name,
                title=incident_title,
                status_select=status_select,
                severity=severity_select,
                sla_status=sla_select,
                category=category,
                reason=reason,
                flow_id=flow_id,
                root_event_id=root_event_id,
                workspace_id=workspace_id,
                run_record_id=effective_run_record_id,
                parent_command_id=parent_command_id,
                last_action="internal_escalate",
                failed_url=failed_url,
                http_status=http_status,
                incident_code=incident_code,
                final_failure=final_failure,
            )
            incident_record_id = _to_str(incident_create_res.get("record_id")).strip()
            incident_created_now = bool(incident_record_id)
        elif incident_record_id:
            incident_create_res = {
                "ok": True,
                "skipped": True,
                "reason": "incident_already_present",
                "record_id": incident_record_id,
            }
        elif not incidents_table_name:
            incident_create_res = {"ok": False, "reason": "missing_incidents_table_name"}
        else:
            incident_create_res = {"ok": False, "reason": "missing_airtable_create"}
    except Exception as e:
        incident_create_res = {"ok": False, "error": repr(e)}
        print("[INTERNAL_ESCALATE] incident create exception =", repr(e))

    incident_update_res: Dict[str, Any] = {"ok": False, "skipped": True}
    try:
        if incidents_table_name and incident_record_id:
            incident_update_res = _best_effort_update_incident(
                airtable_update=airtable_update,
                incidents_table_name=incidents_table_name,
                incident_record_id=incident_record_id,
                run_record_id=effective_run_record_id,
                flow_id=flow_id,
                root_event_id=root_event_id,
                parent_command_id=parent_command_id,
                workspace_id=workspace_id,
            )
        elif not incidents_table_name:
            incident_update_res = {
                "ok": False,
                "reason": "missing_incidents_table_name",
            }
        else:
            incident_update_res = {
                "ok": False,
                "reason": "missing_incident_record_id",
            }
    except Exception as e:
        incident_update_res = {"ok": False, "error": repr(e)}
        print("[INTERNAL_ESCALATE] incident update exception =", repr(e))

    escalation_result = {
        "ok": True,
        "capability": "internal_escalate",
        "status": "done",
        "mode": "internal_escalate",
        "delivered": True,
        "channel": "internal",
        "severity": severity_raw,
        "reason": reason,
        "goal": goal,
        "category": category,
        "incident_code": incident_code,
        "http_status": http_status,
        "status_code": http_status,
        "failed_goal": failed_goal,
        "failed_url": failed_url,
        "failed_method": failed_method,
        "error_message": error_message,
        "incident_message": incident_message,
        "retry_reason": retry_reason,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "sla_status": sla_status_raw,
        "final_failure": final_failure,
        "incident_record_id": incident_record_id,
        "incident_create_ok": bool(incident_record_id),
        "incident_created_now": incident_created_now,
        "log_record_id": log_record_id,
        "run_record_id": effective_run_record_id,
        "linked_run": effective_run_record_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "workspace_id": workspace_id,
        "tenant_id": tenant_id,
        "app_name": app_name,
        "parent_command_id": parent_command_id,
        "command_id": parent_command_id,
        "original_capability": original_capability,
        "failed_capability": failed_capability,
        "source_capability": source_capability,
        "ts": utc_now_iso(),
    }

    logs_update_res: Dict[str, Any] = {"ok": True, "skipped": True, "reason": "not_attempted"}
    try:
        if log_record_id:
            print("[INTERNAL_ESCALATE] log_record_id =", log_record_id)

            logs_update_res = _best_effort_update_logs_error(
                airtable_update=airtable_update,
                logs_errors_table_name=logs_errors_table_name,
                log_record_id=log_record_id,
                escalation_result=escalation_result,
            )

            if not logs_update_res.get("ok") and not logs_update_res.get("skipped"):
                print(
                    "[INTERNAL_ESCALATE] logs_errors update issue =",
                    _safe_json(logs_update_res),
                )
        else:
            logs_update_res = {
                "ok": True,
                "skipped": True,
                "reason": "missing_log_record_id",
            }
    except Exception as e:
        logs_update_res = {"ok": False, "skipped": False, "error": repr(e)}
        print("[INTERNAL_ESCALATE] logs_errors exception =", repr(e))

    next_input = {
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "event_id": source_event_id or root_event_id or flow_id,
        "incident_record_id": incident_record_id,
        "log_record_id": log_record_id,
        "step_index": _to_int(_pick_value_from_dicts(search_dicts, "step_index"), 0) + 1,
        "_depth": depth + 1,
        "goal": "escalation_sent",
        "workspace_id": workspace_id,
        "workspace": workspace_id,
        "tenant_id": tenant_id,
        "app_name": app_name,
        "parent_command_id": parent_command_id,
        "command_id": parent_command_id,
        "linked_command": parent_command_id,
        "severity": severity_raw,
        "category": category,
        "reason": reason,
        "incident_code": incident_code,
        "final_failure": final_failure,
        "failed_url": failed_url,
        "target_url": failed_url,
        "http_target": failed_url,
        "url": failed_url,
        "failed_method": failed_method,
        "method": failed_method,
        "http_status": http_status,
        "status_code": http_status,
        "error_message": error_message,
        "incident_message": incident_message,
        "retry_reason": retry_reason,
        "retry_count": retry_count,
        "retry_max": retry_max,
        "run_record_id": effective_run_record_id,
        "linked_run": effective_run_record_id,
        "decision_status": "Escalated",
        "decision_reason": "internal_escalation_sent",
        "next_action": "complete_flow_incident",
        "incident_create_ok": bool(incident_record_id),
        "incident_create_res": incident_create_res,
        "original_capability": original_capability,
        "failed_capability": failed_capability,
        "source_capability": source_capability,
    }

    return {
        "ok": True,
        "capability": "internal_escalate",
        "status": "done",
        "mode": "internal_escalate",
        "delivered": True,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "source_event_id": source_event_id,
        "incident_record_id": incident_record_id,
        "incident_create_ok": bool(incident_record_id),
        "incident_created_now": incident_created_now,
        "incident_create_res": incident_create_res,
        "log_record_id": log_record_id,
        "message": "internal_escalation_sent",
        "run_record_id": effective_run_record_id,
        "linked_run": effective_run_record_id,
        "command_id": parent_command_id,
        "decision_status": "Escalated",
        "decision_reason": "internal_escalation_sent",
        "next_action": "complete_flow_incident",
        "final_failure": final_failure,
        "logs_update_ok": bool(logs_update_res.get("ok")),
        "logs_update_skipped": bool(logs_update_res.get("skipped")),
        "logs_update_res": logs_update_res,
        "incident_update_ok": bool(incident_update_res.get("ok")),
        "incident_update_res": incident_update_res,
        "next_commands": [
            {
                "capability": "complete_flow_incident",
                "priority": 1,
                "input": next_input,
            }
        ],
        "terminal": False,
        "spawn_summary": {
            "ok": True,
            "spawned": 1,
            "skipped": 0,
            "errors": [],
        },
    }


def run(
    req,
    run_record_id,
    *,
    airtable_update,
    logs_errors_table_name,
    incidents_table_name=None,
    airtable_create=None,
):
    return capability_internal_escalate(
        req,
        run_record_id,
        airtable_update=airtable_update,
        logs_errors_table_name=logs_errors_table_name,
        incidents_table_name=incidents_table_name,
        airtable_create=airtable_create,
    )
