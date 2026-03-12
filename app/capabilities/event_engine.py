from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional


def _json_load_maybe(val: Any) -> Dict[str, Any]:
    if val is None:
        return {}
    if isinstance(val, dict):
        return val
    try:
        s = str(val).strip()
        if not s:
            return {}
        parsed = json.loads(s)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _is_truthy(v: Any) -> bool:
    if v is True:
        return True
    if v is None:
        return False
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


EVENT_TYPE_TO_CAPABILITY: Dict[str, str] = {
    "sla.breached": "escalation_engine",
    "command.stale_lock": "lock_recovery",
    "system.health.check": "health_tick",
    "http.call.requested": "http_exec",
    "manual.health.check": "health_tick",
}


def _event_target_capability(event_type: str) -> Optional[str]:
    return EVENT_TYPE_TO_CAPABILITY.get(str(event_type or "").strip())


def _event_command_idem(event_id: str, target_capability: str) -> str:
    return f"event:{event_id}:{target_capability}"


def _event_has_linked_command(fields: Dict[str, Any]) -> bool:
    linked = fields.get("Linked_Command")
    if isinstance(linked, list) and linked:
        return True
    if linked:
        return True

    command_record_id = str(fields.get("Command_Record_ID") or "").strip()
    if command_record_id:
        return True

    return _is_truthy(fields.get("Command_Created"))


def _event_payload(fields: Dict[str, Any]) -> Dict[str, Any]:
    return _json_load_maybe(fields.get("Payload_JSON"))


def _event_status(fields: Dict[str, Any]) -> str:
    return str(fields.get("Status_select", fields.get("Status", "")) or "").strip()


def _build_command_fields_candidates(
    capability: str,
    idem_key: str,
    input_obj: Dict[str, Any],
    run_record_id: str,
    event_id: str,
    event_type: str,
    utc_now_iso,
) -> List[Dict[str, Any]]:
    input_json = json.dumps(input_obj or {}, ensure_ascii=False)
    now = utc_now_iso()

    return [
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Idempotency_Key": idem_key,
            "Input_JSON": input_json,
            "Linked_Run": [run_record_id],
            "Source_Event_ID": event_id,
            "Event_Type": event_type,
            "Scheduled_At": now,
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Idempotency_Key": idem_key,
            "Input_JSON": input_json,
            "Linked_Run": [run_record_id],
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Idempotency_Key": idem_key,
            "Input_JSON": input_json,
        },
        {
            "Capability": capability,
            "Status_select": "Queued",
            "Idempotency_Key": idem_key,
        },
    ]


def _create_command_from_event(
    capability: str,
    command_input: Dict[str, Any],
    *,
    idempotency_key: Optional[str] = None,
    run_record_id: Optional[str] = None,
    event_id: Optional[str] = None,
    event_type: Optional[str] = None,
    find_command_by_idem,
    _airtable_create_best_effort,
    commands_table_name: str,
    utc_now_iso,
) -> Dict[str, Any]:
    capability = str(capability or "").strip()
    if not capability:
        raise ValueError("Missing capability")

    input_obj = command_input if isinstance(command_input, dict) else {}
    idem = str(idempotency_key or "").strip()

    if not idem and event_id:
        idem = _event_command_idem(event_id, capability)
    if not idem:
        idem = f"cmd:{capability}:{uuid.uuid4().hex}"

    existing = find_command_by_idem(idem)
    if existing:
        return existing

    candidates = _build_command_fields_candidates(
        capability=capability,
        idem_key=idem,
        input_obj=input_obj,
        run_record_id=(run_record_id or ""),
        event_id=(event_id or ""),
        event_type=(event_type or ""),
        utc_now_iso=utc_now_iso,
    )

    create_res = _airtable_create_best_effort(commands_table_name, candidates)
    if not create_res.get("ok"):
        raise ValueError(f"create_command_failed: {create_res.get('error')}")

    record_id = create_res.get("record_id")
    return {
        "id": record_id,
        "fields": {
            "Capability": capability,
            "Idempotency_Key": idem,
        },
    }


def _mark_event_processed_best_effort(
    event_id: str,
    command_record_id: str,
    capability: str,
    *,
    _airtable_update_best_effort,
    events_table_name: str,
    utc_now_iso,
) -> Dict[str, Any]:
    now = utc_now_iso()
    return _airtable_update_best_effort(
        events_table_name,
        event_id,
        [
            {
                "Status": "Processed",
                "Status_select": "Processed",
                "Command_Created": True,
                "Linked_Command": [command_record_id],
                "Command_Record_ID": command_record_id,
                "Processed_At": now,
                "Mapped_Capability": capability,
                "Error_Message": "",
            },
            {
                "Status_select": "Processed",
                "Command_Created": True,
                "Command_Record_ID": command_record_id,
                "Processed_At": now,
                "Mapped_Capability": capability,
            },
            {
                "Command_Created": True,
                "Command_Record_ID": command_record_id,
            },
        ],
    )


def _mark_event_ignored_best_effort(
    event_id: str,
    reason: str,
    event_type: str,
    *,
    _airtable_update_best_effort,
    events_table_name: str,
    utc_now_iso,
) -> Dict[str, Any]:
    now = utc_now_iso()
    payload = json.dumps({"reason": reason, "event_type": event_type}, ensure_ascii=False)
    return _airtable_update_best_effort(
        events_table_name,
        event_id,
        [
            {
                "Status": "Ignored",
                "Status_select": "Ignored",
                "Command_Created": False,
                "Command_Record_ID": "",
                "Processed_At": now,
                "Error_Message": reason,
                "Result_JSON": payload,
            },
            {
                "Status_select": "Ignored",
                "Command_Created": False,
                "Processed_At": now,
                "Error_Message": reason,
            },
        ],
    )


def _mark_event_error_best_effort(
    event_id: str,
    error_message: str,
    *,
    _airtable_update_best_effort,
    events_table_name: str,
    utc_now_iso,
) -> Dict[str, Any]:
    now = utc_now_iso()
    payload = json.dumps({"error": error_message}, ensure_ascii=False)
    return _airtable_update_best_effort(
        events_table_name,
        event_id,
        [
            {
                "Status": "Error",
                "Status_select": "Error",
                "Command_Created": False,
                "Command_Record_ID": "",
                "Processed_At": now,
                "Error_Message": error_message,
                "Result_JSON": payload,
            },
            {
                "Status_select": "Error",
                "Command_Created": False,
                "Processed_At": now,
                "Error_Message": error_message,
            },
        ],
    )


def run(
    req,
    run_record_id: str,
    *,
    airtable_list_view,
    find_command_by_idem,
    _airtable_create_best_effort,
    _airtable_update_best_effort,
    events_table_name: str,
    events_view_name: str,
    commands_table_name: str,
    utc_now_iso,
    safe_limit,
) -> Dict[str, Any]:
    payload = req.input or {}
    limit = safe_limit(int(payload.get("limit", 10) or 10), default=10, minimum=1, maximum=50)
    view_name = str(payload.get("view") or events_view_name or "Queue").strip()

    try:
        records = airtable_list_view(events_table_name, view_name, max_records=limit)
        mode = "view"
    except Exception:
        records = airtable_list_view(events_table_name, events_view_name or "Queue", max_records=limit)
        mode = "fallback_view"

    scanned = 0
    created = 0
    ignored = 0
    errors_count = 0
    processed_ids: List[str] = []
    errors: List[str] = []

    for record in records:
        scanned += 1
        event_id = record.get("id")
        fields = record.get("fields", {}) or {}
        if not event_id:
            continue

        status = _event_status(fields)
        if status not in ("New", "Queued", ""):
            continue

        if _event_has_linked_command(fields):
            ignored += 1
            continue

        event_type = str(fields.get("Event_Type") or "").strip()
        mapped_capability = str(fields.get("Mapped_Capability") or "").strip()
        command_input = _json_load_maybe(fields.get("Command_Input_JSON"))
        idem = str(fields.get("Idempotency_Key") or "").strip()

        target_capability = mapped_capability or _event_target_capability(event_type)
        if not target_capability:
            _mark_event_ignored_best_effort(
                event_id,
                "no_capability_mapping",
                event_type,
                _airtable_update_best_effort=_airtable_update_best_effort,
                events_table_name=events_table_name,
                utc_now_iso=utc_now_iso,
            )
            ignored += 1
            continue

        try:
            cmd = _create_command_from_event(
                capability=target_capability,
                command_input=command_input,
                idempotency_key=idem,
                run_record_id=run_record_id,
                event_id=event_id,
                event_type=event_type,
                find_command_by_idem=find_command_by_idem,
                _airtable_create_best_effort=_airtable_create_best_effort,
                commands_table_name=commands_table_name,
                utc_now_iso=utc_now_iso,
            )
            command_record_id = str(cmd.get("id") or "").strip()

            _mark_event_processed_best_effort(
                event_id,
                command_record_id,
                target_capability,
                _airtable_update_best_effort=_airtable_update_best_effort,
                events_table_name=events_table_name,
                utc_now_iso=utc_now_iso,
            )

            created += 1
            processed_ids.append(event_id)

        except Exception as exc:
            errors_count += 1
            errors.append(f"{event_id}: {repr(exc)}")
            _mark_event_error_best_effort(
                event_id,
                repr(exc),
                _airtable_update_best_effort=_airtable_update_best_effort,
                events_table_name=events_table_name,
                utc_now_iso=utc_now_iso,
            )

    return {
        "ok": True,
        "mode": mode,
        "scanned": scanned,
        "created": created,
        "ignored": ignored,
        "errors_count": errors_count,
        "processed_event_ids": processed_ids,
        "errors": errors[:10],
        "run_record_id": run_record_id,
    }
