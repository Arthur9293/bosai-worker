import json
from datetime import datetime, timezone
from typing import Any, Dict, List


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
        airtable_update(table_name, record_id, fields)
        return {"ok": True, "fields": fields}
    except Exception as e:
        print("[TRY_UPDATE_ONE] error =", repr(e))
        return {"ok": False, "fields": fields, "error": repr(e)}


def _best_effort_update_logs_error(
    airtable_update,
    logs_errors_table_name: str,
    log_record_id: str,
    escalation_result: Dict[str, Any],
) -> Dict[str, Any]:
    result_json = _safe_json(escalation_result)

    attempts: List[Dict[str, Any]] = [
        {"Result_JSON": result_json}
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
                "chosen_fields": fields,
                "attempts": results,
            }

    return {
        "ok": False,
        "chosen_fields": {},
        "attempts": results,
    }


def _best_effort_update_incident(
    airtable_update,
    incidents_table_name: str,
    incident_record_id: str,
    run_record_id: str,
) -> None:
    """
    SAFE PATCH:
    - ne casse jamais
    - met Status_select = Escalated
    - best effort uniquement
    """
    if not incident_record_id:
        return

    candidates = [
        {
            "Status_select": "Escalated",
            "Last_Action": "internal_escalate",
            "Last_Seen_At": utc_now_iso(),
            "Run_Record_ID": run_record_id,
        },
        {
            "Status_select": "Escalated",
        },
        {
            "Last_Seen_At": utc_now_iso(),
        },
    ]

    for fields in candidates:
        try:
            airtable_update(incidents_table_name, incident_record_id, fields)
            print("[INCIDENT_ESCALATE] success")
            return
        except Exception as e:
            print("[INCIDENT_ESCALATE] failed attempt =", repr(e))
            continue


def capability_internal_escalate(
    req,
    run_record_id,
    *,
    airtable_update,
    logs_errors_table_name,
    incidents_table_name=None,
):
    if req is not None and hasattr(req, "input"):
        payload = getattr(req, "input", {}) or {}
    elif isinstance(req, dict):
        payload = req
    else:
        payload = {}

    flow_id = _to_str(payload.get("flow_id")).strip()

    root_event_id = _to_str(
        payload.get("root_event_id")
        or payload.get("event_id")
        or payload.get("id")
    ).strip()

    log_record_id = _to_str(
        payload.get("log_record_id")
        or payload.get("run_record_id")
        or payload.get("incident_record_id")
        or run_record_id
    ).strip()

    incident_record_id = _to_str(
        payload.get("incident_record_id")
        or payload.get("incidentrecordid")
        or payload.get("Incident_Record_ID")
    ).strip()

    reason = _to_str(payload.get("reason"), "internal_escalation")
    goal = _to_str(payload.get("goal"), "escalation_send")
    severity = _to_str(payload.get("severity"), "critical")
    http_status = payload.get("http_status")
    failed_goal = _to_str(payload.get("failed_goal"))
    failed_url = _to_str(
        payload.get("failed_url")
        or payload.get("target_url")
    )
    sla_status = _to_str(payload.get("sla_status"))
    final_failure = payload.get("final_failure")
    parent_command_id = _to_str(payload.get("parent_command_id")).strip()

    workspace_id = _to_str(
        payload.get("workspace_id")
        or payload.get("Workspace_ID")
        or payload.get("workspaceId")
        or "production"
    )

    if not flow_id and log_record_id:
        flow_id = f"flow_internal_escalate_{log_record_id}"

    if not root_event_id:
        root_event_id = flow_id

    if not log_record_id:
        return {
            "ok": False,
            "error": "missing_log_record_id",
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "run_record_id": run_record_id,
            "terminal": True,
        }

    escalation_result = {
        "ok": True,
        "mode": "internal_escalate",
        "delivered": True,
        "channel": "internal",
        "severity": severity,
        "reason": reason,
        "goal": goal,
        "http_status": http_status,
        "failed_goal": failed_goal,
        "failed_url": failed_url,
        "sla_status": sla_status,
        "final_failure": final_failure,
        "incident_record_id": incident_record_id,
        "log_record_id": log_record_id,
        "run_record_id": run_record_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "ts": utc_now_iso(),
    }

    try:
        print("[INTERNAL_ESCALATE] log_record_id =", log_record_id)

        update_res = _best_effort_update_logs_error(
            airtable_update=airtable_update,
            logs_errors_table_name=logs_errors_table_name,
            log_record_id=log_record_id,
            escalation_result=escalation_result,
        )

        if not update_res.get("ok"):
            return {
                "ok": False,
                "error": "airtable_update_failed_no_matching_fields",
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "terminal": True,
            }

    except Exception as e:
        return {
            "ok": False,
            "error": "airtable_update_failed:" + repr(e),
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "terminal": True,
        }

    try:
        if incidents_table_name:
            _best_effort_update_incident(
                airtable_update=airtable_update,
                incidents_table_name=incidents_table_name,
                incident_record_id=incident_record_id,
                run_record_id=run_record_id,
            )
    except Exception:
        pass

    return {
        "ok": True,
        "mode": "internal_escalate",
        "delivered": True,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "log_record_id": log_record_id,
        "message": "internal_escalation_sent",
        "run_record_id": run_record_id,
        "next_commands": [
            {
                "capability": "complete_flow_incident",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "incident_record_id": incident_record_id,
                    "step_index": int(payload.get("step_index") or 0) + 1,
                    "goal": "escalation_sent",
                    "workspace_id": workspace_id,
                    "parent_command_id": parent_command_id,
                    "severity": severity,
                    "final_failure": final_failure,
                    "failed_url": failed_url,
                    "http_status": http_status,
                },
            }
        ],
        "terminal": False,
    }


def run(
    req,
    run_record_id,
    *,
    airtable_update,
    logs_errors_table_name,
    incidents_table_name=None,
):
    return capability_internal_escalate(
        req,
        run_record_id,
        airtable_update=airtable_update,
        logs_errors_table_name=logs_errors_table_name,
        incidents_table_name=incidents_table_name,
    )
