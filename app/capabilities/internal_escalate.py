import json
from datetime import datetime, timezone
from typing import Any, Dict, List


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return "{}"


def _try_update_one(
    airtable_update,
    table_name: str,
    record_id: str,
    fields: Dict[str, Any],
) -> Dict[str, Any]:
    try:
        airtable_update(table_name, record_id, fields)
        return {"ok": True, "fields": fields}
    except Exception as e:
        return {"ok": False, "fields": fields, "error": repr(e)}


def _best_effort_update_logs_error(
    airtable_update,
    logs_errors_table_name: str,
    log_record_id: str,
    escalation_result: Dict[str, Any],
    reason: str,
    severity: str,
    goal: str,
    http_status: Any,
    failed_goal: str,
    failed_url: str,
    sla_status: str,
    run_record_id: str,
) -> Dict[str, Any]:
    ts_now = utc_now_iso()

    payload_redacted = _safe_json(
        {
            "severity": severity,
            "goal": goal,
            "http_status": http_status,
            "failed_goal": failed_goal,
            "failed_url": failed_url,
            "sla_status": sla_status,
        }
    )

    result_json = _safe_json(escalation_result)

    attempts: List[Dict[str, Any]] = [
        # Bloc moderne / probable
        {
            "SLA_Status": "Escalated",
            "Last_SLA_Check": ts_now,
            "Linked_Run": run_record_id,
            "Result_JSON": result_json,
        },
        # Variante FR incident
        {
            "Statut_incident": "Escaladé",
            "Linked_Run": run_record_id,
            "Result_JSON": result_json,
        },
        # Variante avec message
        {
            "Statut_incident": "Escaladé",
            "Error_Message": reason,
            "Linked_Run": run_record_id,
            "Result_JSON": result_json,
        },
        # Variante payload brut réduit
        {
            "Payload_Redacted": payload_redacted,
            "Result_JSON": result_json,
            "Linked_Run": run_record_id,
        },
        # Variante checkbox historique si elle existe
        {
            "Escalation_Sent": True,
            "Result_JSON": result_json,
            "Linked_Run": run_record_id,
        },
        {
            "Escalation_Sent": True,
            "Escalation_Queued": False,
            "Escalation_Queued_At": ts_now,
            "Result_JSON": result_json,
            "Linked_Run": run_record_id,
        },
        # Update minimal de secours
        {
            "Result_JSON": result_json,
        },
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


def capability_internal_escalate(
    req,
    run_record_id,
    *,
    airtable_update,
    logs_errors_table_name,
):
    payload = req.input or {}

    flow_id = str(payload.get("flow_id") or "").strip()
    root_event_id = str(payload.get("root_event_id") or flow_id).strip()

    log_record_id = str(
        payload.get("log_record_id")
        or payload.get("run_record_id")
        or payload.get("incident_record_id")
        or run_record_id
        or ""
    ).strip()

    reason = str(payload.get("reason") or "internal_escalation").strip()
    goal = str(payload.get("goal") or "escalation_send").strip()
    severity = str(payload.get("severity") or "critical").strip()
    http_status = payload.get("http_status")
    failed_goal = str(payload.get("failed_goal") or "").strip()
    failed_url = str(payload.get("failed_url") or "").strip()
    sla_status = str(payload.get("sla_status") or "").strip()

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
        "log_record_id": log_record_id,
        "run_record_id": run_record_id,
        "ts": utc_now_iso(),
    }

    try:
        print("[INTERNAL_ESCALATE] table =", logs_errors_table_name)
        print("[INTERNAL_ESCALATE] log_record_id =", log_record_id)
        print("[INTERNAL_ESCALATE] run_record_id =", run_record_id)
        print("[INTERNAL_ESCALATE] flow_id =", flow_id)
        print("[INTERNAL_ESCALATE] root_event_id =", root_event_id)

        update_res = _best_effort_update_logs_error(
            airtable_update=airtable_update,
            logs_errors_table_name=logs_errors_table_name,
            log_record_id=log_record_id,
            escalation_result=escalation_result,
            reason=reason,
            severity=severity,
            goal=goal,
            http_status=http_status,
            failed_goal=failed_goal,
            failed_url=failed_url,
            sla_status=sla_status,
            run_record_id=run_record_id,
        )

        print(
            "[INTERNAL_ESCALATE] update_res =",
            _safe_json(update_res),
        )

        if not update_res.get("ok"):
            return {
                "ok": False,
                "error": "airtable_update_failed_no_matching_fields",
                "flow_id": flow_id,
                "root_event_id": root_event_id,
                "log_record_id": log_record_id,
                "run_record_id": run_record_id,
                "update_res": update_res,
                "terminal": True,
            }

    except Exception as e:
        return {
            "ok": False,
            "error": "airtable_update_failed:" + repr(e),
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "log_record_id": log_record_id,
            "run_record_id": run_record_id,
            "terminal": True,
        }

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
                "capability": "complete_flow_demo",
                "priority": 1,
                "input": {
                    "flow_id": flow_id,
                    "root_event_id": root_event_id,
                    "step_index": int(payload.get("step_index") or 0) + 1,
                    "goal": "escalation_sent",
                    "workspace_id": str(payload.get("workspace_id") or "").strip(),
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
):
    return capability_internal_escalate(
        req,
        run_record_id,
        airtable_update=airtable_update,
        logs_errors_table_name=logs_errors_table_name,
    )
