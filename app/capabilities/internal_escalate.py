import json
from datetime import datetime, timezone


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


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

    update_fields = {
        "Escalation_Sent": True,
        "Escalation_Queued": False,
        "Escalation_Queued_At": utc_now_iso(),
        "Statut_incident": "Escaladé",
        "Error_Message": reason,
        "Payload_Redacted": json.dumps(
            {
                "severity": severity,
                "goal": goal,
                "http_status": http_status,
                "failed_goal": failed_goal,
                "failed_url": failed_url,
                "sla_status": sla_status,
            },
            ensure_ascii=False,
        ),
        "Result_JSON": json.dumps(escalation_result, ensure_ascii=False),
        "Linked_Run": [run_record_id],
    }

    try:
        print("[INTERNAL_ESCALATE] table =", logs_errors_table_name)
        print("[INTERNAL_ESCALATE] log_record_id =", log_record_id)
        print("[INTERNAL_ESCALATE] run_record_id =", run_record_id)
        print("[INTERNAL_ESCALATE] flow_id =", flow_id)
        print("[INTERNAL_ESCALATE] root_event_id =", root_event_id)
        print(
            "[INTERNAL_ESCALATE] update_fields =",
            json.dumps(update_fields, ensure_ascii=False),
        )

        airtable_update(
            logs_errors_table_name,
            log_record_id,
            update_fields,
        )
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
