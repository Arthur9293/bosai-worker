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
    reason: str,
    severity: str,
    goal: str,
    http_status: Any,
    failed_goal: str,
    failed_url: str,
    sla_status: str,
    run_record_id: str,
) -> Dict[str, Any]:
    result_json = _safe_json(escalation_result)

    attempts: List[Dict[str, Any]] = [
        {
            "Result_JSON": result_json,
        }
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

    root_event_id = str(
        payload.get("root_event_id")
        or payload.get("event_id")
        or payload.get("id")
        or ""
    ).strip()

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

    workspace_id = str(
        payload.get("workspace_id")
        or payload.get("Workspace_ID")
        or payload.get("workspaceId")
        or ""
    ).strip()

    if not workspace_id:
        workspace_id = "production"

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
        "log_record_id": log_record_id,
        "run_record_id": run_record_id,
        "flow_id": flow_id,
        "root_event_id": root_event_id,
        "workspace_id": workspace_id,
        "ts": utc_now_iso(),
    }

    try:
        print("[INTERNAL_ESCALATE] table =", logs_errors_table_name)
        print("[INTERNAL_ESCALATE] log_record_id =", log_record_id)
        print("[INTERNAL_ESCALATE] run_record_id =", run_record_id)
        print("[INTERNAL_ESCALATE] flow_id =", flow_id)
        print("[INTERNAL_ESCALATE] root_event_id =", root_event_id)
        print("[INTERNAL_ESCALATE] workspace_id =", workspace_id)

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

        print("[INTERNAL_ESCALATE] update_res =", _safe_json(update_res))

        if isinstance(update_res, dict):
            for idx, attempt in enumerate(update_res.get("attempts", []), start=1):
                print(f"[INTERNAL_ESCALATE] attempt_{idx} =", _safe_json(attempt))

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
                    "workspace_id": workspace_id,
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
