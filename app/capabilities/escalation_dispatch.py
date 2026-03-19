# app/capabilities/escalation_dispatch.py
import os
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False)


def _safe_bool(v: Any) -> bool:
    if v is True:
        return True
    if v in (1, "1", "true", "True", "yes", "Yes"):
        return True
    return False


def capability_escalation_dispatch(
    req,
    run_record_id: str,
    *,
    airtable_list_filtered,
    airtable_list_view,
    airtable_create,
    airtable_update,
    http_timeout_seconds: float,
    logs_errors_table_name: str,
    logs_errors_view_name: str,
    commands_table_name: str,
) -> Dict[str, Any]:

    inp = req.input or {}

    env_limit = int((os.getenv("ESCALATION_DISPATCH_LIMIT", "50") or "50").strip())
    limit = int(inp.get("limit", env_limit) or env_limit)
    if limit <= 0:
        limit = env_limit
    if limit > 200:
        limit = 200

    only_breached = inp.get("only_breached")
    if only_breached is None:
        only_breached = _safe_bool(os.getenv("ESCALATION_ONLY_BREACHED", "1"))
    else:
        only_breached = _safe_bool(only_breached)

    cmd_cap = (os.getenv("ESCALATION_COMMAND_CAPABILITY", "internal_escalate") or "internal_escalate").strip()

    http_target = (os.getenv("ESCALATION_HTTP_TARGET", "") or "").strip()
    http_method = (os.getenv("ESCALATION_HTTP_METHOD", "POST") or "POST").strip().upper()

    view_name = (req.view or logs_errors_view_name or "Active").strip()

    if only_breached:
        formula = "AND({SLA_Status}='Breached',OR({Escalation_Queued}=0,{Escalation_Queued}=BLANK()))"
    else:
        formula = "OR({Escalation_Queued}=0,{Escalation_Queued}=BLANK())"

    mode = "formula"
    try:
        recs = airtable_list_filtered(
            logs_errors_table_name,
            formula=formula,
            view_name=view_name,
            sort=[{"field": "SLA_Remaining_Minutes", "direction": "asc"}],
            max_records=limit,
        )
    except Exception:
        mode = "view_fallback"
        recs = airtable_list_view(logs_errors_table_name, view_name, max_records=limit)

    scanned = 0
    queued = 0
    skipped = 0
    failed = 0
    errors: List[str] = []

    for r in recs:
        scanned += 1
        log_id = r.get("id")
        fields = (r.get("fields", {}) or {})

        if not log_id:
            skipped += 1
            continue

        if only_breached and str(fields.get("SLA_Status", "")).strip() != "Breached":
            skipped += 1
            continue

        if _safe_bool(fields.get("Escalation_Queued")):
            skipped += 1
            continue

        flow_id = str(
            fields.get("Flow_ID")
            or fields.get("flow_id")
            or fields.get("Root_Event_ID")
            or fields.get("root_event_id")
            or f"esc-flow:{log_id}"
        ).strip()

        root_event_id = str(
            fields.get("Root_Event_ID")
            or fields.get("root_event_id")
            or flow_id
        ).strip()

        payload = {
            "source": "bosai-worker",
            "type": "incident_escalation",
            "log_record_id": log_id,
            "run_record_id": run_record_id,
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "fields": fields,
            "ts": utc_now_iso(),
        }

        cmd_input: Dict[str, Any] = {
            "flow_id": flow_id,
            "root_event_id": root_event_id,
            "step_index": 1,
            "goal": "escalation_send",
            "reason": "sla_breached_internal_escalation",
            "severity": "critical",
            "log_record_id": log_id,
            "incident_record_id": log_id,
            "http_status": fields.get("HTTP_Status") or 500,
            "failed_goal": str(fields.get("Name") or "incident_escalation").strip(),
            "failed_url": str(fields.get("Endpoint_URL") or http_target or "").strip(),
            "sla_status": str(fields.get("SLA_Status") or "").strip(),
            "method": http_method,
            "payload": payload,
        }

        idem = f"esc:{log_id}:{run_record_id}"

        try:
            cmd_fields: Dict[str, Any] = {
                "Capability": cmd_cap,
                "Status_select": "Queued",
                "Idempotency_Key": idem,
                "Command_JSON": _json_dumps(cmd_input),
                "Input_JSON": _json_dumps(cmd_input),
                "Linked_Run": [run_record_id],
                "Flow_ID": flow_id,
                "Root_Event_ID": root_event_id,
                "Workspace_ID": str(fields.get("Workspace_ID") or "production").strip() or "production",
            }

            cmd_id = airtable_create(commands_table_name, cmd_fields)

            # 🔥 PATCH PRO
            try:
                queued_at = utc_now_iso()

                update_candidates: List[Dict[str, Any]] = [
                    {
                        "Escalation_Queued": True,
                        "Escalation_Queued_At": queued_at,
                        "Escalation_Command_ID": cmd_id,
                        "Linked_Run": [run_record_id],
                        "Statut_incident": "Escalated",
                        "Escalation_Sent": True,
                    },
                    {
                        "Escalation_Queued": True,
                        "Escalation_Queued_At": queued_at,
                        "Escalation_Command_ID": cmd_id,
                        "Linked_Run": [run_record_id],
                        "Escalation_Sent": True,
                    },
                    {
                        "Escalation_Queued": True,
                        "Escalation_Queued_At": queued_at,
                        "Escalation_Command_ID": cmd_id,
                        "Linked_Run": [run_record_id],
                    },
                    {
                        "Escalation_Queued": True,
                        "Escalation_Queued_At": queued_at,
                        "Escalation_Command_ID": cmd_id,
                    },
                    {
                        "Escalation_Queued": True,
                    },
                ]

                updated = False
                last_error: Optional[str] = None

                for candidate in update_candidates:
                    try:
                        airtable_update(logs_errors_table_name, log_id, candidate)
                        updated = True
                        break
                    except Exception as e:
                        last_error = repr(e)

                if not updated and last_error:
                    try:
                        airtable_update(
                            logs_errors_table_name,
                            log_id,
                            {"Escalation_Last_Error": last_error},
                        )
                    except Exception:
                        pass

            except Exception as e:
                try:
                    airtable_update(
                        logs_errors_table_name,
                        log_id,
                        {"Escalation_Last_Error": repr(e)},
                    )
                except Exception:
                    pass

            queued += 1

        except Exception as e:
            failed += 1
            errors.append(f"{log_id}: {repr(e)}")
            try:
                airtable_update(
                    logs_errors_table_name,
                    log_id,
                    {"Escalation_Last_Error": repr(e)},
                )
            except Exception:
                pass

    return {
        "ok": True,
        "mode": mode,
        "view": view_name,
        "scanned": scanned,
        "queued": queued,
        "skipped": skipped,
        "failed": failed,
        "errors_count": len(errors),
        "errors": errors[:10],
        "run_record_id": run_record_id,
        "ts": utc_now_iso(),
    }


def run(
    req,
    run_record_id: str,
    *,
    airtable_list_filtered,
    airtable_list_view,
    airtable_create,
    airtable_update,
    http_timeout_seconds: float,
    logs_errors_table_name: str,
    logs_errors_view_name: str,
    commands_table_name: str,
) -> Dict[str, Any]:
    return capability_escalation_dispatch(
        req,
        run_record_id,
        airtable_list_filtered=airtable_list_filtered,
        airtable_list_view=airtable_list_view,
        airtable_create=airtable_create,
        airtable_update=airtable_update,
        http_timeout_seconds=http_timeout_seconds,
        logs_errors_table_name=logs_errors_table_name,
        logs_errors_view_name=logs_errors_view_name,
        commands_table_name=commands_table_name,
    )
