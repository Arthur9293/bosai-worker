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
    """
    Reads Logs_Erreurs (Active) and creates Commands (Queued) for Breached incidents.
    SAFE / best-effort:
      - If formulas fail or fields are missing, it falls back and skips safely.
      - If already Escalation_Queued, it skips.
      - Writes back flags best-effort.
    """

    inp = req.input or {}

    # limit
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

    # command config
    cmd_cap = (os.getenv("ESCALATION_COMMAND_CAPABILITY", "http_exec") or "http_exec").strip()
    http_target = (os.getenv("ESCALATION_HTTP_TARGET", "") or "").strip()
    http_method = (os.getenv("ESCALATION_HTTP_METHOD", "POST") or "POST").strip().upper()

    tool_key = (os.getenv("ESCALATION_TOOL_KEY", "") or "").strip()
    tool_mode = (os.getenv("ESCALATION_TOOL_MODE", "") or "").strip()
    tool_intent = (os.getenv("ESCALATION_TOOL_INTENT", "") or "").strip()

    view_name = (req.view or logs_errors_view_name or "Active").strip()

    # Prefer formula
    # NOTE: Escalation_Queued checkbox may not exist; formula can error → fallback.
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

        # filter in-code (fallback-safe)
        if only_breached:
            if str(fields.get("SLA_Status", "")).strip() != "Breached":
                skipped += 1
                continue

        if _safe_bool(fields.get("Escalation_Queued")):
            skipped += 1
            continue

        # Guard: if no http_target configured, we can still mark queued,
        # but better to create a command ONLY if target exists.
        if not http_target:
            failed += 1
            errors.append(f"{log_id}: missing ESCALATION_HTTP_TARGET (no command created)")
            continue

        # Build command input for http_exec
        payload = {
            "source": "bosai-worker",
            "type": "incident_escalation",
            "log_record_id": log_id,
            "run_record_id": run_record_id,
            "fields": fields,  # keep raw for Make / downstream
            "ts": utc_now_iso(),
        }

        cmd_input: Dict[str, Any] = {
            "http_target": http_target,
            "method": http_method,
            "json": payload,
        }

        # optional ToolCatalog governance fields
        if tool_key:
            cmd_input["Tool_Key"] = tool_key
        if tool_mode:
            cmd_input["Tool_Mode"] = tool_mode
        if tool_intent:
            cmd_input["Tool_Intent"] = tool_intent

        idem = f"esc:{log_id}:{run_record_id}"

        # Create command record
        try:
            cmd_fields: Dict[str, Any] = {
                "Capability": cmd_cap,
                "Status_select": "Queued",
                "Idempotency_Key": idem,
                "Command_JSON": _json_dumps(cmd_input),
                "Linked_Run": [run_record_id],
            }
            cmd_id = airtable_create(commands_table_name, cmd_fields)

            # Update log record best-effort
            try:
                update_fields: Dict[str, Any] = {
                    "Escalation_Queued": True,
                    "Escalation_Queued_At": utc_now_iso(),
                    "Linked_Run": [run_record_id],
                }
                # optional link
                update_fields["Escalation_Command"] = [cmd_id]
                airtable_update(logs_errors_table_name, log_id, update_fields)
            except Exception as e:
                # still consider queued since command exists
                try:
                    airtable_update(logs_errors_table_name, log_id, {"Escalation_Last_Error": repr(e)})
                except Exception:
                    pass

            queued += 1

        except Exception as e:
            failed += 1
            errors.append(f"{log_id}: {repr(e)}")
            try:
                airtable_update(logs_errors_table_name, log_id, {"Escalation_Last_Error": repr(e)})
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
