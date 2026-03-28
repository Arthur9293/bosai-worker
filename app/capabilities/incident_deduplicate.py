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
        "flow_id": _to_str(payload.get("flow_id")),
        "root_event_id": _to_str(payload.get("root_event_id") or payload.get("event_id")),
        "parent_command_id": _to_str(payload.get("parent_command_id")),
        "step_index": _to_int(payload.get("step_index"), 0),
        "depth": _to_int(payload.get("_depth") or payload.get("depth"), 0),
        "workspace_id": _to_str(payload.get("workspace_id") or "production"),
        "run_record_id": _to_str(payload.get("run_record_id")),
    }


def _build_incident_key(data: Dict[str, Any], meta: Dict[str, Any]) -> str:
    return "|".join(
        [
            _to_str(meta.get("flow_id")),
            _to_str(meta.get("root_event_id")),
            _to_str(data.get("original_capability") or data.get("failed_capability")),
            _to_str(data.get("failed_method") or data.get("method")).upper(),
            _to_str(data.get("failed_url") or data.get("target_url")),
            _to_str(data.get("http_status")),
            _to_str(data.get("incident_code")).lower(),
            _to_str(data.get("reason")),
            "final" if _to_bool(data.get("final_failure")) else "not_final",
        ]
    )


def _find_existing_incident(
    incidents_table_name: str,
    incident_key: str,
    airtable_list_filtered,
) -> Optional[Dict[str, Any]]:
    try:
        recs = airtable_list_filtered(
            incidents_table_name,
            formula=f"{{Incident_Key}}='{incident_key}'",
            max_records=1,
        )
        if isinstance(recs, list) and recs:
            return recs[0]
    except Exception:
        pass

    return None


def run(
    req: Optional[Any] = None,
    run_record_id: str = "",
    *,
    airtable_list_filtered,
    airtable_update,
    incidents_table_name: str,
    **kwargs: Any,
) -> Dict[str, Any]:

    payload = getattr(req, "input", {}) if hasattr(req, "input") else req or {}
    data = _extract_input(payload)
    meta = _extract_meta(data)

    depth = _to_int(meta.get("depth"), 0)
    if depth >= DEFAULT_MAX_DEPTH:
        return {
            "ok": False,
            "capability": "incident_deduplicate",
            "error": "max_depth_reached",
            "terminal": True,
        }

    incident_key = _to_str(data.get("incident_key")) or _build_incident_key(data, meta)

    existing = _find_existing_incident(
        incidents_table_name,
        incident_key,
        airtable_list_filtered,
    )

    # =========================
    # ✅ INCIDENT EXISTE → STOP LOOP
    # =========================
    if existing:
        existing_id = _to_str(existing.get("id"))

        try:
            airtable_update(
                incidents_table_name,
                existing_id,
                {
                    "Last_Seen_At": _now_ts(),
                },
            )
        except Exception:
            pass

        return {
            "ok": True,
            "capability": "incident_deduplicate",
            "status": "done",
            "incident_exists": True,
            "incident_record_id": existing_id,
            "action": "noop",
            "next_commands": [],  # 🔥 STOP CRITIQUE
            "terminal": True,    # 🔥 STOP CRITIQUE
        }

    # =========================
    # ❌ NO INCIDENT → CREATE
    # =========================
    return {
        "ok": True,
        "capability": "incident_deduplicate",
        "status": "done",
        "incident_exists": False,
        "action": "create_new",
        "next_commands": [
            {
                "capability": "incident_create",
                "priority": 1,
                "input": {
                    **data,
                    "incident_key": incident_key,
                    "_depth": depth + 1,
                    "step_index": _to_int(meta.get("step_index"), 0) + 1,
                },
            }
        ],
        "terminal": False,
    }
