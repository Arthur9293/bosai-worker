import json
import os
from typing import Any, Dict

import requests


AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()
POLICIES_TABLE_NAME = os.getenv("POLICIES_TABLE_NAME", "Policies").strip()
POLICIES_VIEW_NAME = os.getenv("POLICIES_VIEW_NAME", "Active").strip()


def _airtable_url(table_name: str) -> str:
    return f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{table_name}"


def _airtable_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }


def _pick_policy_value(fields: Dict[str, Any], policy_type: str) -> Any:
    t = str(policy_type or "").strip().lower()

    if t == "bool":
        return fields.get("Value_Bool")
    if t == "number":
        return fields.get("Value_Number")
    if t == "text":
        return fields.get("Value_Text")
    if t == "json":
        raw = fields.get("Value_JSON")
        if isinstance(raw, dict):
            return raw
        if raw is None:
            return None
        try:
            s = str(raw).strip()
            return json.loads(s) if s else None
        except Exception:
            return raw

    for key in ("Value_Bool", "Value_Number", "Value_Text", "Value_JSON"):
        value = fields.get(key)
        if value not in (None, "", []):
            return value

    return None


def get_policies() -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
        print("[policies] missing AIRTABLE env")
        return {}

    try:
        response = requests.get(
            _airtable_url(POLICIES_TABLE_NAME),
            headers=_airtable_headers(),
            params={
                "view": POLICIES_VIEW_NAME,
                "maxRecords": 100,
            },
            timeout=20,
        )
        response.raise_for_status()

        records = response.json().get("records", [])
        print(f"[policies] fetched records: {len(records)}")

        policies: Dict[str, Any] = {}

        for rec in records:
            fields = rec.get("fields", {}) or {}
            print("[policies] fields keys:", list(fields.keys()))

            enabled = fields.get("Enabled", True)
            if enabled is False:
                continue

            name = str(fields.get("Policy_Key") or "").strip()
            if not name:
                name = str(fields.get("Name") or "").strip()
            if not name:
                name = str(fields.get("Policy") or "").strip()
            if not name:
                name = str(fields.get("Key") or "").strip()
            if not name:
                continue

            print("[policies] resolved name:", name)

            policy_type = str(fields.get("Type") or "").strip()
            value = _pick_policy_value(fields, policy_type)

            print("[policies] type/value:", policy_type, value)

            if value is None:
                continue

            policies[name] = value

        print("[policies] final keys:", list(policies.keys()))
        return policies

    except Exception as e:
        print("[policies] ERROR:", repr(e))
        return {}
