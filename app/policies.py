import json
import os
from typing import Any, Dict
from urllib.parse import quote

import requests
from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


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
    load_dotenv(os.path.join(BASE_DIR, "..", ".env"), override=True)

    airtable_api_key = os.getenv("AIRTABLE_API_KEY", "").strip()
    airtable_base_id = os.getenv("AIRTABLE_BASE_ID", "").strip()
    policies_table_name = os.getenv("POLICIES_TABLE_NAME", "Policies").strip()
    policies_view_name = os.getenv("POLICIES_VIEW_NAME", "Active").strip()

    if not airtable_api_key or not airtable_base_id:
        print("[policies] missing AIRTABLE env")
        return {}

    url = f"https://api.airtable.com/v0/{airtable_base_id}/{quote(policies_table_name)}"

    try:
        print("[DEBUG POLICIES]")
        print("BASE_ID =", airtable_base_id)
        print("TABLE =", policies_table_name)
        print("VIEW =", policies_view_name)
        print("URL =", url)

        response = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {airtable_api_key}",
                "Content-Type": "application/json",
            },
            params={
                "view": policies_view_name,
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

            policy_type = str(fields.get("Type") or "").strip()
            value = _pick_policy_value(fields, policy_type)

            if value is None:
                continue

            policies[name] = value

        print("[policies] final keys:", list(policies.keys()))
        return policies

    except Exception as e:
        print("[policies] ERROR:", repr(e))
        return {}
