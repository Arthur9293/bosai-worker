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


def _coerce_value(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if value is None:
        return None

    s = str(value).strip()
    if not s:
        return ""

    lower = s.lower()
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False

    try:
        if "." in s:
            return float(s)
        return int(s)
    except Exception:
        return s


def get_policies() -> Dict[str, Any]:
    if not AIRTABLE_API_KEY or not AIRTABLE_BASE_ID:
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
        policies: Dict[str, Any] = {}

        for rec in records:
            fields = rec.get("fields", {}) or {}

            enabled = fields.get("Enabled", True)
            if enabled is False:
                continue

            name = str(fields.get("Name") or "").strip()
            if not name:
                continue

            raw_value = fields.get("Value")
            policies[name] = _coerce_value(raw_value)

        return policies

    except Exception:
        return {}
