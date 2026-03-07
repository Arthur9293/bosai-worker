import os
import json
import urllib.request
import urllib.parse
from typing import Dict, Any, List


AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()
AIRTABLE_POLICIES_TABLE = os.getenv("AIRTABLE_POLICIES_TABLE", "Policies").strip()


def airtable_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }


def fetch_airtable_records(table_name: str) -> List[Dict[str, Any]]:
    url = (
        f"https://api.airtable.com/v0/"
        f"{AIRTABLE_BASE_ID}/"
        f"{urllib.parse.quote(table_name)}"
    )

    records: List[Dict[str, Any]] = []
    offset = None

    while True:
        final_url = url
        if offset:
            final_url += "?" + urllib.parse.urlencode({"offset": offset})

        req = urllib.request.Request(
            final_url,
            headers=airtable_headers(),
            method="GET",
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            batch = data.get("records", [])
            records.extend(batch)

            offset = data.get("offset")
            if not offset:
                break

    return records


def parse_policy_value(fields: Dict[str, Any]) -> Any:
    policy_type = str(fields.get("Type", "")).lower()

    if policy_type == "bool":
        return bool(fields.get("Value_Bool"))

    if policy_type == "number":
        return fields.get("Value_Number")

    if policy_type == "text":
        return fields.get("Value_Text")

    if policy_type == "json":
        value = fields.get("Value_JSON")
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except Exception:
            return None

    return None


def load_policies() -> Dict[str, Any]:
    records = fetch_airtable_records(AIRTABLE_POLICIES_TABLE)

    policies: Dict[str, Any] = {}

    for record in records:
        fields = record.get("fields", {})

        if not fields.get("Enabled"):
            continue

        policy_name = record.get("fields", {}).get("Name")

        if not policy_name:
            # fallback si le champ principal Airtable porte un autre nom
            policy_name = record.get("fields", {}).get("Policy")
        if not policy_name:
            continue

        policies[policy_name] = parse_policy_value(fields)

    return policies
