import os
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_EVENTS_TABLE = os.getenv("SUPABASE_EVENTS_TABLE", "bosai_events").strip()

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()
AIRTABLE_COMMANDS_TABLE = os.getenv("AIRTABLE_COMMANDS_TABLE", "Commands").strip()
AIRTABLE_EVENT_POLICIES_TABLE = os.getenv("AIRTABLE_EVENT_POLICIES_TABLE", "Event_Policies").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()

try:
    EVENT_ENGINE_LIMIT = int(os.getenv("EVENT_ENGINE_LIMIT", "10"))
except Exception:
    EVENT_ENGINE_LIMIT = 10

if EVENT_ENGINE_LIMIT <= 0:
    EVENT_ENGINE_LIMIT = 10

if EVENT_ENGINE_LIMIT > 100:
    EVENT_ENGINE_LIMIT = 100


ALLOWED_CAPABILITIES = {
    "http_exec",
    "sla_machine",
    "escalation_engine",
    "command_orchestrator",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def require_env(name: str, value: str) -> None:
    if not value or not str(value).strip():
        raise RuntimeError(f"Missing env var: {name}")


def safe_json_dumps(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return json.dumps({}, ensure_ascii=False)


def safe_json_loads(text: str, default: Any) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return default


def normalize_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def normalize_lower(value: Any) -> str:
    return normalize_str(value).lower()


def normalize_payload(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    return {}


def merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        merged[key] = value
    return merged


def clean_airtable_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(fields, dict):
        return {}

    cleaned: Dict[str, Any] = {}

    for key, value in fields.items():
        if key == "Owner":
            continue

        if value is None:
            continue

        if isinstance(value, str):
            stripped = value.strip()
            if stripped == "":
                continue
            cleaned[key] = stripped
            continue

        cleaned[key] = value

    return cleaned


def supabase_headers() -> Dict[str, str]:
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }


def airtable_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }


def fetch_events() -> List[Dict[str, Any]]:
    query = urllib.parse.urlencode({
        "select": "*",
        "processed_at": "is.null",
        "order": "created_at.asc",
        "limit": str(EVENT_ENGINE_LIMIT),
    })

    url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_EVENTS_TABLE}?{query}"

    req = urllib.request.Request(
        url,
        headers=supabase_headers(),
        method="GET",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        data = safe_json_loads(body, [])

        if not isinstance(data, list):
            print("WARN fetch_events returned non-list, fallback to []")
            return []

        valid_events: List[Dict[str, Any]] = []
        for item in data:
            if isinstance(item, dict):
                valid_events.append(item)

        return valid_events


def fetch_event_policies() -> List[Dict[str, Any]]:
    """
    Lit la table Airtable Event_Policies.
    On récupère tous les records (pagination simple) puis on filtre côté Python.
    """
    all_records: List[Dict[str, Any]] = []
    offset: Optional[str] = None

    while True:
        params = {
            "pageSize": "100",
        }
        if offset:
            params["offset"] = offset

        query = urllib.parse.urlencode(params)
        url = (
            f"https://api.airtable.com/v0/"
            f"{AIRTABLE_BASE_ID}/"
            f"{urllib.parse.quote(AIRTABLE_EVENT_POLICIES_TABLE)}"
            f"?{query}"
        )

        req = urllib.request.Request(
            url,
            headers=airtable_headers(),
            method="GET",
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            parsed = safe_json_loads(body, {})

        records = parsed.get("records", [])
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict):
                    all_records.append(record)

        offset = parsed.get("offset")
        if not offset:
            break

    return all_records


def parse_policy_priority(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 999999


def parse_policy_input_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return {}
        parsed = safe_json_loads(stripped, {})
        if isinstance(parsed, dict):
            return parsed

    return {}


def is_policy_enabled(fields: Dict[str, Any]) -> bool:
    value = fields.get("Enabled", False)
    return bool(value)


def event_matches_policy(event: Dict[str, Any], policy_fields: Dict[str, Any]) -> bool:
    event_type = normalize_lower(event.get("type"))
    event_source = normalize_lower(event.get("source"))

    policy_type = normalize_lower(policy_fields.get("Event_Type"))
    policy_source = normalize_lower(policy_fields.get("Event_Source"))

    if not policy_type:
        return False

    if event_type != policy_type:
        return False

    # Event_Source vide = wildcard
    if policy_source and event_source != policy_source:
        return False

    return True


def resolve_policy_for_event(
    event: Dict[str, Any],
    policies: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []

    for record in policies:
        fields = record.get("fields", {})
        if not isinstance(fields, dict):
            continue

        if not is_policy_enabled(fields):
            continue

        if event_matches_policy(event, fields):
            matches.append(record)

    if not matches:
        return None

    matches.sort(key=lambda record: parse_policy_priority(record.get("fields", {}).get("Priority")))
    return matches[0]


def fallback_map_event_to_command(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mapping stable historique.
    Utilisé si aucune policy ne match.
    """
    if not isinstance(event, dict):
        raise ValueError("Event must be a dict")

    event_id = event.get("id")
    if not event_id:
        raise ValueError("Event missing id")

    event_type = normalize_lower(event.get("type"))
    payload = normalize_payload(event.get("payload"))

    capability = "command_orchestrator"
    input_json = payload

    if event_type in ("command_http_exec", "http_exec", "http_request", "command.http_exec"):
        capability = "http_exec"
        input_json = {
            "url": payload.get("url", ""),
            "method": payload.get("method", "GET"),
            "headers": payload.get("headers", {}),
            "json": payload.get("json", payload.get("body", {})),
        }

    elif event_type in ("sla_machine", "sla_check"):
        capability = "sla_machine"
        input_json = payload

    elif event_type in ("escalation_engine", "escalate"):
        capability = "escalation_engine"
        input_json = payload

    elif event_type in ("command_orchestrator", "orchestrator"):
        capability = "command_orchestrator"
        input_json = payload

    fields = {
        "Capability": capability,
        "Status_select": "Queued",
        "Idempotency_Key": f"evt-{event_id}",
        "Input_JSON": safe_json_dumps(input_json),
        "Approved": True,
        "worker": WORKER_NAME,
        "Notes": f"Created from Supabase event {event_id} (fallback)",
    }

    return clean_airtable_fields(fields)


def map_event_to_command_with_policy(
    event: Dict[str, Any],
    policies: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("Event must be a dict")

    event_id = normalize_str(event.get("id"))
    if not event_id:
        raise ValueError("Event missing id")

    event_payload = normalize_payload(event.get("payload"))
    matched_policy = resolve_policy_for_event(event, policies)

    if not matched_policy:
        print(f"INFO no policy matched for event {event_id}, using fallback")
        return fallback_map_event_to_command(event)

    policy_fields = matched_policy.get("fields", {})
    policy_name = normalize_str(policy_fields.get("Name")) or "Unnamed Policy"
    target_capability = normalize_lower(policy_fields.get("Target_Capability"))
    target_input_json = parse_policy_input_json(policy_fields.get("Target_Input_JSON"))

    if not target_capability:
        raise RuntimeError(f"Policy '{policy_name}' missing Target_Capability")

    if target_capability not in ALLOWED_CAPABILITIES:
        raise RuntimeError(
            f"Policy '{policy_name}' uses unsupported Target_Capability '{target_capability}'"
        )

    # Règle de merge sûre :
    # - base = payload event
    # - override = Target_Input_JSON policy
    # => la policy peut compléter / surcharger
    final_input_json = merge_dicts(event_payload, target_input_json)

    fields = {
        "Capability": target_capability,
        "Status_select": "Queued",
        "Idempotency_Key": f"evt-{event_id}",
        "Input_JSON": safe_json_dumps(final_input_json),
        "Approved": True,
        "worker": WORKER_NAME,
        "Notes": f"Created from Supabase event {event_id} via policy {policy_name}",
    }

    return clean_airtable_fields(fields)


def create_airtable_command(fields: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(fields, dict) or not fields:
        raise ValueError("Invalid Airtable fields payload")

    safe_fields = clean_airtable_fields(fields)
    if not safe_fields:
        raise ValueError("Airtable fields empty after cleaning")

    payload = {"fields": safe_fields}
    data = safe_json_dumps(payload).encode("utf-8")

    url = (
        f"https://api.airtable.com/v0/"
        f"{AIRTABLE_BASE_ID}/"
        f"{urllib.parse.quote(AIRTABLE_COMMANDS_TABLE)}"
    )

    req = urllib.request.Request(
        url,
        data=data,
        headers=airtable_headers(),
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        parsed = safe_json_loads(body, {})

        if not isinstance(parsed, dict):
            raise RuntimeError("Airtable create returned non-dict response")

        return parsed


def mark_event_processed(event_id: str) -> None:
    if not event_id:
        raise ValueError("Missing event_id for mark_event_processed")

    query = urllib.parse.urlencode({
        "id": f"eq.{event_id}"
    })

    url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_EVENTS_TABLE}?{query}"

    payload = {
        "processed_at": now_iso(),
        "processed_by": "bosai-event-engine"
    }

    data = safe_json_dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers=supabase_headers(),
        method="PATCH",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def main() -> None:
    require_env("SUPABASE_URL", SUPABASE_URL)
    require_env("SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY)
    require_env("AIRTABLE_API_KEY", AIRTABLE_API_KEY)
    require_env("AIRTABLE_BASE_ID", AIRTABLE_BASE_ID)

    print(f"EVENT_ENGINE_LIMIT = {EVENT_ENGINE_LIMIT}")
    print(f"SUPABASE_EVENTS_TABLE = {SUPABASE_EVENTS_TABLE}")
    print(f"AIRTABLE_COMMANDS_TABLE = {AIRTABLE_COMMANDS_TABLE}")
    print(f"AIRTABLE_EVENT_POLICIES_TABLE = {AIRTABLE_EVENT_POLICIES_TABLE}")
    print(f"WORKER_NAME = {WORKER_NAME}")

    policies = fetch_event_policies()
    print(f"Loaded policies: {len(policies)}")

    events = fetch_events()
    print(f"Fetched events: {len(events)}")

    created = 0
    processed = 0
    failed = 0

    for event in events:
        event_id = None

        try:
            if not isinstance(event, dict):
                raise ValueError("Fetched event is not a dict")

            event_id = normalize_str(event.get("id"))
            if not event_id:
                raise ValueError("Fetched event missing id")

            fields = map_event_to_command_with_policy(event, policies)

            cmd = create_airtable_command(fields)
            cmd_id = cmd.get("id")

            print(f"Created command for event {event_id} -> {cmd_id}")
            created += 1

            mark_event_processed(event_id)
            print(f"Marked processed {event_id}")
            processed += 1

        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="ignore")
            print(f"HTTP error {e.code} for event {event_id}: {err}")
            failed += 1

        except Exception as e:
            print(f"Error for event {event_id}: {repr(e)}")
            failed += 1

    print(safe_json_dumps({
        "ok": True,
        "fetched": len(events),
        "created": created,
        "processed": processed,
        "failed": failed,
    }))


if __name__ == "__main__":
    main()
