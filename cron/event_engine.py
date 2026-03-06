import os
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_EVENTS_TABLE = os.getenv("SUPABASE_EVENTS_TABLE", "bosai_events").strip()

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()
AIRTABLE_COMMANDS_TABLE = os.getenv("AIRTABLE_COMMANDS_TABLE", "Commands").strip()
AIRTABLE_EVENT_POLICIES_TABLE = os.getenv("AIRTABLE_EVENT_POLICIES_TABLE", "Event_Policies").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()

# Event fetch limit
try:
    EVENT_ENGINE_LIMIT = int(os.getenv("EVENT_ENGINE_LIMIT", "10"))
except Exception:
    EVENT_ENGINE_LIMIT = 10

if EVENT_ENGINE_LIMIT <= 0:
    EVENT_ENGINE_LIMIT = 10

if EVENT_ENGINE_LIMIT > 100:
    EVENT_ENGINE_LIMIT = 100

# Guardrails
try:
    MAX_INPUT_JSON_CHARS = int(os.getenv("MAX_INPUT_JSON_CHARS", "12000"))
except Exception:
    MAX_INPUT_JSON_CHARS = 12000

if MAX_INPUT_JSON_CHARS <= 0:
    MAX_INPUT_JSON_CHARS = 12000

try:
    MAX_NOTES_CHARS = int(os.getenv("MAX_NOTES_CHARS", "500"))
except Exception:
    MAX_NOTES_CHARS = 500

if MAX_NOTES_CHARS <= 0:
    MAX_NOTES_CHARS = 500


# ----------------------------
# Helpers
# ----------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def require_env(name: str, value: str) -> None:
    if not value or not str(value).strip():
        raise RuntimeError(f"Missing env var: {name}")


def safe_json_dumps(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return json.dumps({}, ensure_ascii=False, separators=(",", ":"))


def safe_json_loads(text: str, default: Any) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return default


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def normalize_lower(value: Any) -> str:
    return normalize_text(value).lower()


def normalize_upper(value: Any) -> str:
    return normalize_text(value).upper()


def normalize_payload(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    return {}


def truncate_text(value: str, limit: int) -> str:
    text = normalize_text(value)
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def safe_priority_number(value: Any, default: int = 100) -> int:
    try:
        n = int(value)
        if n < 0:
            return default
        return n
    except Exception:
        return default


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


def clean_airtable_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    """
    Airtable guardrails:
    - remove Owner
    - remove None
    - remove empty strings
    - keep False / 0 / True
    """
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


def is_valid_http_url(url: str) -> bool:
    text = normalize_text(url)
    return text.startswith("http://") or text.startswith("https://")


def parse_json_object_from_text(text: str) -> Dict[str, Any]:
    parsed = safe_json_loads(text, {})
    if isinstance(parsed, dict):
        return parsed
    return {}


def derive_error_code(exc: Exception) -> str:
    message = repr(exc)

    if "missing valid url" in message.lower():
        return "INVALID_URL"

    if "no policy found" in message.lower():
        return "POLICY_NOT_FOUND"

    if "input_json too large" in message.lower():
        return "INPUT_TOO_LARGE"

    if "airtable create" in message.lower():
        return "AIRTABLE_CREATE_FAILED"

    if isinstance(exc, urllib.error.HTTPError):
        return "HTTP_ERROR"

    return "UNKNOWN_ERROR"


# ----------------------------
# Supabase events
# ----------------------------

def fetch_events() -> List[Dict[str, Any]]:
    query = urllib.parse.urlencode({
        "select": "*",
        "processed_at": "is.null",
        "rejected_at": "is.null",
        "dead_lettered": "eq.false",
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

        return [item for item in data if isinstance(item, dict)]


def update_event(event_id: str, patch: Dict[str, Any]) -> None:
    if not event_id:
        raise ValueError("Missing event_id for update_event")

    if not isinstance(patch, dict) or not patch:
        raise ValueError("Missing patch for update_event")

    query = urllib.parse.urlencode({
        "id": f"eq.{event_id}"
    })

    url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_EVENTS_TABLE}?{query}"
    data = safe_json_dumps(patch).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers=supabase_headers(),
        method="PATCH",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def mark_event_processed(event_id: str) -> None:
    update_event(
        event_id,
        {
            "processed_at": now_iso(),
            "processed_by": "bosai-event-engine",
            "event_status": "processed",
            "last_error_code": None,
        },
    )


def reject_event(event_id: str, reason: str, error_code: str) -> None:
    update_event(
        event_id,
        {
            "rejected_at": now_iso(),
            "rejected_by": "bosai-event-engine",
            "rejected_reason": truncate_text(reason, 1000),
            "event_status": "rejected",
            "last_error_code": error_code,
        },
    )


def dead_letter_event(event_id: str, reason: str, error_code: str, payload: Dict[str, Any]) -> None:
    update_event(
        event_id,
        {
            "rejected_at": now_iso(),
            "rejected_by": "bosai-event-engine",
            "rejected_reason": truncate_text(reason, 1000),
            "dead_lettered": True,
            "dead_letter_payload": payload,
            "event_status": "dead_lettered",
            "last_error_code": error_code,
        },
    )


# ----------------------------
# Airtable Event Policies
# ----------------------------

def fetch_event_policies() -> List[Dict[str, Any]]:
    base_url = (
        f"https://api.airtable.com/v0/"
        f"{AIRTABLE_BASE_ID}/"
        f"{urllib.parse.quote(AIRTABLE_EVENT_POLICIES_TABLE)}"
    )

    all_records: List[Dict[str, Any]] = []
    offset: Optional[str] = None

    while True:
        url = base_url
        if offset:
            url += "?" + urllib.parse.urlencode({"offset": offset})

        req = urllib.request.Request(
            url,
            headers=airtable_headers(),
            method="GET",
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            data = safe_json_loads(body, {})
            records = data.get("records", [])

            if isinstance(records, list):
                all_records.extend([r for r in records if isinstance(r, dict)])

            offset = data.get("offset")
            if not offset:
                break

    return all_records


def build_policy_index(records: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """
    Index by:
    (event_type, event_source)

    Empty event_source = fallback for a given type.
    """
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for record in records:
        fields = record.get("fields", {})
        if not isinstance(fields, dict):
            continue

        enabled = bool(fields.get("Enabled", False))
        if not enabled:
            continue

        event_type = normalize_lower(fields.get("Event_Type"))
        event_source = normalize_lower(fields.get("Event_Source"))

        if not event_type:
            continue

        key = (event_type, event_source)
        index[key] = fields

    return index


def find_policy_for_event(
    event: Dict[str, Any],
    policy_index: Dict[Tuple[str, str], Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    event_type = normalize_lower(event.get("type"))
    event_source = normalize_lower(event.get("source"))

    if not event_type:
        return None

    exact_key = (event_type, event_source)
    fallback_key = (event_type, "")

    if exact_key in policy_index:
        return policy_index[exact_key]

    if fallback_key in policy_index:
        return policy_index[fallback_key]

    return None


# ----------------------------
# Mapping Event -> Command
# ----------------------------

def build_input_from_event_and_policy(
    event: Dict[str, Any],
    policy: Dict[str, Any]
) -> Dict[str, Any]:
    payload = normalize_payload(event.get("payload"))
    event_type = normalize_lower(event.get("type"))
    target_input_json_raw = normalize_text(policy.get("Target_Input_JSON"))

    # 1) Policy override wins if valid JSON object
    if target_input_json_raw:
        parsed = parse_json_object_from_text(target_input_json_raw)
        if parsed:
            return parsed

    # 2) Smart fallback by event type
    if event_type in ("command_http_exec", "http_exec", "http_request", "command.http_exec"):
        url = normalize_text(payload.get("url"))
        if not is_valid_http_url(url):
            raise ValueError("http_exec event missing valid url")

        method = normalize_upper(payload.get("method") or "GET")
        if not method:
            method = "GET"

        headers = payload.get("headers", {})
        if not isinstance(headers, dict):
            headers = {}

        body_json = payload.get("json", payload.get("body", {}))
        if not isinstance(body_json, dict):
            body_json = {}

        return {
            "url": url,
            "method": method,
            "headers": headers,
            "json": body_json,
        }

    # 3) Generic fallback
    return payload


def map_event_to_command(event: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("Event must be a dict")

    if not isinstance(policy, dict):
        raise ValueError("Policy must be a dict")

    event_id = normalize_text(event.get("id"))
    if not event_id:
        raise ValueError("Event missing id")

    capability = normalize_text(policy.get("Target_Capability"))
    if not capability:
        raise ValueError("Policy missing Target_Capability")

    input_json = build_input_from_event_and_policy(event, policy)
    input_json_text = safe_json_dumps(input_json)

    if len(input_json_text) > MAX_INPUT_JSON_CHARS:
        raise ValueError(
            f"Input_JSON too large ({len(input_json_text)} chars > {MAX_INPUT_JSON_CHARS})"
        )

    notes = truncate_text(f"Created from Supabase event {event_id}", MAX_NOTES_CHARS)

    fields: Dict[str, Any] = {
        "Capability": capability,
        "Status_select": "Queued",
        "Idempotency_Key": f"evt-{event_id}",
        "Input_JSON": input_json_text,
        "Approved": True,
        "worker": WORKER_NAME,
        "Notes": notes,
    }

    # Useful cockpit fields for http_exec
    if capability == "http_exec":
        url = normalize_text(input_json.get("url"))
        method = normalize_upper(input_json.get("method") or "GET")
        headers = input_json.get("headers", {})

        if not is_valid_http_url(url):
            raise ValueError("Mapped http_exec command missing valid url")

        if not isinstance(headers, dict):
            headers = {}

        fields["http_target"] = url
        fields["HTTP_Method"] = method or "GET"
        fields["HTTP_Headers_JSON"] = safe_json_dumps(headers)

    return clean_airtable_fields(fields)


# ----------------------------
# Airtable Commands
# ----------------------------

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


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    require_env("SUPABASE_URL", SUPABASE_URL)
    require_env("SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY)
    require_env("AIRTABLE_API_KEY", AIRTABLE_API_KEY)
    require_env("AIRTABLE_BASE_ID", AIRTABLE_BASE_ID)
    require_env("AIRTABLE_COMMANDS_TABLE", AIRTABLE_COMMANDS_TABLE)
    require_env("AIRTABLE_EVENT_POLICIES_TABLE", AIRTABLE_EVENT_POLICIES_TABLE)

    print(f"EVENT_ENGINE_LIMIT = {EVENT_ENGINE_LIMIT}")
    print(f"SUPABASE_EVENTS_TABLE = {SUPABASE_EVENTS_TABLE}")
    print(f"AIRTABLE_COMMANDS_TABLE = {AIRTABLE_COMMANDS_TABLE}")
    print(f"AIRTABLE_EVENT_POLICIES_TABLE = {AIRTABLE_EVENT_POLICIES_TABLE}")
    print(f"WORKER_NAME = {WORKER_NAME}")

    policy_records = fetch_event_policies()
    policy_index = build_policy_index(policy_records)
    print(f"Loaded policies: {len(policy_index)}")

    events = fetch_events()
    print(f"Fetched events: {len(events)}")

    if not events:
        print("No events to process")

    enriched_events: List[Tuple[int, Dict[str, Any], Optional[Dict[str, Any]]]] = []

    for event in events:
        policy = find_policy_for_event(event, policy_index)
        priority = 100

        if policy:
            priority = safe_priority_number(policy.get("Priority"), default=100)

        enriched_events.append((priority, event, policy))

    enriched_events.sort(key=lambda item: item[0])

    created = 0
    processed = 0
    failed = 0
    skipped = 0

    for priority, event, policy in enriched_events:
        event_id = None

        try:
            if not isinstance(event, dict):
                raise ValueError("Fetched event is not a dict")

            event_id = normalize_text(event.get("id"))
            if not event_id:
                raise ValueError("Fetched event missing id")

            event_type = normalize_text(event.get("type"))
            event_source = normalize_text(event.get("source"))

            if not event_type:
                raise ValueError(f"Event {event_id} missing type")

            if not policy:
                err = ValueError(
                    f"No policy found for event_id={event_id} type={event_type} source={event_source}"
                )
                error_code = derive_error_code(err)
                reject_event(event_id, repr(err), error_code)
                print(f"Rejected event {event_id} -> {error_code}")
                skipped += 1
                continue

            fields = map_event_to_command(event, policy)
            cmd = create_airtable_command(fields)
            cmd_id = normalize_text(cmd.get("id"))

            print(
                f"Created command for event {event_id} "
                f"(priority={priority}, capability={fields.get('Capability')}) -> {cmd_id}"
            )
            created += 1

            mark_event_processed(event_id)
            print(f"Marked processed {event_id}")
            processed += 1

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="ignore")
            error_code = derive_error_code(e)
            dead_letter_event(
                event_id=event_id or "",
                reason=f"HTTP error {e.code}: {error_body}",
                error_code=error_code,
                payload={
                    "http_status": e.code,
                    "body": truncate_text(error_body, 4000),
                },
            )
            print(f"Dead-lettered event {event_id} -> {error_code}")
            failed += 1

        except Exception as e:
            error_code = derive_error_code(e)
            reject_event(
                event_id=event_id or "",
                reason=repr(e),
                error_code=error_code,
            )
            print(f"Rejected event {event_id} -> {error_code}")
            failed += 1

    print(safe_json_dumps({
        "ok": True,
        "fetched": len(events),
        "created": created,
        "processed": processed,
        "failed": failed,
        "skipped": skipped,
    }))


if __name__ == "__main__":
    main()
