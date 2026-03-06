import os
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from chaos_guard import ChaosGuard, build_chaos_guard_config


SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_EVENTS_TABLE = os.getenv("SUPABASE_EVENTS_TABLE", "bosai_events").strip()

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()
AIRTABLE_COMMANDS_TABLE = os.getenv("AIRTABLE_COMMANDS_TABLE", "Commands").strip()
AIRTABLE_EVENT_POLICIES_TABLE = os.getenv("AIRTABLE_EVENT_POLICIES_TABLE", "Event_Policies").strip()
AIRTABLE_COMMAND_POLICIES_TABLE = os.getenv("AIRTABLE_COMMAND_POLICIES_TABLE", "Command_Policies").strip()

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


def is_https_url(url: str) -> bool:
    return normalize_text(url).startswith("https://")


def parse_json_object_from_text(text: str) -> Dict[str, Any]:
    parsed = safe_json_loads(text, {})
    if isinstance(parsed, dict):
        return parsed
    return {}


def parse_json_list_from_text(text: str) -> List[str]:
    parsed = safe_json_loads(normalize_text(text), [])
    if not isinstance(parsed, list):
        return []

    out: List[str] = []
    for item in parsed:
        val = normalize_text(item)
        if val:
            out.append(val)
    return out


def extract_host_from_url(url: str) -> str:
    text = normalize_text(url)
    if not text:
        return ""

    try:
        parsed = urllib.parse.urlparse(text)
        return normalize_lower(parsed.hostname or "")
    except Exception:
        return ""


def method_allowed(method: str, allowed_methods: List[str]) -> bool:
    if not allowed_methods:
        return True
    allowed = {normalize_upper(x) for x in allowed_methods if normalize_text(x)}
    return normalize_upper(method) in allowed


def host_allowed(host: str, allowed_hosts: List[str]) -> bool:
    if not allowed_hosts:
        return True
    allowed = {normalize_lower(x) for x in allowed_hosts if normalize_text(x)}
    return normalize_lower(host) in allowed


def derive_error_code(exc: Exception) -> str:
    message = repr(exc).lower()

    if "missing valid url" in message:
        return "INVALID_URL"

    if "no policy found" in message:
        return "POLICY_NOT_FOUND"

    if "input_json too large" in message:
        return "INPUT_TOO_LARGE"

    if "airtable create" in message:
        return "AIRTABLE_CREATE_FAILED"

    if "command policy" in message:
        return "COMMAND_POLICY_ERROR"

    if "host not allowed" in message:
        return "DISALLOWED_HOST"

    if "method not allowed" in message:
        return "DISALLOWED_METHOD"

    if "requires https" in message:
        return "HTTPS_REQUIRED"

    if "rate_limit_exceeded" in message:
        return "CHAOS_RATE_LIMIT"

    if "payload_too_large" in message:
        return "CHAOS_PAYLOAD_TOO_LARGE"

    if "source_blocked" in message:
        return "CHAOS_SOURCE_BLOCKED"

    if "event_not_dict" in message:
        return "CHAOS_EVENT_INVALID"

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
# Airtable tables
# ----------------------------

def fetch_airtable_table_records(table_name: str) -> List[Dict[str, Any]]:
    base_url = (
        f"https://api.airtable.com/v0/"
        f"{AIRTABLE_BASE_ID}/"
        f"{urllib.parse.quote(table_name)}"
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


def fetch_event_policies() -> List[Dict[str, Any]]:
    return fetch_airtable_table_records(AIRTABLE_EVENT_POLICIES_TABLE)


def fetch_command_policies() -> List[Dict[str, Any]]:
    return fetch_airtable_table_records(AIRTABLE_COMMAND_POLICIES_TABLE)


def build_policy_index(records: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
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


def build_command_policy_index(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}

    for record in records:
        fields = record.get("fields", {})
        if not isinstance(fields, dict):
            continue

        enabled = bool(fields.get("Enabled", False))
        capability = normalize_text(fields.get("Capability"))

        if not enabled:
            continue

        if not capability:
            continue

        index[capability] = fields

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

    if target_input_json_raw:
        parsed = parse_json_object_from_text(target_input_json_raw)
        if parsed:
            return parsed

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

    return payload


def validate_command_against_policy(
    capability: str,
    input_json: Dict[str, Any],
    command_policy: Dict[str, Any],
) -> None:
    if not isinstance(command_policy, dict):
        raise ValueError(f"No command policy found for capability={capability}")

    max_input_chars = safe_priority_number(command_policy.get("Max_Input_Chars"), default=12000)
    input_json_text = safe_json_dumps(input_json)

    if len(input_json_text) > max_input_chars:
        raise ValueError(
            f"Input_JSON too large for capability={capability} "
            f"({len(input_json_text)} > {max_input_chars})"
        )

    require_https = bool(command_policy.get("Require_Https", False))
    allowed_hosts = parse_json_list_from_text(command_policy.get("Allowed_Hosts_JSON", "[]"))
    allowed_methods = parse_json_list_from_text(command_policy.get("Allowed_Methods_JSON", "[]"))

    if capability == "http_exec":
        url = normalize_text(input_json.get("url"))
        method = normalize_upper(input_json.get("method") or "GET")
        host = extract_host_from_url(url)

        if not is_valid_http_url(url):
            raise ValueError("http_exec event missing valid url")

        if require_https and not is_https_url(url):
            raise ValueError(f"http_exec requires https url: {url}")

        if not host_allowed(host, allowed_hosts):
            raise ValueError(f"http_exec host not allowed: {host}")

        if not method_allowed(method, allowed_methods):
            raise ValueError(f"http_exec method not allowed: {method}")


def map_event_to_command(
    event: Dict[str, Any],
    event_policy: Dict[str, Any],
    command_policy_index: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("Event must be a dict")

    if not isinstance(event_policy, dict):
        raise ValueError("Event policy must be a dict")

    event_id = normalize_text(event.get("id"))
    if not event_id:
        raise ValueError("Event missing id")

    capability = normalize_text(event_policy.get("Target_Capability"))
    if not capability:
        raise ValueError("Event policy missing Target_Capability")

    input_json = build_input_from_event_and_policy(event, event_policy)

    command_policy = command_policy_index.get(capability)
    validate_command_against_policy(capability, input_json, command_policy)

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

    if capability == "http_exec":
        url = normalize_text(input_json.get("url"))
        method = normalize_upper(input_json.get("method") or "GET")
        headers = input_json.get("headers", {})

        if not isinstance(headers, dict):
            headers = {}

        fields["http_target"] = url
        fields["HTTP_Method"] = method or "GET"
        fields["HTTP_Headers_JSON"] = safe_json_dumps(headers)

    return clean_airtable_fields(fields)


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
    require_env("AIRTABLE_COMMAND_POLICIES_TABLE", AIRTABLE_COMMAND_POLICIES_TABLE)

    chaos_guard_config = build_chaos_guard_config({
        "max_events_per_minute": os.getenv("CHAOS_GUARD_MAX_EVENTS_PER_MINUTE", "50"),
        "payload_size_limit": os.getenv("CHAOS_GUARD_PAYLOAD_SIZE_LIMIT", "4096"),
        "blocked_sources": safe_json_loads(
            os.getenv("CHAOS_GUARD_BLOCKED_SOURCES_JSON", "[]"),
            []
        ),
    })
    chaos_guard = ChaosGuard(chaos_guard_config)

    print(f"EVENT_ENGINE_LIMIT = {EVENT_ENGINE_LIMIT}")
    print(f"SUPABASE_EVENTS_TABLE = {SUPABASE_EVENTS_TABLE}")
    print(f"AIRTABLE_COMMANDS_TABLE = {AIRTABLE_COMMANDS_TABLE}")
    print(f"AIRTABLE_EVENT_POLICIES_TABLE = {AIRTABLE_EVENT_POLICIES_TABLE}")
    print(f"AIRTABLE_COMMAND_POLICIES_TABLE = {AIRTABLE_COMMAND_POLICIES_TABLE}")
    print(f"WORKER_NAME = {WORKER_NAME}")
    print(f"CHAOS_GUARD_CONFIG = {safe_json_dumps(chaos_guard_config)}")

    policy_records = fetch_event_policies()
    policy_index = build_policy_index(policy_records)
    print(f"Loaded event policies: {len(policy_index)}")

    command_policy_records = fetch_command_policies()
    command_policy_index = build_command_policy_index(command_policy_records)
    print(f"Loaded command policies: {len(command_policy_index)}")

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

            ok, chaos_reason = chaos_guard.validate_event(event)
            if not ok:
                err = ValueError(f"chaos_guard_reject:{chaos_reason}")
                error_code = derive_error_code(err)
                reject_event(event_id, repr(err), error_code)
                print(f"Rejected by chaos guard event {event_id} -> {error_code}")
                skipped += 1
                continue

            if not policy:
                err = ValueError(
                    f"No policy found for event_id={event_id} type={event_type} source={event_source}"
                )
                error_code = derive_error_code(err)
                reject_event(event_id, repr(err), error_code)
                print(f"Rejected event {event_id} -> {error_code}")
                skipped += 1
                continue

            fields = map_event_to_command(event, policy, command_policy_index)
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
            reason = repr(e)
            error_code = derive_error_code(e)
            print(f"Event rejected {event_id}: {reason}")

            try:
                reject_event(
                    event_id=event_id or "",
                    reason=reason,
                    error_code=error_code,
                )
                print(f"Rejected event {event_id} -> {error_code}")
            except Exception as reject_err:
                print(f"Reject failed for event {event_id}: {repr(reject_err)}")

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
