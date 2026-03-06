import os
import sys
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

from chaos_guard import ChaosGuard, build_chaos_guard_config


SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_EVENTS_TABLE = os.getenv("SUPABASE_EVENTS_TABLE", "bosai_events").strip()

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()
AIRTABLE_COMMANDS_TABLE = os.getenv("AIRTABLE_COMMANDS_TABLE", "Commands").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-event-dispatcher").strip()

try:
    DISPATCH_LIMIT = int(os.getenv("DISPATCH_LIMIT", "20"))
except Exception:
    DISPATCH_LIMIT = 20

if DISPATCH_LIMIT <= 0:
    DISPATCH_LIMIT = 20

if DISPATCH_LIMIT > 100:
    DISPATCH_LIMIT = 100


# ----------------------------
# Helpers
# ----------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


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


def truncate_text(value: Any, limit: int) -> str:
    text = normalize_text(value)
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def normalize_payload(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    return {}


def is_valid_http_url(url: str) -> bool:
    text = normalize_text(url)
    return text.startswith("http://") or text.startswith("https://")


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


def build_events_url(query_params: Optional[Dict[str, str]] = None) -> str:
    base = f"{SUPABASE_URL}/rest/v1/{SUPABASE_EVENTS_TABLE}"
    if not query_params:
        return base
    return f"{base}?{urllib.parse.urlencode(query_params)}"


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


def derive_error_code(exc: Exception) -> str:
    message = repr(exc).lower()

    if "invalid_url" in message or "missing valid url" in message:
        return "INVALID_URL"

    if "policy_not_found" in message or "unsupported event type" in message:
        return "POLICY_NOT_FOUND"

    if "rate_limit_exceeded" in message:
        return "CHAOS_RATE_LIMIT"

    if "payload_too_large" in message:
        return "CHAOS_PAYLOAD_TOO_LARGE"

    if "source_blocked" in message:
        return "CHAOS_SOURCE_BLOCKED"

    if "event_not_dict" in message:
        return "CHAOS_EVENT_INVALID"

    if "airtable create failed" in message:
        return "AIRTABLE_CREATE_FAILED"

    if "airtable fields empty" in message:
        return "AIRTABLE_FIELDS_EMPTY"

    if isinstance(exc, urllib.error.HTTPError):
        return "HTTP_ERROR"

    return "UNKNOWN_ERROR"


# ----------------------------
# Supabase event state
# ----------------------------

def update_event(event_id: str, patch: Dict[str, Any]) -> None:
    if not event_id:
        raise ValueError("Missing event_id for update_event")

    if not isinstance(patch, dict) or not patch:
        raise ValueError("Missing patch for update_event")

    url = build_events_url({"id": f"eq.{event_id}"})

    req = urllib.request.Request(
        url,
        data=safe_json_dumps(patch).encode("utf-8"),
        headers=supabase_headers(),
        method="PATCH",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def claim_event(event: Dict[str, Any]) -> bool:
    event_id = normalize_text(event.get("id"))
    event_status = normalize_lower(event.get("event_status"))

    if not event_id:
        return False

    if event_status != "pending":
        return False

    update_event(
        event_id,
        {
            "event_status": "processing",
            "processing_started_at": now_iso(),
            "processed_by": WORKER_NAME,
        },
    )
    return True


def mark_event_processed(event_id: str) -> None:
    patch: Dict[str, Any] = {
        "event_status": "processed",
        "processed_at": now_iso(),
        "processed_by": WORKER_NAME,
        "last_error_code": None,
        "rejected_at": None,
        "rejected_by": None,
        "rejected_reason": None,
    }

    update_event(event_id, patch)


def reject_event(event_id: str, reason: str, error_code: str) -> None:
    update_event(
        event_id,
        {
            "event_status": "rejected",
            "rejected_at": now_iso(),
            "rejected_by": WORKER_NAME,
            "rejected_reason": truncate_text(reason, 1000),
            "last_error_code": error_code,
        },
    )


def dead_letter_event(event_id: str, reason: str, error_code: str, payload: Dict[str, Any]) -> None:
    update_event(
        event_id,
        {
            "event_status": "dead_lettered",
            "dead_lettered": True,
            "rejected_at": now_iso(),
            "rejected_by": WORKER_NAME,
            "rejected_reason": truncate_text(reason, 1000),
            "last_error_code": error_code,
            "dead_letter_payload": payload,
        },
    )


# ----------------------------
# Fetch pending events
# ----------------------------

def fetch_pending_events() -> List[Dict[str, Any]]:
    query = {
        "select": "*",
        "event_status": "eq.pending",
        "dead_lettered": "eq.false",
        "order": "created_at.asc",
        "limit": str(DISPATCH_LIMIT),
    }

    url = build_events_url(query)

    req = urllib.request.Request(
        url,
        headers=supabase_headers(),
        method="GET",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        data = safe_json_loads(body, [])

        if not isinstance(data, list):
            return []

        return [item for item in data if isinstance(item, dict)]


# ----------------------------
# Airtable Commands
# ----------------------------

def create_airtable_command(fields: Dict[str, Any]) -> Dict[str, Any]:
    safe_fields = clean_airtable_fields(fields)

    if not safe_fields:
        raise ValueError("Airtable fields empty after cleaning")

    url = (
        f"https://api.airtable.com/v0/"
        f"{AIRTABLE_BASE_ID}/"
        f"{urllib.parse.quote(AIRTABLE_COMMANDS_TABLE)}"
    )

    req = urllib.request.Request(
        url,
        data=safe_json_dumps({"fields": safe_fields}).encode("utf-8"),
        headers=airtable_headers(),
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        parsed = safe_json_loads(body, {})

        if not isinstance(parsed, dict):
            raise RuntimeError("Airtable create failed: non-dict response")

        return parsed


# ----------------------------
# Event -> Command mapping
# ----------------------------

def build_http_exec_command_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    event_id = normalize_text(event.get("id"))
    payload = normalize_payload(event.get("payload"))

    url = normalize_text(payload.get("url"))
    method = normalize_upper(payload.get("method") or "GET")
    headers = payload.get("headers", {})
    body_json = payload.get("json", payload.get("body", {}))

    if not is_valid_http_url(url):
        raise ValueError("INVALID_URL: http_exec event missing valid url")

    if not isinstance(headers, dict):
        headers = {}

    if not isinstance(body_json, dict):
        body_json = {}

    input_json = {
        "url": url,
        "method": method,
        "headers": headers,
        "json": body_json,
    }

    return {
        "Capability": "http_exec",
        "Status_select": "Queued",
        "Idempotency_Key": f"evt-{event_id}",
        "Input_JSON": safe_json_dumps(input_json),
        "Approved": True,
        "worker": WORKER_NAME,
        "Notes": truncate_text(f"Created from event {event_id}", 500),
        "http_target": url,
        "HTTP_Method": method,
        "HTTP_Headers_JSON": safe_json_dumps(headers),
    }


def build_sla_machine_command_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    event_id = normalize_text(event.get("id"))
    payload = event.get("payload")

    if payload is not None and not isinstance(payload, dict):
        raise ValueError("UNKNOWN_ERROR: sla_machine payload must be a dict")

    input_json = payload if isinstance(payload, dict) else {}

    return {
        "Capability": "sla_machine",
        "Status_select": "Queued",
        "Idempotency_Key": f"evt-{event_id}",
        "Input_JSON": safe_json_dumps(input_json),
        "Approved": True,
        "worker": WORKER_NAME,
        "Notes": truncate_text(f"Created from event {event_id}", 500),
    }


def map_event_to_command_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    event_type = normalize_lower(event.get("type"))

    if event_type == "http_exec":
        return build_http_exec_command_fields(event)

    if event_type == "sla_machine":
        return build_sla_machine_command_fields(event)

    raise ValueError(f"POLICY_NOT_FOUND: unsupported event type {event_type}")


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    require_env("SUPABASE_URL", SUPABASE_URL)
    require_env("SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY)
    require_env("SUPABASE_EVENTS_TABLE", SUPABASE_EVENTS_TABLE)
    require_env("AIRTABLE_API_KEY", AIRTABLE_API_KEY)
    require_env("AIRTABLE_BASE_ID", AIRTABLE_BASE_ID)
    require_env("AIRTABLE_COMMANDS_TABLE", AIRTABLE_COMMANDS_TABLE)

    chaos_guard_config = build_chaos_guard_config({
        "max_events_per_minute": os.getenv("CHAOS_GUARD_MAX_EVENTS_PER_MINUTE", "50"),
        "payload_size_limit": os.getenv("CHAOS_GUARD_PAYLOAD_SIZE_LIMIT", "4096"),
        "blocked_sources": safe_json_loads(
            os.getenv("CHAOS_GUARD_BLOCKED_SOURCES_JSON", "[]"),
            []
        ),
    })
    chaos_guard = ChaosGuard(chaos_guard_config)

    print(f"SUPABASE_EVENTS_TABLE = {SUPABASE_EVENTS_TABLE}")
    print(f"AIRTABLE_COMMANDS_TABLE = {AIRTABLE_COMMANDS_TABLE}")
    print(f"WORKER_NAME = {WORKER_NAME}")
    print(f"DISPATCH_LIMIT = {DISPATCH_LIMIT}")
    print(f"CHAOS_GUARD_CONFIG = {safe_json_dumps(chaos_guard_config)}")

    events = fetch_pending_events()
    print(f"Fetched pending events: {len(events)}")

    claimed = 0
    processed = 0
    rejected = 0
    dead_lettered = 0
    skipped = 0
    failed = 0

    for event in events:
        event_id = normalize_text(event.get("id"))

        try:
            if not event_id:
                skipped += 1
                continue

            if not claim_event(event):
                print(f"Skipped event {event_id}: not claimable")
                skipped += 1
                continue

            claimed += 1

            ok, chaos_reason = chaos_guard.validate_event(event)
            if not ok:
                err = ValueError(f"chaos_guard_reject:{chaos_reason}")
                error_code = derive_error_code(err)
                reject_event(event_id, repr(err), error_code)
                print(f"Rejected by chaos guard event {event_id} -> {error_code}")
                rejected += 1
                continue

            fields = map_event_to_command_fields(event)
            command = create_airtable_command(fields)
            command_id = normalize_text(command.get("id"))

            print(
                f"Created command for event {event_id} "
                f"-> capability={fields.get('Capability')} command_id={command_id}"
            )

            mark_event_processed(event_id)
            processed += 1

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            error_code = derive_error_code(e)

            try:
                dead_letter_event(
                    event_id=event_id,
                    reason=f"HTTP error {e.code}: {body}",
                    error_code=error_code,
                    payload={
                        "http_status": e.code,
                        "body": truncate_text(body, 4000),
                        "dispatcher": WORKER_NAME,
                        "at": now_iso(),
                    },
                )
                dead_lettered += 1
            except Exception as inner_exc:
                print(f"Dead-letter failed for {event_id}: {repr(inner_exc)}")
                failed += 1

        except Exception as e:
            error_code = derive_error_code(e)
            reason = repr(e)

            try:
                reject_event(event_id, reason, error_code)
                print(f"Rejected event {event_id} -> {error_code}")
                rejected += 1
            except Exception as inner_exc:
                print(f"Reject failed for {event_id}: {repr(inner_exc)}")
                failed += 1

    print(safe_json_dumps({
        "ok": True,
        "fetched": len(events),
        "claimed": claimed,
        "processed": processed,
        "rejected": rejected,
        "dead_lettered": dead_lettered,
        "skipped": skipped,
        "failed": failed,
    }))


if __name__ == "__main__":
    main()
