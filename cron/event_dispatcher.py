import os
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

from chaos_guard import ChaosGuard, build_chaos_guard_config


SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_EVENTS_TABLE = os.getenv("SUPABASE_EVENTS_TABLE", "bosai_events").strip()

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


def truncate_text(value: Any, limit: int) -> str:
    text = normalize_text(value)
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def supabase_headers() -> Dict[str, str]:
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }


def build_events_url(query_params: Optional[Dict[str, str]] = None) -> str:
    base = f"{SUPABASE_URL}/rest/v1/{SUPABASE_EVENTS_TABLE}"
    if not query_params:
        return base
    return f"{base}?{urllib.parse.urlencode(query_params)}"


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


def is_valid_http_url(url: str) -> bool:
    text = normalize_text(url)
    return text.startswith("http://") or text.startswith("https://")


def derive_error_code(exc: Exception) -> str:
    message = repr(exc).lower()

    if "invalid_url" in message or "missing valid url" in message:
        return "INVALID_URL"

    if "policy_not_found" in message or "unsupported event type" in message:
        return "POLICY_NOT_FOUND"

    if "disallowed_method" in message:
        return "DISALLOWED_METHOD"

    if "disallowed_host" in message:
        return "DISALLOWED_HOST"

    if "https_required" in message:
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
# Event state helpers
# ----------------------------

def claim_event(event: Dict[str, Any]) -> bool:
    """
    Claim simple :
    on ne traite que les events encore pending.
    """
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
    update_event(
        event_id,
        {
            "event_status": "processed",
            "processed_at": now_iso(),
            "processed_by": WORKER_NAME,
            "last_error_code": None,
            "rejected_at": None,
            "rejected_by": None,
            "rejected_reason": None,
        },
    )


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
# Handlers
# ----------------------------

def handle_http_exec_event(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("INVALID_URL: http_exec payload must be a dict")

    url = normalize_text(payload.get("url"))
    method = normalize_text(payload.get("method") or "GET").upper()

    if not is_valid_http_url(url):
        raise ValueError("INVALID_URL: http_exec event missing valid url")

    return {
        "ok": True,
        "validated": True,
        "type": "http_exec",
        "url": url,
        "method": method,
    }


def handle_sla_machine_event(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload")
    if payload is not None and not isinstance(payload, dict):
        raise ValueError("UNKNOWN_ERROR: sla_machine payload must be a dict")

    return {
        "ok": True,
        "validated": True,
        "type": "sla_machine",
    }


def dispatch_event(event: Dict[str, Any]) -> Dict[str, Any]:
    event_type = normalize_lower(event.get("type"))

    if event_type == "http_exec":
        return handle_http_exec_event(event)

    if event_type == "sla_machine":
        return handle_sla_machine_event(event)

    raise ValueError(f"POLICY_NOT_FOUND: unsupported event type {event_type}")


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    require_env("SUPABASE_URL", SUPABASE_URL)
    require_env("SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY)
    require_env("SUPABASE_EVENTS_TABLE", SUPABASE_EVENTS_TABLE)

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

            result = dispatch_event(event)

            print(f"Dispatched event {event_id} -> {safe_json_dumps(result)}")
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
