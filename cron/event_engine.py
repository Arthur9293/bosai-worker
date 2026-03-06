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

try:
    EVENT_ENGINE_LIMIT = int(os.getenv("EVENT_ENGINE_LIMIT", "10"))
except Exception:
    EVENT_ENGINE_LIMIT = 10

if EVENT_ENGINE_LIMIT <= 0:
    EVENT_ENGINE_LIMIT = 10

if EVENT_ENGINE_LIMIT > 100:
    EVENT_ENGINE_LIMIT = 100

# ----------------------------
# Chaos guard / guardrails
# ----------------------------

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

ALLOW_MARK_PROCESSED_ON_SKIP = normalize_bool = None  # placeholder set below


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


def normalize_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value

    text = normalize_lower(value)
    if text in ("1", "true", "yes", "y", "on"):
        return True
    if text in ("0", "false", "no", "n", "off", ""):
        return False
    return default


ALLOW_MARK_PROCESSED_ON_SKIP = normalize_bool(
    os.getenv("ALLOW_MARK_PROCESSED_ON_SKIP", "false"),
    default=False,
)


def truncate_text(value: str, limit: int) -> str:
    value = normalize_text(value)
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


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
    Garde-fous Airtable :
    - supprime Owner
    - supprime None
    - supprime chaînes vides
    - conserve False / 0 / True
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


# ----------------------------
# Supabase events
# ----------------------------

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

        return [item for item in data if isinstance(item, dict)]


def mark_event_processed(event_id: str) -> None:
    if not event_id:
        raise ValueError("Missing event_id for mark_event_processed")

    query = urllib.parse.urlencode({
        "id": f"eq.{event_id}"
    })

    url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_EVENTS
