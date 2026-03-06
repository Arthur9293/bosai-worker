import os
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List


SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_EVENTS_TABLE = os.getenv("SUPABASE_EVENTS_TABLE", "bosai_events").strip()

try:
    RETRY_DELAY_SECONDS = int(os.getenv("RETRY_DELAY_SECONDS", "60"))
except Exception:
    RETRY_DELAY_SECONDS = 60

if RETRY_DELAY_SECONDS <= 0:
    RETRY_DELAY_SECONDS = 60

try:
    RETRY_FETCH_LIMIT = int(os.getenv("RETRY_FETCH_LIMIT", "20"))
except Exception:
    RETRY_FETCH_LIMIT = 20

if RETRY_FETCH_LIMIT <= 0:
    RETRY_FETCH_LIMIT = 20

if RETRY_FETCH_LIMIT > 100:
    RETRY_FETCH_LIMIT = 100


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


def supabase_headers() -> Dict[str, str]:
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }


def parse_iso_datetime(value: Any) -> datetime | None:
    text = normalize_text(value)
    if not text:
        return None

    try:
        # support trailing Z if present
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def build_events_url(query_params: Dict[str, str] | None = None) -> str:
    base = f"{SUPABASE_URL}/rest/v1/{SUPABASE_EVENTS_TABLE}"
    if not query_params:
        return base
    return f"{base}?{urllib.parse.urlencode(query_params)}"


def fetch_retry_events() -> List[Dict[str, Any]]:
    query = {
        "select": "*",
        "event_status": "eq.rejected",
        "dead_lettered": "eq.false",
        "order": "created_at.asc",
        "limit": str(RETRY_FETCH_LIMIT),
    }

    url = build_events_url(query)
    req = urllib.request.Request(url, headers=supabase_headers(), method="GET")

    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        data = safe_json_loads(body, [])

        if not isinstance(data, list):
            return []

        return [item for item in data if isinstance(item, dict)]


def patch_event(event_id: str, data: Dict[str, Any]) -> None:
    if not event_id:
        raise ValueError("Missing event_id for patch_event")

    if not isinstance(data, dict) or not data:
        raise ValueError("Missing patch data for patch_event")

    url = build_events_url({"id": f"eq.{event_id}"})

    req = urllib.request.Request(
        url,
        data=safe_json_dumps(data).encode("utf-8"),
        headers=supabase_headers(),
        method="PATCH",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def is_ready_for_retry(event: Dict[str, Any]) -> bool:
    retry_after = parse_iso_datetime(event.get("retry_after"))

    # If no retry_after set, it's ready now.
    if retry_after is None:
        return True

    return retry_after <= now_utc()


def main() -> None:
    require_env("SUPABASE_URL", SUPABASE_URL)
    require_env("SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY)
    require_env("SUPABASE_EVENTS_TABLE", SUPABASE_EVENTS_TABLE)

    print(f"SUPABASE_EVENTS_TABLE = {SUPABASE_EVENTS_TABLE}")
    print(f"RETRY_DELAY_SECONDS = {RETRY_DELAY_SECONDS}")
    print(f"RETRY_FETCH_LIMIT = {RETRY_FETCH_LIMIT}")

    events = fetch_retry_events()

    retry_checked = len(events)
    ready = 0
    retried = 0
    dead_lettered = 0
    skipped_not_ready = 0
    failed = 0

    for event in events:
        try:
            event_id = normalize_text(event.get("id"))
            if not event_id:
                raise ValueError("Missing event id")

            retry_count_raw = event.get("retry_count", 0)
            max_retries_raw = event.get("max_retries", 3)

            try:
                retry_count = int(retry_count_raw or 0)
            except Exception:
                retry_count = 0

            try:
                max_retries = int(max_retries_raw or 3)
            except Exception:
                max_retries = 3

            if max_retries <= 0:
                max_retries = 3

            if not is_ready_for_retry(event):
                skipped_not_ready += 1
                continue

            ready += 1

            if retry_count >= max_retries:
                patch_event(event_id, {
                    "event_status": "dead_lettered",
                    "dead_lettered": True,
                    "last_error_code": "MAX_RETRIES_EXCEEDED",
                    "dead_letter_payload": {
                        "retry_count": retry_count,
                        "max_retries": max_retries,
                        "dead_lettered_by": "bosai-retry-engine",
                        "dead_lettered_at": now_iso(),
                    }
                })
                dead_lettered += 1
                continue

            next_retry = now_utc() + timedelta(seconds=RETRY_DELAY_SECONDS)

            patch_event(event_id, {
                "retry_count": retry_count + 1,
                "retry_after": next_retry.isoformat(),
                "event_status": "pending",
                "last_error_code": None,
                # on garde l'historique de rejet en place;
                # l'event_engine filtrera sur event_status / rejected_at selon ta logique actuelle
            })

            retried += 1

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            print(f"HTTP error for retry event: {e.code} {body}")
            failed += 1

        except Exception as e:
            print(f"Retry engine failed for event: {repr(e)}")
            failed += 1

    print(safe_json_dumps({
        "retry_checked": retry_checked,
        "ready": ready,
        "retried": retried,
        "dead_lettered": dead_lettered,
        "skipped_not_ready": skipped_not_ready,
        "failed": failed,
    }))


if __name__ == "__main__":
    main()
