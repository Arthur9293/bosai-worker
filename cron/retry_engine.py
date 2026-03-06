import os
import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

EVENT_TABLE = "bosai_events"

RETRY_DELAY_SECONDS = int(os.getenv("RETRY_DELAY_SECONDS", "60"))
RETRY_LIMIT = int(os.getenv("RETRY_FETCH_LIMIT", "20"))

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def supabase_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }

def fetch_retry_events():
    query = urllib.parse.urlencode({
        "select": "*",
        "event_status": "eq.rejected",
        "order": "created_at.asc",
        "limit": str(RETRY_LIMIT)
    })

    url = f"{SUPABASE_URL}/rest/v1/{EVENT_TABLE}?{query}"

    req = urllib.request.Request(url, headers=supabase_headers())

    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())

def patch_event(event_id, data):

    url = f"{SUPABASE_URL}/rest/v1/{EVENT_TABLE}?id=eq.{event_id}"

    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers=supabase_headers(),
        method="PATCH"
    )

    with urllib.request.urlopen(req):
        pass


def main():

    events = fetch_retry_events()

    retried = 0
    dead = 0

    for event in events:

        retry_count = event.get("retry_count", 0)
        max_retries = event.get("max_retries", 3)
        event_id = event["id"]

        if retry_count >= max_retries:

            patch_event(event_id, {
                "event_status": "dead_lettered",
                "dead_lettered": True
            })

            dead += 1
            continue

        next_retry = datetime.now(timezone.utc) + timedelta(seconds=RETRY_DELAY_SECONDS)

        patch_event(event_id, {
            "retry_count": retry_count + 1,
            "retry_after": next_retry.isoformat(),
            "event_status": "pending"
        })

        retried += 1

    print(json.dumps({
        "retry_checked": len(events),
        "retried": retried,
        "dead_lettered": dead
    }))


if __name__ == "__main__":
    main()
