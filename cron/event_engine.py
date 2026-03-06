import os
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_EVENTS_TABLE = os.getenv("SUPABASE_EVENTS_TABLE", "bosai_events").strip()

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()
AIRTABLE_COMMANDS_TABLE = os.getenv("AIRTABLE_COMMANDS_TABLE", "Commands").strip()

WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()
EVENT_ENGINE_LIMIT = int(os.getenv("EVENT_ENGINE_LIMIT", "10"))


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def require_env(name, value):
    if not value:
        raise RuntimeError(f"Missing env var: {name}")


def supabase_headers():
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }


def airtable_headers():
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }


def fetch_events():
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
        method="GET"
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def infer_command_from_event(event):
    event_id = event.get("id")
    event_type = str(event.get("type", "")).lower()
    payload = event.get("payload") or {}

    capability = "command_orchestrator"
    input_json = {}

    if event_type in ("command_http_exec", "http_exec", "http_request"):
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

    fields = {
        "Capability": capability,
        "Status_select": "Queue",
        "Idempotency_Key": f"evt-{event_id}",
        "Input_JSON": json.dumps(input_json),
        "Approved": True,
        "Owner": "event_engine",
        "worker": WORKER_NAME,
        "Notes": f"Created from Supabase event {event_id}",
    }

    if capability == "http_exec":
        fields["URL"] = input_json.get("url")
        fields["HTTP_Method"] = input_json.get("method", "GET")
        fields["HTTP_Headers_JSON"] = json.dumps(input_json.get("headers", {}))

    return fields


def create_airtable_command(fields):
    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{urllib.parse.quote(AIRTABLE_COMMANDS_TABLE)}"

    payload = {"fields": fields}
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers=airtable_headers(),
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def mark_event_processed(event_id):
    query = urllib.parse.urlencode({
        "id": f"eq.{event_id}"
    })

    url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_EVENTS_TABLE}?{query}"

    payload = {
        "processed_at": now_iso(),
        "processed_by": "bosai-event-engine"
    }

    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers=supabase_headers(),
        method="PATCH"
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def main():
    require_env("SUPABASE_URL", SUPABASE_URL)
    require_env("SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY)
    require_env("AIRTABLE_API_KEY", AIRTABLE_API_KEY)
    require_env("AIRTABLE_BASE_ID", AIRTABLE_BASE_ID)

    events = fetch_events()

    print(f"Fetched events: {len(events)}")

    created = 0
    processed = 0
    failed = 0

    for event in events:

        event_id = event.get("id")

        try:
            fields = infer_command_from_event(event)

            cmd = create_airtable_command(fields)

            print(f"Created command for event {event_id} -> {cmd.get('id')}")

            created += 1

            mark_event_processed(event_id)

            print(f"Marked processed {event_id}")

            processed += 1

        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="ignore")
            print(f"HTTP error {e.code} for event {event_id}: {err}")
            failed += 1

        except Exception as e:
            print(f"Error for event {event_id}: {e}")
            failed += 1

    print(json.dumps({
        "ok": True,
        "fetched": len(events),
        "created": created,
        "processed": processed,
        "failed": failed
    }))


if __name__ == "__main__":
    main()
