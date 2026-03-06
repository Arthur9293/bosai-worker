import os
import requests
import json
from datetime import datetime

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

AIRTABLE_BASE = os.environ["AIRTABLE_BASE_ID"]
AIRTABLE_TABLE = "Commands"
AIRTABLE_TOKEN = os.environ["AIRTABLE_TOKEN"]

def fetch_events():

    url = f"{SUPABASE_URL}/rest/v1/bosai_events"

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}"
    }

    params = {
        "processed_at": "is.null",
        "order": "created_at.asc",
        "limit": 25
    }

    r = requests.get(url, headers=headers, params=params)
    return r.json()


def create_command(event):

    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE}/{AIRTABLE_TABLE}"

    headers = {
        "Authorization": f"Bearer {AIRTABLE_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "fields": {
            "Capability": "http_exec",
            "Status_select": "Queue",
            "URL": event["payload"].get("url"),
            "HTTP_Method": event["payload"].get("method", "GET"),
            "Input_JSON": json.dumps(event["payload"]),
            "Idempotency_Key": event["id"]
        }
    }

    requests.post(url, headers=headers, json=payload)


def mark_processed(event_id):

    url = f"{SUPABASE_URL}/rest/v1/bosai_events?id=eq.{event_id}"

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "processed_at": datetime.utcnow().isoformat(),
        "processed_by": "event_engine"
    }

    requests.patch(url, headers=headers, json=payload)


def main():

    events = fetch_events()

    for event in events:

        create_command(event)
        mark_processed(event["id"])


if __name__ == "__main__":
    main()
