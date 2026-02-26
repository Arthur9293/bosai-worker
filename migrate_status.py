import os, requests

API_KEY = os.environ["AIRTABLE_API_KEY"]
BASE_ID = os.environ["AIRTABLE_BASE_ID"]
TABLE_NAME = os.environ.get("SYSTEM_RUNS_TABLE_NAME", "System_Runs")

url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_NAME}"
headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

def norm(v: str) -> str:
    if not v: return "queued"
    s = v.strip().lower()
    if s in ("ok", "done", "completed", "success"): return "success"
    if s in ("fail", "failed", "error", "err"): return "error"
    if s in ("running", "in_progress", "in progress"): return "running"
    if s in ("queued", "pending"): return "queued"
    if s in ("canceled", "cancelled"): return "canceled"
    return "queued"

offset = None
while True:
    params = {"pageSize": 100}
    if offset: params["offset"] = offset

    r = requests.get(url, headers=headers, params=params)
    r.raise_for_status()
    data = r.json()

    records = data.get("records", [])
    if not records:
        break

    updates = []
    for rec in records:
        fields = rec.get("fields", {})
        raw = fields.get("Status")
        updates.append({
            "id": rec["id"],
            "fields": {
                "Status_raw": raw if raw is not None else "",
                "Status_select": norm(raw or "")
            }
        })

    # Airtable: max 10 records per PATCH
    for i in range(0, len(updates), 10):
        payload = {"records": updates[i:i+10]}
        ur = requests.patch(url, headers=headers, json=payload)
        ur.raise_for_status()
        print("updated", i, "to", i + len(payload["records"]))

    offset = data.get("offset")
    if not offset:
        break

print("Migration finished.")
