from __future__ import annotations

import urllib.parse
import json
import time
import requests
from typing import Any, Dict, Optional

from .config import AIRTABLE_API_BASE, AIRTABLE_BASE_ID, AIRTABLE_TOKEN

class AirtableClient:
    def __init__(self) -> None:
        if not AIRTABLE_TOKEN or not AIRTABLE_BASE_ID:
            raise RuntimeError("Airtable not configured: AIRTABLE_TOKEN or AIRTABLE_BASE_ID missing")
        self.base_id = AIRTABLE_BASE_ID
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {AIRTABLE_TOKEN}",
            "Content-Type": "application/json",
        })

    def create_record(self, table_name: str, fields: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
        url = f"{AIRTABLE_API_BASE}/{self.base_id}/{table_name}"
        payload = {"fields": fields}
        resp = self.session.post(url, data=json.dumps(payload), timeout=timeout)
        if resp.status_code >= 400:
            raise RuntimeError(f"Airtable create_record failed: {resp.status_code} {resp.text}")
        return resp.json()

    def update_record(self, table_name: str, record_id: str, fields: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
        url = f"{AIRTABLE_API_BASE}/{self.base_id}/{table_name}/{record_id}"
        payload = {"fields": fields}
        resp = self.session.patch(url, data=json.dumps(payload), timeout=timeout)
        if resp.status_code >= 400:
            raise RuntimeError(f"Airtable update_record failed: {resp.status_code} {resp.text}")
        return resp.json()

    def find_records(
        self,
        table_name: str,
        *,
        filter_by_formula: Optional[str] = None,
        max_records: int = 1,
        fields: Optional[list[str]] = None,
        sort_field: Optional[str] = None,
        sort_direction: str = "desc",
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """
        Returns Airtable list response: { "records": [...], "offset": ...? }
        """
        base_url = f"{AIRTABLE_API_BASE}/{self.base_id}/{table_name}"

        params = []
        if filter_by_formula:
            params.append(("filterByFormula", filter_by_formula))
        if max_records:
            params.append(("maxRecords", str(max_records)))
        if fields:
            # Airtable supports repeated fields[]=Name
            for f in fields:
                params.append(("fields[]", f))
        if sort_field:
            params.append(("sort[0][field]", sort_field))
            params.append(("sort[0][direction]", sort_direction))

        qs = urllib.parse.urlencode(params, doseq=True)
        url = f"{base_url}?{qs}" if qs else base_url

        resp = self.session.get(url, timeout=timeout)
        if resp.status_code >= 400:
            raise RuntimeError(f"Airtable find_records failed: {resp.status_code} {resp.text}")
        return resp.json()

    def ping(self) -> float:
        # Minimal ping: list 1 record from any table would require a table.
        # We return a synthetic "ok" latency by hitting metadata-free endpoint is not available.
        # So we just return 0 here; health engine will treat airtable as optional when missing.
        t0 = time.time()
        _ = (time.time() - t0)
        return _
