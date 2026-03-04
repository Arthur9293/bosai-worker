import os
import json
import time
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import requests


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    # Airtable accepte ISO 8601
    return dt.astimezone(timezone.utc).isoformat()


class AirtableClient:
    def __init__(self, api_key: str, base_id: str):
        self.api_key = api_key.strip()
        self.base_id = base_id.strip()
        if not self.api_key or not self.base_id:
            raise RuntimeError("AirtableClient: missing AIRTABLE_API_KEY or AIRTABLE_BASE_ID")
        self.base_url = f"https://api.airtable.com/v0/{self.base_id}"

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def list_records(
        self,
        table: str,
        filter_formula: Optional[str] = None,
        max_records: int = 100,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"pageSize": min(max_records, 100)}
        if filter_formula:
            params["filterByFormula"] = filter_formula

        out: List[Dict[str, Any]] = []
        offset: Optional[str] = None

        while True:
            if offset:
                params["offset"] = offset
            r = requests.get(f"{self.base_url}/{table}", headers=self._headers(), params=params, timeout=20)
            r.raise_for_status()
            data = r.json()
            out.extend(data.get("records", []))
            offset = data.get("offset")
            if not offset or len(out) >= max_records:
                break

        return out[:max_records]

    def get_record(self, table: str, record_id: str) -> Dict[str, Any]:
        r = requests.get(f"{self.base_url}/{table}/{record_id}", headers=self._headers(), timeout=20)
        r.raise_for_status()
        return r.json()

    def update_record(self, table: str, record_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        payload = {"fields": fields}
        r = requests.patch(f"{self.base_url}/{table}/{record_id}", headers=self._headers(), json=payload, timeout=20)
        r.raise_for_status()
        return r.json()


class Scheduler:
    """
    Scheduler Airtable:
    - prend les jobs due (Next_Run_At <= now) et non lockés
    - lock (Lock_Until + Lock_Token + Locked_By)
    - exécute via un callback (run_callback)
    - planifie Next_Run_At = now + Every_Minutes
    """

    def __init__(
        self,
        airtable: AirtableClient,
        table_name: str,
        worker_name: str,
        lock_seconds: int = 90,
        tick_max_jobs: int = 10,
    ):
        self.airtable = airtable
        self.table = table_name
        self.worker_name = worker_name
        self.lock_seconds = max(15, int(lock_seconds))
        self.tick_max_jobs = max(1, int(tick_max_jobs))

    def _safe_parse_json(self, s: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not s:
            return {}, None
        try:
            v = json.loads(s)
            if v is None:
                return {}, None
            if not isinstance(v, dict):
                return None, "Input_JSON must be a JSON object (dict)."
            return v, None
        except Exception as e:
            return None, f"Invalid JSON in Input_JSON: {e}"

    def _job_due_filter(self) -> str:
        # Airtable formula:
        # Enabled = 1
        # Next_Run_At is not blank and <= NOW()
        # Lock_Until is blank OR Lock_Until < NOW()
        return (
            "AND("
            "{Enabled}=1,"
            "NOT(IS_BLANK({Next_Run_At})),"
            "{Next_Run_At}<=NOW(),"
            "OR(IS_BLANK({Lock_Until}), {Lock_Until}<NOW())"
            ")"
        )

    def _acquire_lock(self, record_id: str) -> Optional[str]:
        token = secrets.token_urlsafe(16)
        until = utcnow() + timedelta(seconds=self.lock_seconds)

        # 1) tentative lock
        self.airtable.update_record(
            self.table,
            record_id,
            {
                "Lock_Until": iso(until),
                "Lock_Token": token,
                "Locked_By": self.worker_name,
            },
        )

        # 2) re-read pour vérifier qu’on a bien le token
        rec = self.airtable.get_record(self.table, record_id)
        fields = rec.get("fields", {})
        if fields.get("Lock_Token") != token:
            return None
        return token

    def _release_lock(self, record_id: str, token: str) -> None:
        # release “soft”: on vide Lock_Until si token match
        try:
            rec = self.airtable.get_record(self.table, record_id)
            fields = rec.get("fields", {})
            if fields.get("Lock_Token") != token:
                return
            self.airtable.update_record(
                self.table,
                record_id,
                {"Lock_Until": None, "Lock_Token": None, "Locked_By": None},
            )
        except Exception:
            # en cas d’erreur, le TTL expirera
            return

    def tick(self, run_callback) -> Dict[str, Any]:
        started = utcnow()
        processed: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        due = self.airtable.list_records(self.table, filter_formula=self._job_due_filter(), max_records=self.tick_max_jobs)

        for rec in due:
            rid = rec.get("id")
            fields = rec.get("fields", {}) or {}

            token = None
            try:
                token = self._acquire_lock(rid)
                if not token:
                    continue

                capability = (fields.get("Capability") or "").strip()
                every = fields.get("Every_Minutes")
                input_raw = fields.get("Input_JSON") or "{}"

                if not capability:
                    raise RuntimeError("Missing Capability")
                if every is None:
                    raise RuntimeError("Missing Every_Minutes")
                every_min = int(every)
                if every_min <= 0:
                    raise RuntimeError("Every_Minutes must be > 0")

                input_obj, err = self._safe_parse_json(input_raw)
                if err:
                    raise RuntimeError(err)

                # Run
                run_res = run_callback(capability=capability, input_obj=input_obj, job_record_id=rid)

                # Plan next
                now = utcnow()
                next_run = now + timedelta(minutes=every_min)

                self.airtable.update_record(
                    self.table,
                    rid,
                    {
                        "Last_Run_At": iso(now),
                        "Next_Run_At": iso(next_run),
                        "Last_Error": None,
                        "Last_Run_Linked_Run": run_res.get("run_record_id"),
                    },
                )

                processed.append(
                    {
                        "job_record_id": rid,
                        "capability": capability,
                        "ok": True,
                        "run_record_id": run_res.get("run_record_id"),
                    }
                )

            except Exception as e:
                try:
                    self.airtable.update_record(
                        self.table,
                        rid,
                        {"Last_Error": str(e)},
                    )
                except Exception:
                    pass

                errors.append({"job_record_id": rid, "ok": False, "error": str(e)})

            finally:
                if token:
                    self._release_lock(rid, token)

        ended = utcnow()
        return {
            "ok": True,
            "started_at": iso(started),
            "ended_at": iso(ended),
            "due_count": len(due),
            "processed_count": len(processed),
            "error_count": len(errors),
            "processed": processed,
            "errors": errors,
        }
