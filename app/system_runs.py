from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.config import env, APP_NAME, APP_VERSION, WORKER_NAME
from app.airtable_client import AirtableClient


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SystemRun:
    command_id: str
    capability: str
    idempotency_key: str
    env_name: str
    priority: int

    status: str = "running"          # running | ok | error
    http_status: int = 200
    is_bad: bool = False

    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None

    payload_json: Optional[Dict[str, Any]] = None
    result_json: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class SystemRunsWriter:
    """
    Robust writer:
    - never crashes the worker
    - supports create + update (if AirtableClient has update_record)
    - linked record field is configurable (default: Commands)
    """

    def __init__(self):
        self.airtable = AirtableClient()
        self.table_id = env("SYSTEM_RUNS_TABLE_ID")
        self.command_link_field = env("SYSTEM_RUNS_COMMAND_LINK_FIELD", "Commands")

    def _fields(self, run: SystemRun) -> Dict[str, Any]:
        started_at = run.started_at or iso_now()
        fields: Dict[str, Any] = {
            # Linked record => list of rec ids
            self.command_link_field: [run.command_id],

            "Worker_Name": WORKER_NAME,
            "App": APP_NAME,
            "Version": APP_VERSION,

            "Env": run.env_name,
            "Priority": int(run.priority),
            "Idempotency_Key": run.idempotency_key,

            "Capability": run.capability,
            "Status": run.status,

            "Started_At": started_at,
            "HTTP_Status": int(run.http_status),
            "Is_Bad": bool(run.is_bad),
        }

        if run.finished_at:
            fields["Finished_At"] = run.finished_at
        if run.duration_ms is not None:
            fields["Duration_ms"] = int(run.duration_ms)
        if run.payload_json is not None:
            fields["Payload_JSON"] = run.payload_json
        if run.result_json is not None:
            fields["Result_JSON"] = run.result_json
        if run.error_message:
            fields["Error_Message"] = run.error_message

        return fields

    def create(self, run: SystemRun) -> Optional[str]:
        try:
            print(f"Writing to Airtable: create System_Run {run.command_id} ({run.status})")
            rec = self.airtable.create_record(self.table_id, self._fields(run))
            if isinstance(rec, dict):
                return rec.get("id")
            return str(rec) if rec else None
        except Exception as e:
            print(f"WARN: System_Runs create failed: {e}")
            return None

    def update(self, run_id: str, run: SystemRun) -> bool:
        try:
            # If client supports update_record, use it. Else fallback false.
            updater = getattr(self.airtable, "update_record", None)
            if not callable(updater):
                return False
            print(f"Writing to Airtable: update System_Run {run_id} ({run.status})")
            updater(self.table_id, run_id, self._fields(run))
            return True
        except Exception as e:
            print(f"WARN: System_Runs update failed: {e}")
            return False
