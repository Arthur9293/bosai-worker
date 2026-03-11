from __future__ import annotations

from typing import Any, Dict


def run(req: Any, run_record_id: str) -> Dict[str, Any]:
    return {
        "ok": True,
        "capability": "commands_tick",
        "run_record_id": run_record_id,
        "input": getattr(req, "input", {}) or {},
    }
