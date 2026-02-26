from __future__ import annotations

from typing import Any, Dict

DEFAULTS = {
    "sla_machine": 1,
    "health_tick": 5,
}

class PriorityEngine:
    def compute(self, capability: str, payload: Dict[str, Any] | None) -> int:
        # 1) override direct
        if isinstance(payload, dict):
            p = payload.get("priority")
            if isinstance(p, int):
                return max(0, min(10, p))

        # 2) defaults by capability
        return DEFAULTS.get(capability, 3)
