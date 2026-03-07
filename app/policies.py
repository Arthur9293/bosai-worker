import os
import json
from typing import Any, Dict


def get_policies() -> Dict[str, Any]:
    raw = os.getenv("BOSAI_POLICIES_JSON", "{}").strip()

    if not raw:
        return {}

    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}
