import json
import time
from collections import deque
from typing import Any, Deque, Dict, Optional, Tuple


DEFAULT_CONFIG: Dict[str, Any] = {
    "max_events_per_minute": 50,
    "payload_size_limit": 4096,
    "blocked_sources": [],
}


def build_chaos_guard_config(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    config = dict(DEFAULT_CONFIG)

    if isinstance(overrides, dict):
        config.update(overrides)

    try:
        config["max_events_per_minute"] = int(config.get("max_events_per_minute", 50))
    except Exception:
        config["max_events_per_minute"] = 50

    if config["max_events_per_minute"] <= 0:
        config["max_events_per_minute"] = 50

    try:
        config["payload_size_limit"] = int(config.get("payload_size_limit", 4096))
    except Exception:
        config["payload_size_limit"] = 4096

    if config["payload_size_limit"] <= 0:
        config["payload_size_limit"] = 4096

    blocked_sources = config.get("blocked_sources", [])
    if not isinstance(blocked_sources, list):
        blocked_sources = []

    config["blocked_sources"] = [
        str(item).strip()
        for item in blocked_sources
        if str(item).strip()
    ]

    return config


class ChaosGuard:
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = build_chaos_guard_config(config)
        self.event_window: Deque[float] = deque()

    def check_event_rate(self) -> Tuple[bool, Optional[str]]:
        now = time.time()

        while self.event_window and (now - self.event_window[0] > 60):
            self.event_window.popleft()

        if len(self.event_window) >= self.config["max_events_per_minute"]:
            return False, "rate_limit_exceeded"

        self.event_window.append(now)
        return True, None

    def check_payload_size(self, payload: Any) -> Tuple[bool, Optional[str]]:
        try:
            payload_text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            payload_text = str(payload)

        if len(payload_text) > self.config["payload_size_limit"]:
            return False, "payload_too_large"

        return True, None

    def check_source(self, source: Any) -> Tuple[bool, Optional[str]]:
        source_text = str(source or "").strip()

        if source_text in self.config["blocked_sources"]:
            return False, "source_blocked"

        return True, None

    def validate_event(self, event: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if not isinstance(event, dict):
            return False, "event_not_dict"

        checks = (
            self.check_event_rate(),
            self.check_payload_size(event.get("payload")),
            self.check_source(event.get("source")),
        )

        for ok, reason in checks:
            if not ok:
                return False, reason

        return True, None
