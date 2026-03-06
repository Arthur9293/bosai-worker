import time
from collections import deque

class ChaosGuard:
    def __init__(self, config):
        self.config = config
        self.event_window = deque()

    def check_event_rate(self):
        now = time.time()
        while self.event_window and now - self.event_window[0] > 60:
            self.event_window.popleft()

        if len(self.event_window) >= self.config["max_events_per_minute"]:
            return False, "Rate limit exceeded"

        self.event_window.append(now)
        return True, None

    def check_payload_size(self, payload):
        if len(str(payload)) > self.config["payload_size_limit"]:
            return False, "Payload too large"
        return True, None

    def check_source(self, source):
        if source in self.config["blocked_sources"]:
            return False, "Source blocked"
        return True, None

    def validate_event(self, event):
        checks = [
            self.check_event_rate(),
            self.check_payload_size(event.get("payload")),
            self.check_source(event.get("source"))
        ]

        for ok, reason in checks:
            if not ok:
                return False, reason

        return True, None
