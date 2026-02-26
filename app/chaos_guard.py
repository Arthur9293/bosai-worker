from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Tuple

from .config import CHAOS_GUARD_COOLDOWN_SECONDS


@dataclass
class GuardEntry:
    ts: float


class ChaosGuard:
    """
    Anti-duplicate (cooldown) based on idempotency_key
    + simple in-memory run lock per command_id

    - check(key) : keeps your current cooldown behavior
    - assert_can_run(command_id, idempotency_key) : used by worker.py
    - finalize(command_id, status, is_bad) : unlock
    """

    def __init__(self) -> None:
        self._seen: Dict[str, GuardEntry] = {}
        self._locks: Dict[str, str] = {}  # command_id -> idempotency_key

    def check(self, key: str) -> Tuple[bool, int]:
        now = time.time()

        # cleanup light
        cutoff = now - (CHAOS_GUARD_COOLDOWN_SECONDS * 2)
        for k in list(self._seen.keys()):
            if self._seen[k].ts < cutoff:
                del self._seen[k]

        if key in self._seen:
            age = now - self._seen[key].ts
            if age < CHAOS_GUARD_COOLDOWN_SECONDS:
                retry = int(CHAOS_GUARD_COOLDOWN_SECONDS - age)
                return (False, max(1, retry))

        self._seen[key] = GuardEntry(ts=now)
        return (True, 0)

    def assert_can_run(self, command_id: str, idempotency_key: str) -> None:
        # 1) cooldown on idempotency_key (keeps your stable behavior)
        allowed, retry_after_s = self.check(idempotency_key)
        if not allowed:
            raise RuntimeError(f"cooldown_active retry_after_s={retry_after_s}")

        # 2) in-memory lock by command_id (prevents concurrent runs)
        existing = self._locks.get(command_id)
        if existing is not None:
            if existing == idempotency_key:
                raise RuntimeError("duplicate_run_same_idempotency_key")
            raise RuntimeError("command_already_running")

        self._locks[command_id] = idempotency_key

    def finalize(self, command_id: str, status: str, is_bad: bool) -> None:
        # always unlock
        if command_id in self._locks:
            del self._locks[command_id]
