from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Deque, Dict
from collections import deque

@dataclass
class RunStat:
    ts: float
    status: str       # OK / ERROR / DUPLICATE / REJECTED
    duration_ms: int

class HealthEngine:
    """
    Score 0..100 basé sur les runs récents.
    - erreurs = pénalité forte
    - duplicates = pénalité légère
    - durée très haute = pénalité
    """
    def __init__(self, window_size: int = 50) -> None:
        self.window_size = window_size
        self.runs: Deque[RunStat] = deque(maxlen=window_size)
        self.started_at = time.time()

    def record(self, status: str, duration_ms: int) -> None:
        self.runs.append(RunStat(ts=time.time(), status=status, duration_ms=duration_ms))

    def score(self) -> int:
        if not self.runs:
            return 100

        ok = sum(1 for r in self.runs if r.status == "OK")
        err = sum(1 for r in self.runs if r.status == "ERROR")
        dup = sum(1 for r in self.runs if r.status == "DUPLICATE")
        rej = sum(1 for r in self.runs if r.status == "REJECTED")

        avg_ms = int(sum(r.duration_ms for r in self.runs) / max(1, len(self.runs)))

        score = 100
        score -= err * 20
        score -= rej * 10
        score -= dup * 3

        # Perf penalty
        if avg_ms > 2000:
            score -= 10
        if avg_ms > 5000:
            score -= 15

        if score < 0:
            score = 0
        if score > 100:
            score = 100
        return score

    def snapshot(self) -> Dict:
        up_s = int(time.time() - self.started_at)
        return {
            "score": self.score(),
            "window": len(self.runs),
            "uptime_seconds": up_s,
            "recent": {
                "ok": sum(1 for r in self.runs if r.status == "OK"),
                "error": sum(1 for r in self.runs if r.status == "ERROR"),
                "duplicate": sum(1 for r in self.runs if r.status == "DUPLICATE"),
                "rejected": sum(1 for r in self.runs if r.status == "REJECTED"),
            },
            "avg_duration_ms": int(sum(r.duration_ms for r in self.runs) / max(1, len(self.runs))) if self.runs else 0,
        }
