from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class DecisionInput(BaseModel):
    event_id: str = ""
    event_type: str = ""
    source: str = ""
    payload: Dict[str, Any] = Field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3


class DecisionResult(BaseModel):
    decision: str
    capability: Optional[str] = None
    priority: int = 1
    blocked: bool = False
    reason: str = ""
    rejected_reason: str = ""
    delay_seconds: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)
