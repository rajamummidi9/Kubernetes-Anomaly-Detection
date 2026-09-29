from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    source: str
    observation: str


class Action(BaseModel):
    priority: Literal["now", "next", "later"]
    title: str
    rationale: str
    command: str = ""
    risk: str = ""


class RootCause(BaseModel):
    title: str
    confidence: Literal["low", "medium", "high"]
    hypothesis: str
    evidence: list[Evidence] = Field(default_factory=list)
    disconfirming_checks: list[str] = Field(default_factory=list)


class IntelligenceResult(BaseModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    provider: str
    model: str
    summary: str
    situation: Literal["healthy", "watch", "incident"]
    root_causes: list[RootCause] = Field(default_factory=list)
    predicted_risks: list[str] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    alert_title: str
    alert_body: str
    limitations: list[str] = Field(default_factory=list)
    cached: bool = False


class Prediction(BaseModel):
    id: str
    severity: Literal["info", "warning", "critical"]
    title: str
    probability: Literal["low", "medium", "high"]
    horizon: str
    evidence: list[str]
    recommendation: str


class IntelligenceStatus(BaseModel):
    enabled: bool
    provider: str = ""
    model: str = ""
    auto_run: bool = False
    status: str
