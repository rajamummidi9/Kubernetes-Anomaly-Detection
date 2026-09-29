from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


class SignalType(str, Enum):
    cpu = "cpu"
    memory = "memory"
    error_rate = "error_rate"
    latency = "latency"
    restarts = "restarts"
    traffic = "traffic"
    deployment = "deployment"
    node_pressure = "node_pressure"
    oom = "oom"


class MetricPoint(BaseModel):
    timestamp: datetime
    value: float


class MetricSeries(BaseModel):
    name: str
    signal: SignalType
    namespace: str
    service: str
    labels: dict[str, str] = Field(default_factory=dict)
    points: list[MetricPoint] = Field(default_factory=list)

    @property
    def values(self) -> list[float]:
        return [p.value for p in self.points]


class AnomalySignal(BaseModel):
    signal: SignalType
    namespace: str
    service: str
    observed: float
    expected_mean: float
    expected_std: float
    z_score: float
    contribution: float
    message: str
    labels: dict[str, str] = Field(default_factory=dict)


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    namespace: str
    service: str
    score: float
    severity: Severity
    signals: list[AnomalySignal] = Field(default_factory=list)
    narrative: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_alert(self) -> bool:
        return self.score >= 70


class EvaluationResult(BaseModel):
    evaluated_at: datetime = Field(default_factory=utcnow)
    series_count: int
    anomaly_count: int
    incident_count: int
    incidents: list[Incident] = Field(default_factory=list)
    anomalies: list[AnomalySignal] = Field(default_factory=list)
