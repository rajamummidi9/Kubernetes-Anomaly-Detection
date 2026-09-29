"""Advisory layer: security, upgrades, and incident investigations."""

from __future__ import annotations

from datetime import date
from typing import Any

from anomaly_detection.advisors.rca import investigations
from anomaly_detection.advisors.security import security_advice, security_summary
from anomaly_detection.advisors.upgrades import upgrade_advice
from anomaly_detection.insights.model import Insight
from anomaly_detection.k8s.snapshot import ClusterSnapshot


def build_advisors(
    snapshot: ClusterSnapshot,
    insights: list[Insight],
    system_namespaces: set[str],
    today: date | None = None,
) -> dict[str, Any]:
    items = security_advice(snapshot, system_namespaces)
    posture, summary = security_summary(items)
    return {
        "security": {"posture": posture, "summary": summary, "items": items},
        "upgrades": upgrade_advice(snapshot, insights, today=today),
        "investigations": investigations(snapshot, insights),
    }
