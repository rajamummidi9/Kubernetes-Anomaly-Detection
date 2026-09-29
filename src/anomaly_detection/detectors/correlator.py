from __future__ import annotations

from collections import defaultdict

from anomaly_detection.detectors.baseline import severity_from_score, soft_cap_contributions
from anomaly_detection.models import AnomalySignal, Incident, Severity


def correlate_incidents(anomalies: list[AnomalySignal]) -> list[Incident]:
    """Group anomalies by namespace/service and produce weighted incident scores."""
    grouped: dict[tuple[str, str], list[AnomalySignal]] = defaultdict(list)
    for a in anomalies:
        grouped[(a.namespace, a.service)].append(a)

    incidents: list[Incident] = []
    for (namespace, service), signals in grouped.items():
        score = soft_cap_contributions([s.contribution for s in signals])
        severity = Severity(severity_from_score(score))
        incidents.append(
            Incident(
                namespace=namespace,
                service=service,
                score=round(score, 1),
                severity=severity,
                signals=sorted(signals, key=lambda s: s.contribution, reverse=True),
                narrative=build_narrative(namespace, service, score, signals),
            )
        )

    return sorted(incidents, key=lambda i: i.score, reverse=True)


def build_narrative(
    namespace: str,
    service: str,
    score: float,
    signals: list[AnomalySignal],
) -> str:
    if not signals:
        return f"No anomalies for {namespace}/{service}."

    top = signals[0]
    parts = [
        f"High-confidence anomaly on {namespace}/{service} "
        f"(incident score {score:.0f}/100)."
        if score >= 70
        else f"Elevated signals on {namespace}/{service} (score {score:.0f}/100)."
    ]
    parts.append(top.message)

    others = signals[1:4]
    if others:
        joined = "; ".join(
            f"{s.signal.value} z={s.z_score:.1f} (+{s.contribution:.0f})" for s in others
        )
        parts.append(f"Also correlated: {joined}.")

    deployment = next((s for s in signals if s.signal.value == "deployment"), None)
    if deployment:
        parts.append(
            "A recent deployment may be related — investigate the latest rollout first."
        )

    return " ".join(parts)
