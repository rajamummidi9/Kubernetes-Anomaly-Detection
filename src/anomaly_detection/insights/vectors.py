"""Four detection domains and the signals this process can actually see."""

from __future__ import annotations

from typing import Any

from anomaly_detection.config import Settings
from anomaly_detection.insights.model import SEVERITY_RANK, Insight

VECTORS = (
    {
        "id": "security_runtime",
        "title": "Security and runtime",
        "focus": "Privilege, identity, and egress control",
        "detects": "Container breakout conditions, new admin identities, and namespaces where any external connection is allowed.",
        "insight_ids": {"privileged", "mutable-image-tag", "run-as-root", "open-egress", "new-admin-binding"},
        "blind_spots": [
            "Syscall sequences are not visible from the Kubernetes API. Add Falco or Tetragon for runtime exploits and breakouts.",
            "Individual pod-to-external-IP flows need Hubble, Cilium, or cloud flow logs.",
        ],
    },
    {
        "id": "performance",
        "title": "Performance and infrastructure",
        "focus": "Saturation, restarts, and scaling limits",
        "detects": "Restart loops, memory pressure, unavailable workloads, and autoscalers that cannot react.",
        "insight_ids": {
            "crashloop", "oom-killed", "recent-restarts", "workload-down", "workload-degraded",
            "node-memory-hot", "node-cpu-hot", "near-memory-limit", "hpa-maxed", "hpa-broken",
            "pending-pods",
        },
        "blind_spots": [
            "A memory leak is reported only after several snapshots show a rising slope in Early warnings.",
            "Transaction rate and latency drops need PROMETHEUS_URL and application RED metrics.",
        ],
    },
    {
        "id": "logs",
        "title": "Log and event patterns",
        "focus": "Repeated failures rather than one-off lines",
        "detects": "Hidden dependency failures and logic errors that surface as the same warning hundreds of times.",
        "insight_ids": {"repeating-errors", "event-backoff"},
        "blind_spots": [
            "Application log similarity needs LOKI_URL or your log store. This view uses Kubernetes warning events.",
        ],
    },
    {
        "id": "cost",
        "title": "Cost and capacity waste",
        "focus": "Requests, bursts, node growth, and batch fan-out",
        "detects": "Idle reservations, unbounded CPU, fast node provisioning, and jobs without a deadline.",
        "insight_ids": {
            "missing-requests", "overprovisioned", "unbounded-cpu", "node-provisioning",
            "runaway-jobs", "memory-requests-saturated", "cpu-requests-saturated",
        },
        "blind_spots": [
            "Cloud invoice data is not read. Node growth and unreserved CPU are the in-cluster signs of a bill shock.",
        ],
    },
)


def build_vectors(insights: list[Insight], settings: Settings) -> list[dict[str, Any]]:
    by_id = {item.id: item for item in insights}
    cards = []
    for spec in VECTORS:
        matched = [
            item for item in by_id.values()
            if item.id in spec["insight_ids"] or (spec["id"] == "logs" and item.id.startswith("event-"))
        ]
        findings = [
            {"id": item.id, "severity": item.severity, "title": item.title}
            for item in sorted(matched, key=lambda item: (SEVERITY_RANK[item.severity], item.id))
        ]
        active = any(item.severity in {"critical", "warning"} for item in matched)
        cards.append({
            "id": spec["id"],
            "title": spec["title"],
            "focus": spec["focus"],
            "detects": spec["detects"],
            "status": "watch" if active else "clear",
            "finding_count": len(findings),
            "findings": findings[:6],
            "blind_spots": list(spec["blind_spots"]),
            "enabled_sources": _sources(settings),
        })
    return cards


def _sources(settings: Settings) -> list[str]:
    sources = ["Kubernetes API"]
    if settings.prometheus_url or settings.mimir_url:
        sources.append("Prometheus-compatible metrics")
    if settings.loki_url:
        sources.append("Loki")
    return sources
