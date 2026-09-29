from __future__ import annotations

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from anomaly_detection.advisors import build_advisors
from anomaly_detection.config import Settings
from anomaly_detection.insights.index import ClusterIndex, Resources
from anomaly_detection.insights.model import SEVERITY_RANK, Category, Insight
from anomaly_detection.insights.rules import RULES, Thresholds, age, cores, event_rows, gib, pct
from anomaly_detection.insights.vectors import build_vectors
from anomaly_detection.k8s.client import KubeClientFactory
from anomaly_detection.k8s.snapshot import ClusterSnapshot, fetch_snapshot

PENALTY = {"critical": 20, "warning": 8, "info": 2}
# Caps keep one noisy severity from zeroing a category.
PENALTY_CAP = {"critical": 60, "warning": 35, "info": 10}
WEIGHTS = {
    Category.reliability: 0.35,
    Category.capacity: 0.25,
    Category.efficiency: 0.15,
    Category.security: 0.15,
    Category.configuration: 0.10,
}
POOL_LABELS = (
    "agentpool",
    "kubernetes.azure.com/agentpool",
    "eks.amazonaws.com/nodegroup",
    "cloud.google.com/gke-nodepool",
    "karpenter.sh/nodepool",
)


def grade(score: int) -> str:
    for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return letter
    return "F"


def _res(r: Resources) -> dict[str, float]:
    return {"cpu": round(r.cpu, 3), "memory": r.memory}


def build_report(snapshot: ClusterSnapshot, settings: Settings) -> dict[str, Any]:
    thresholds = Thresholds(
        window=timedelta(hours=settings.event_window_hours),
        node_warn=settings.node_warn_percent,
        node_crit=settings.node_critical_percent,
    )
    idx = ClusterIndex(snapshot, settings.system_namespace_set)
    insights: list[Insight] = []
    rule_errors: list[str] = []
    for rule in RULES:
        try:
            insights.extend(rule(idx, thresholds))
        except Exception as exc:  # noqa: BLE001 - one bad rule must not hide the rest
            rule_errors.append(f"{rule.__name__}: {type(exc).__name__}: {exc}")
    insights.sort(key=lambda i: (SEVERITY_RANK[i.severity], -i.affected_count))

    scores = _scores(insights)
    return {
        "meta": {
            "context": snapshot.context,
            "server_version": snapshot.server_version,
            "generated_at": snapshot.collected_at.isoformat(),
            "window_hours": settings.event_window_hours,
            "metrics_available": snapshot.metrics_available,
            "coverage": snapshot.coverage,
            "rule_errors": rule_errors,
        },
        "scores": scores,
        "summary": _summary(idx, insights),
        "capacity": _capacity(idx),
        "quick_wins": _quick_wins(insights),
        "advisors": build_advisors(snapshot, insights, settings.system_namespace_set),
        "vectors": build_vectors(insights, settings),
        "insights": [i.to_dict() for i in insights],
        "nodes": _nodes(idx),
        "namespaces": _namespaces(idx, insights),
        "top_pods": _top_pods(idx),
        "pod_catalog": _pod_catalog(idx),
        "events": event_rows(idx, thresholds)[:100],
    }


def _scores(insights: list[Insight]) -> dict[str, Any]:
    categories = {}
    for cat in Category:
        items = [i for i in insights if i.category == cat]
        categories[cat.value] = {
            "score": _category_score(items),
            "critical": sum(i.severity == "critical" for i in items),
            "warning": sum(i.severity == "warning" for i in items),
            "info": sum(i.severity == "info" for i in items),
        }
    overall = round(sum(WEIGHTS[c] * categories[c.value]["score"] for c in Category))
    if any(i.severity == "critical" and i.category == Category.reliability for i in insights):
        overall = min(overall, 69)
    return {"overall": overall, "grade": grade(overall), "categories": categories}


def _category_score(items: list[Insight]) -> int:
    penalty = 0
    for severity, weight in PENALTY.items():
        count = sum(i.severity == severity for i in items)
        penalty += min(PENALTY_CAP[severity], count * weight)
    return max(0, 100 - penalty)


def _summary(idx: ClusterIndex, insights: list[Insight]) -> dict[str, Any]:
    active = idx.active_pods
    return {
        "nodes": len(idx.nodes),
        "nodes_ready": sum(n.ready for n in idx.nodes.values()),
        "namespaces": len(idx.snapshot.namespaces),
        "pods": len(active),
        "pods_ready": sum(p.ready for p in active),
        "workloads": len(idx.snapshot.deployments) + len(idx.snapshot.statefulsets) + len(idx.snapshot.daemonsets),
        "critical": sum(i.severity == "critical" for i in insights),
        "warning": sum(i.severity == "warning" for i in insights),
        "info": sum(i.severity == "info" for i in insights),
    }


def _capacity(idx: ClusterIndex) -> dict[str, Any]:
    nodes = [n for n in idx.nodes.values() if n.ready]
    allocatable, capacity, usage = Resources(), Resources(), Resources()
    for n in nodes:
        allocatable += n.allocatable
        capacity += n.capacity
        if n.usage:
            usage += n.usage
    requests, limits = Resources(), Resources()
    for p in idx.active_pods:
        requests += p.requests
        limits += p.limits
    pod_capacity = sum(n.pod_capacity for n in nodes)
    notes = []
    for attr, label, fmt in (("memory", "Memory", gib), ("cpu", "CPU", cores)):
        used, req, lim, alloc = (getattr(x, attr) for x in (usage, requests, limits, allocatable))
        if req and pct(req, alloc) >= 70:
            notes.append(f"{label}: requests reserve {pct(req, alloc):.0f}% of allocatable, so the scheduler treats the cluster as {'nearly ' if pct(req, alloc) < 95 else ''}full.")
        if idx.snapshot.metrics_available and used and req < used * 0.5:
            notes.append(f"{label}: pods request {fmt(req)} but use {fmt(used)}, so the scheduler sees the cluster as mostly empty.")
        if lim > alloc:
            notes.append(f"{label}: limits are overcommitted at {pct(lim, alloc):.0f}% of allocatable.")
        if used and pct(used, alloc) >= 80:
            notes.append(f"{label}: {pct(used, alloc):.0f}% of allocatable is in use; headroom is thin.")
    return {
        "cpu": {"usage": usage.cpu, "requests": requests.cpu, "limits": limits.cpu,
                "allocatable": allocatable.cpu, "capacity": capacity.cpu},
        "memory": {"usage": usage.memory, "requests": requests.memory, "limits": limits.memory,
                   "allocatable": allocatable.memory, "capacity": capacity.memory},
        "pods": {"usage": len(idx.active_pods), "allocatable": pod_capacity},
        "notes": notes,
    }


def _quick_wins(insights: list[Insight]) -> list[dict[str, Any]]:
    ranked = sorted(
        (i for i in insights if i.severity != "info" or len(insights) < 5),
        key=lambda i: (SEVERITY_RANK[i.severity], -i.affected_count),
    )
    return [
        {"id": i.id, "severity": i.severity, "category": i.category.value, "title": i.title,
         "action": i.recommendation, "fix": i.fix}
        for i in ranked[:6]
    ]


def _nodes(idx: ClusterIndex) -> list[dict[str, Any]]:
    rows = []
    for n in idx.nodes.values():
        labels = n.node.metadata.labels or {}
        created = n.node.metadata.creation_timestamp
        rows.append({
            "name": n.name,
            "ready": n.ready,
            "unschedulable": n.unschedulable,
            "pool": next((labels[k] for k in POOL_LABELS if k in labels), ""),
            "instance_type": labels.get("node.kubernetes.io/instance-type", ""),
            "zone": labels.get("topology.kubernetes.io/zone", ""),
            "kubelet": n.node.status.node_info.kubelet_version,
            "age": age(idx.now - created) if created else "",
            "pressure": n.pressure,
            "taints": len(n.node.spec.taints or []),
            "allocatable": _res(n.allocatable),
            "usage": _res(n.usage) if n.usage else None,
            "requests": _res(n.requests),
            "limits": _res(n.limits),
            "pods": n.pods,
            "pod_capacity": n.pod_capacity,
        })
    return sorted(rows, key=lambda r: (r["usage"] or {}).get("memory", 0) / max(r["allocatable"]["memory"], 1), reverse=True)


def _namespaces(idx: ClusterIndex, insights: list[Insight]) -> list[dict[str, Any]]:
    stats: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "pods": 0, "not_ready": 0, "restarts": 0, "usage": Resources(), "requests": Resources(),
        "critical": 0, "warning": 0, "info": 0,
    })
    for p in idx.active_pods:
        row = stats[p.namespace]
        row["pods"] += 1
        row["not_ready"] += 0 if p.ready or p.phase == "Succeeded" else 1
        row["restarts"] += p.restarts
        row["requests"] += p.requests
        if p.usage:
            row["usage"] += p.usage
    for insight in insights:
        for ns in {a.namespace for a in insight.affected if a.namespace}:
            stats[ns][insight.severity] += 1
    rows = []
    for ns, row in stats.items():
        score = max(0, 100 - sum(
            min(PENALTY_CAP[s], row[s] * PENALTY[s]) for s in PENALTY
        ))
        rows.append({
            "namespace": ns, "system": idx.is_system(ns), "score": score,
            "pods": row["pods"], "not_ready": row["not_ready"], "restarts": row["restarts"],
            "usage": _res(row["usage"]), "requests": _res(row["requests"]),
            "critical": row["critical"], "warning": row["warning"], "info": row["info"],
        })
    return sorted(rows, key=lambda r: (r["score"], -r["usage"]["memory"]))


def _top_pods(idx: ClusterIndex, limit: int = 25) -> list[dict[str, Any]]:
    measured = [p for p in idx.active_pods if p.usage]
    measured.sort(key=lambda p: p.usage.memory, reverse=True)
    return [{
        "namespace": p.namespace, "name": p.name, "workload": f"{p.workload_kind}/{p.workload_name}",
        "node": p.node, "restarts": p.restarts, "ready": p.ready,
        "usage": _res(p.usage), "requests": _res(p.requests), "limits": _res(p.limits),
        "qos": p.pod.status.qos_class or "",
    } for p in measured[:limit]]


def _pod_catalog(idx: ClusterIndex) -> list[dict[str, Any]]:
    """Compact live resources for every active pod, so chat can answer by name."""
    rows = []
    for p in idx.active_pods:
        usage = p.usage
        rows.append({
            "namespace": p.namespace,
            "name": p.name,
            "workload": f"{p.workload_kind}/{p.workload_name}",
            "node": p.node,
            "phase": p.phase,
            "ready": p.ready,
            "restarts": p.restarts,
            "cpu_cores": {
                "used": None if usage is None else round(usage.cpu, 3),
                "requested": round(p.requests.cpu, 3),
                "limit": round(p.limits.cpu, 3) or None,
            },
            "memory_mib": {
                "used": None if usage is None else round(usage.memory / (1024 ** 2)),
                "requested": round(p.requests.memory / (1024 ** 2)),
                "limit": round(p.limits.memory / (1024 ** 2)) or None,
            },
        })
    return rows


def to_markdown(report: dict[str, Any]) -> str:
    meta, scores, summary = report["meta"], report["scores"], report["summary"]
    lines = [
        f"# Cluster health report: {meta['context']}",
        "",
        f"Generated {meta['generated_at']} · Kubernetes {meta['server_version'] or 'unknown'}",
        "",
        f"**Score {scores['overall']}/100 (grade {scores['grade']})** · "
        f"{summary['nodes_ready']}/{summary['nodes']} nodes ready · "
        f"{summary['pods_ready']}/{summary['pods']} pods ready · "
        f"{summary['critical']} critical, {summary['warning']} warning, {summary['info']} info",
        "",
        "| Category | Score | Critical | Warning | Info |",
        "|---|---|---|---|---|",
    ]
    for name, cat in scores["categories"].items():
        lines.append(f"| {name} | {cat['score']} | {cat['critical']} | {cat['warning']} | {cat['info']} |")
    if report["capacity"]["notes"]:
        lines += ["", "## Capacity", ""] + [f"- {n}" for n in report["capacity"]["notes"]]
    lines += ["", "## Top actions", ""]
    for i, win in enumerate(report["quick_wins"], 1):
        lines.append(f"{i}. **[{win['severity']}] {win['title']}**: {win['action']}")
    lines += _advisor_markdown(report.get("advisors") or {})
    lines += ["", "## All findings", ""]
    for ins in report["insights"]:
        lines += [
            f"### [{ins['severity']}] {ins['title']}",
            "",
            f"{ins['summary']}",
            "",
            f"- **Impact:** {ins['impact']}",
            f"- **Fix:** {ins['recommendation']}",
        ]
        if ins["fix"]:
            lines += ["", "```", ins["fix"], "```"]
        if ins["affected"]:
            lines += ["", "Affected:"]
            for a in ins["affected"][:15]:
                target = "/".join(x for x in (a["namespace"], a["name"]) if x)
                lines.append(f"- `{target}` {a['detail']}")
            if ins["affected_count"] > 15:
                lines.append(f"- …and {ins['affected_count'] - 15} more")
        lines.append("")
    return "\n".join(lines)


def _advisor_markdown(advisors: dict[str, Any]) -> list[str]:
    if not advisors:
        return []
    lines = ["", "## Advisors", ""]
    security = advisors.get("security") or {}
    if security:
        lines += [f"### Security ({security.get('posture', '')})", "", security.get("summary", ""), ""]
        for item in security.get("items") or []:
            lines.append(f"- **[{item['severity']}] {item['title']}** {item['advice']}")
    upgrades = advisors.get("upgrades") or {}
    if upgrades:
        lines += ["", f"### Upgrades ({upgrades.get('status', '')})", "", upgrades.get("headline", ""), ""]
        for step in upgrades.get("plan") or []:
            lines.append(f"- **{step['title']}** {step['detail']}")
    cases = advisors.get("investigations") or []
    lines += ["", "### Investigations", ""]
    if not cases:
        lines.append("No correlated incident is active.")
    for case in cases:
        lines += [
            f"- **[{case['severity']}] {case['title']}** ({case['confidence']} confidence)",
            f"  - Likely cause: {case['likely_cause']}",
        ]
        for check in case.get("checks") or []:
            lines.append(f"  - Check: `{check}`")
    return lines


class ClusterAnalyzer:
    """Caches one report per context so page refreshes don't hammer the API server."""

    def __init__(self, settings: Settings, ttl_seconds: int = 30):
        self.settings = settings
        self.clients = KubeClientFactory(settings)
        self.ttl = ttl_seconds
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def analyze(self, context: str | None = None, force: bool = False) -> dict[str, Any]:
        started = time.monotonic()
        try:
            api, name = self.clients.get(context)
        except Exception as exc:  # noqa: BLE001
            return self._error(context or "unknown", exc)
        with self._lock:
            cached = self._cache.get(name)
            if cached and not force and time.monotonic() - cached[0] < self.ttl:
                return cached[1]
        snapshot = fetch_snapshot(api, name)
        if snapshot.coverage.get("pods") != "ok" and snapshot.coverage.get("nodes") != "ok":
            return self._error(name, RuntimeError(
                f"pods: {snapshot.coverage.get('pods')}; nodes: {snapshot.coverage.get('nodes')}"
            ))
        report = build_report(snapshot, self.settings)
        report["meta"]["connected"] = True
        report["meta"]["duration_ms"] = round((time.monotonic() - started) * 1000)
        with self._lock:
            self._cache[name] = (time.monotonic(), report)
        return report

    @staticmethod
    def _error(context: str, exc: Exception) -> dict[str, Any]:
        return {
            "meta": {
                "context": context,
                "connected": False,
                "error": f"{type(exc).__name__}: {exc}",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
        }
