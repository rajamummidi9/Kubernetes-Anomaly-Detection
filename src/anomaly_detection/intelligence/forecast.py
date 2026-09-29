from __future__ import annotations

import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Any

from anomaly_detection.intelligence.models import Prediction


class ReportHistory:
    """Bounded in-memory history used for short-horizon early warnings."""

    def __init__(self, max_points: int = 288):
        self._reports: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=max_points))
        self._lock = threading.Lock()

    def add(self, report: dict[str, Any]) -> None:
        meta = report.get("meta") or {}
        context = str(meta.get("context") or "unknown")
        point = _point(report)
        with self._lock:
            values = self._reports[context]
            if values and values[-1]["at"] == point["at"]:
                return
            values.append(point)

    def predictions(self, context: str) -> list[dict[str, Any]]:
        with self._lock:
            points = list(self._reports.get(context, ()))
        return [p.model_dump(mode="json") for p in predict(points)]

    def size(self, context: str) -> int:
        with self._lock:
            return len(self._reports.get(context, ()))


def _point(report: dict[str, Any]) -> dict[str, Any]:
    meta = report.get("meta") or {}
    cap = report.get("capacity") or {}
    summary = report.get("summary") or {}
    score = report.get("scores") or {}
    return {
        "at": meta.get("generated_at"),
        "score": score.get("overall", 0),
        "critical": summary.get("critical", 0),
        "warning": summary.get("warning", 0),
        "pods_ready": summary.get("pods_ready", 0),
        "pods": summary.get("pods", 0),
        "cpu_usage": _share(cap.get("cpu"), "usage"),
        "cpu_requests": _share(cap.get("cpu"), "requests"),
        "memory_usage": _share(cap.get("memory"), "usage"),
        "memory_requests": _share(cap.get("memory"), "requests"),
        "pod_density": _share(cap.get("pods"), "usage"),
    }


def _share(values: dict[str, Any] | None, field: str) -> float:
    values = values or {}
    total = float(values.get("allocatable") or 0)
    return (float(values.get(field) or 0) / total * 100) if total else 0.0


def predict(points: list[dict[str, Any]]) -> list[Prediction]:
    if not points:
        return []
    latest = points[-1]
    out: list[Prediction] = []
    out.extend(_capacity_risks(latest))
    if len(points) >= 3:
        out.extend(_trend_risks(points))
    if latest["critical"] > 0:
        out.append(Prediction(
            id="incident-active",
            severity="critical",
            title="An active incident can cascade before the next refresh",
            probability="high",
            horizon="now",
            evidence=[f"{latest['critical']} critical finding(s)", f"cluster score {latest['score']}/100"],
            recommendation="Resolve the top critical finding before making unrelated cluster changes.",
        ))
    return sorted(out, key=lambda p: {"critical": 0, "warning": 1, "info": 2}[p.severity])


def _capacity_risks(latest: dict[str, Any]) -> list[Prediction]:
    out = []
    for field, label in (
        ("memory_requests", "memory requests"),
        ("cpu_requests", "CPU requests"),
        ("memory_usage", "memory usage"),
        ("cpu_usage", "CPU usage"),
        ("pod_density", "pod slots"),
    ):
        value = latest[field]
        if value < 80:
            continue
        severity = "critical" if value >= 95 else "warning"
        out.append(Prediction(
            id=f"{field}-headroom",
            severity=severity,
            title=f"{label.capitalize()} leave little scale-out headroom",
            probability="high",
            horizon="next rollout or traffic spike",
            evidence=[f"{label} are {value:.0f}% of allocatable"],
            recommendation="Right-size the largest consumers or add capacity before the next rollout.",
        ))
    return out


def _trend_risks(points: list[dict[str, Any]]) -> list[Prediction]:
    out = []
    for field, label in (
        ("memory_usage", "Memory usage"),
        ("memory_requests", "Memory requests"),
        ("cpu_usage", "CPU usage"),
        ("pod_density", "Pod density"),
    ):
        first, last = points[0][field], points[-1][field]
        delta = last - first
        timestamps = [_parse(p["at"]) for p in points]
        if not timestamps[0] or not timestamps[-1]:
            continue
        hours = max((timestamps[-1] - timestamps[0]).total_seconds() / 3600, 1 / 60)
        rate = delta / hours
        if rate <= 0.5 or last >= 95:
            continue
        hours_to_90 = (90 - last) / rate
        if not 0 < hours_to_90 <= 24:
            continue
        out.append(Prediction(
            id=f"{field}-trend",
            severity="warning",
            title=f"{label} is trending toward 90%",
            probability="medium",
            horizon=f"about {max(1, round(hours_to_90))}h if the trend continues",
            evidence=[
                f"{first:.1f}% → {last:.1f}% over {hours:.1f}h",
                f"linear slope {rate:.1f} percentage points/hour",
            ],
            recommendation="Confirm the trend in Prometheus; identify the workload driving it before adding capacity.",
        ))
    return out


def _parse(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
