from __future__ import annotations

import math
import random
from datetime import datetime, timedelta, timezone

from anomaly_detection.models import MetricPoint, MetricSeries, SignalType


def _series(
    *,
    signal: SignalType,
    namespace: str,
    service: str,
    values: list[float],
    start: datetime | None = None,
    step_minutes: int = 5,
) -> MetricSeries:
    start = start or datetime.now(timezone.utc) - timedelta(minutes=step_minutes * (len(values) - 1))
    points = [
        MetricPoint(timestamp=start + timedelta(minutes=step_minutes * i), value=v)
        for i, v in enumerate(values)
    ]
    return MetricSeries(
        name=signal.value,
        signal=signal,
        namespace=namespace,
        service=service,
        labels={"namespace": namespace, "service": service},
        points=points,
    )


def _baseline(n: int, center: float, noise: float, rng: random.Random) -> list[float]:
    return [max(0.0, center + rng.gauss(0, noise)) for _ in range(n)]


def generate_demo_series(seed: int = 42) -> list[MetricSeries]:
    """Synthetic multi-service metrics with a clear anomaly on svc01."""
    rng = random.Random(seed)
    history = 36  # ~3 hours at 5m
    series: list[MetricSeries] = []

    # Healthy service
    cpu = _baseline(history, 0.35, 0.02, rng)
    mem = _baseline(history, 400_000_000, 8_000_000, rng)
    err = _baseline(history, 0.01, 0.002, rng)
    lat = _baseline(history, 0.12, 0.01, rng)
    rps = _baseline(history, 120, 8, rng)
    restarts = [0.0] * history
    series.extend(
        [
            _series(signal=SignalType.cpu, namespace="prod", service="payments-api", values=cpu),
            _series(signal=SignalType.memory, namespace="prod", service="payments-api", values=mem),
            _series(signal=SignalType.error_rate, namespace="prod", service="payments-api", values=err),
            _series(signal=SignalType.latency, namespace="prod", service="payments-api", values=lat),
            _series(signal=SignalType.traffic, namespace="prod", service="payments-api", values=rps),
            _series(signal=SignalType.restarts, namespace="prod", service="payments-api", values=restarts),
        ]
    )

    # Anomalous service: memory leak + CPU spike + errors + recent restarts
    cpu_bad = _baseline(history - 1, 0.38, 0.02, rng) + [1.15]
    mem_bad = [350_000_000 + i * 12_000_000 for i in range(history - 1)] + [820_000_000]
    err_bad = _baseline(history - 1, 0.015, 0.003, rng) + [0.18]
    lat_bad = _baseline(history - 1, 0.15, 0.015, rng) + [0.55]
    rps_bad = _baseline(history - 1, 200, 10, rng) + [40.0]  # traffic drop
    restarts_bad = [0.0] * (history - 1) + [3.0]
    deploy = [0.0] * (history - 1) + [1.0]

    series.extend(
        [
            _series(signal=SignalType.cpu, namespace="prod", service="svc01", values=cpu_bad),
            _series(signal=SignalType.memory, namespace="prod", service="svc01", values=mem_bad),
            _series(signal=SignalType.error_rate, namespace="prod", service="svc01", values=err_bad),
            _series(signal=SignalType.latency, namespace="prod", service="svc01", values=lat_bad),
            _series(signal=SignalType.traffic, namespace="prod", service="svc01", values=rps_bad),
            _series(signal=SignalType.restarts, namespace="prod", service="svc01", values=restarts_bad),
            _series(signal=SignalType.deployment, namespace="prod", service="svc01", values=deploy),
            _series(
                signal=SignalType.oom,
                namespace="prod",
                service="svc01",
                values=[0.0] * (history - 1) + [2.0],
            ),
        ]
    )

    # Mild node pressure (informational)
    node = _baseline(history - 1, 0.55, 0.03, rng) + [0.92]
    series.append(
        _series(signal=SignalType.node_pressure, namespace="prod", service="node-pool-a", values=node)
    )

    # Sanitize any accidental NaNs
    for s in series:
        for p in s.points:
            if math.isnan(p.value) or math.isinf(p.value):
                p.value = 0.0
    return series
