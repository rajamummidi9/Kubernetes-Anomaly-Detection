from __future__ import annotations

import math
from statistics import mean, pstdev

from anomaly_detection.models import AnomalySignal, MetricSeries, SignalType


def baseline_stats(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    mu = mean(values)
    sigma = pstdev(values)
    return mu, sigma


def z_score(observed: float, mu: float, sigma: float) -> float:
    if sigma <= 1e-12:
        return 0.0 if abs(observed - mu) < 1e-9 else 10.0
    return (observed - mu) / sigma


def detect_baseline_anomalies(
    series_list: list[MetricSeries],
    *,
    sensitivity: dict[str, float],
    weights: dict[str, float],
    history_ratio: float = 0.85,
) -> list[AnomalySignal]:
    """Compare the newest point against a rolling baseline of prior points."""
    anomalies: list[AnomalySignal] = []
    for series in series_list:
        if len(series.points) < 3:
            continue

        split = max(2, int(len(series.points) * history_ratio))
        history = series.values[:split]
        observed = series.values[-1]
        mu, sigma = baseline_stats(history)
        z = z_score(observed, mu, sigma)
        threshold = sensitivity.get(series.signal.value, 3.0)

        if abs(z) < threshold:
            continue

        weight = float(weights.get(series.signal.value, 10))
        # Map |z| into a contribution capped at the configured weight.
        magnitude = min(1.0, abs(z) / (threshold * 2))
        contribution = round(weight * magnitude, 2)
        direction = "above" if z > 0 else "below"

        anomalies.append(
            AnomalySignal(
                signal=series.signal,
                namespace=series.namespace,
                service=series.service,
                observed=observed,
                expected_mean=mu,
                expected_std=sigma,
                z_score=round(z, 3),
                contribution=contribution,
                message=(
                    f"{series.signal.value} for {series.namespace}/{series.service} "
                    f"is {direction} baseline "
                    f"(observed={observed:.4g}, expected≈{mu:.4g}±{sigma:.4g}, z={z:.2f})"
                ),
                labels=series.labels,
            )
        )
    return anomalies


def severity_from_score(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "warning"
    return "info"


def clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def soft_cap_contributions(contributions: list[float], hard_cap: float = 100.0) -> float:
    """Combine contributions with diminishing overlap so totals stay interpretable."""
    if not contributions:
        return 0.0
    ordered = sorted(contributions, reverse=True)
    total = 0.0
    for i, c in enumerate(ordered):
        total += c * (0.85**i)
    return clamp(total, 0.0, hard_cap)


def expected_band(mu: float, sigma: float, k: float = 2.0) -> tuple[float, float]:
    return mu - k * sigma, mu + k * sigma


def percent_above_baseline(observed: float, mu: float) -> float:
    if abs(mu) < 1e-12:
        return math.inf if observed > 0 else 0.0
    return ((observed - mu) / abs(mu)) * 100.0
