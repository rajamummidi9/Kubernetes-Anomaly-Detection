from __future__ import annotations

from anomaly_detection.collectors.demo import generate_demo_series
from anomaly_detection.collectors.metrics import MetricsCollector
from anomaly_detection.config import Settings, get_settings, load_detector_config
from anomaly_detection.detectors.baseline import detect_baseline_anomalies
from anomaly_detection.detectors.correlator import correlate_incidents
from anomaly_detection.models import EvaluationResult, Incident


class AnomalyEngine:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.config = load_detector_config(self.settings)
        self.metrics = MetricsCollector(self.settings)
        self._latest: EvaluationResult | None = None
        self._incidents: dict[str, Incident] = {}
        self.status = "not evaluated"

    @property
    def latest(self) -> EvaluationResult | None:
        return self._latest

    @property
    def enabled(self) -> bool:
        return self.settings.demo_mode or bool(self.settings.metrics_url)

    def get_incident(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_incidents(self) -> list[Incident]:
        return sorted(self._incidents.values(), key=lambda i: i.score, reverse=True)

    async def evaluate(self) -> EvaluationResult:
        if self.settings.demo_mode:
            series = generate_demo_series()
            self.status = "demo data"
        elif not self.settings.metrics_url:
            series = []
            self.status = "disabled: set PROMETHEUS_URL or MIMIR_URL"
        else:
            series = []
            for ns in self.settings.namespaces or [".*"]:
                series.extend(await self.metrics.collect_namespace(ns))
            errors = self.metrics.errors
            self.status = f"error: {errors[0]}" if errors and not series else "ok"

        anomalies = detect_baseline_anomalies(
            series,
            sensitivity=self.config.get("sensitivity", {}),
            weights=self.config.get("weights", {}),
        )
        incidents = correlate_incidents(anomalies)
        self._incidents = {i.id: i for i in incidents}
        self._latest = EvaluationResult(
            series_count=len(series),
            anomaly_count=len(anomalies),
            incident_count=len(incidents),
            incidents=incidents,
            anomalies=anomalies,
        )
        return self._latest

    async def aclose(self) -> None:
        await self.metrics.aclose()
