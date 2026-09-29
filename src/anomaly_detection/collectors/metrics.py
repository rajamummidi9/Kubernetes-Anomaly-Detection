from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urljoin

import httpx

from anomaly_detection.config import Settings, load_queries
from anomaly_detection.models import MetricPoint, MetricSeries, SignalType


SIGNAL_QUERY_MAP: dict[SignalType, str] = {
    SignalType.cpu: "cpu_usage",
    SignalType.memory: "memory_usage",
    SignalType.restarts: "pod_restarts",
    SignalType.traffic: "http_request_rate",
    SignalType.error_rate: "http_error_rate",
    SignalType.latency: "http_latency_p95",
    SignalType.oom: "oom_kills",
    SignalType.node_pressure: "node_memory_pressure",
}


class MetricsCollector:
    """Query Prometheus or Mimir for current + historical metric ranges."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None):
        self.settings = settings
        self.queries = load_queries(settings)
        self._client = client
        self.errors: list[str] = []

    @property
    def base_url(self) -> str:
        return self.settings.metrics_url

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def render_query(self, template_name: str, **kwargs: str) -> str:
        template = self.queries[template_name]
        for name, value in kwargs.items():
            template = template.replace(f"{{{name}}}", value)
        return template

    async def query_range(
        self,
        query: str,
        *,
        start: datetime,
        end: datetime,
        step: str = "5m",
    ) -> list[dict[str, Any]]:
        client = await self._get_client()
        url = urljoin(self.base_url + "/", "api/v1/query_range")
        params = {
            "query": query,
            "start": start.timestamp(),
            "end": end.timestamp(),
            "step": step,
        }
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        payload = resp.json()
        return payload.get("data", {}).get("result", [])

    async def collect_namespace(
        self,
        namespace: str,
        *,
        window: timedelta = timedelta(hours=24),
        step: str = "5m",
    ) -> list[MetricSeries]:
        end = datetime.now(timezone.utc)
        start = end - window
        series: list[MetricSeries] = []
        self.errors = []

        for signal, template_name in SIGNAL_QUERY_MAP.items():
            if template_name not in self.queries:
                continue
            query = self.render_query(
                template_name,
                namespace=namespace,
                service=".*",
                pod=".*",
                window="1h",
            )
            try:
                results = await self.query_range(query, start=start, end=end, step=step)
            except httpx.HTTPError as exc:
                self.errors.append(f"{template_name}: {type(exc).__name__}: {exc}")
                continue

            for result in results:
                labels = result.get("metric", {})
                service = (
                    labels.get("service")
                    or labels.get("pod")
                    or labels.get("instance")
                    or "unknown"
                )
                points = [
                    MetricPoint(
                        timestamp=datetime.fromtimestamp(float(ts), tz=timezone.utc),
                        value=float(val),
                    )
                    for ts, val in result.get("values", [])
                ]
                series.append(
                    MetricSeries(
                        name=template_name,
                        signal=signal,
                        namespace=namespace,
                        service=service,
                        labels=labels,
                        points=points,
                    )
                )
        return series
