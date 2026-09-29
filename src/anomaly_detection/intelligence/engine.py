from __future__ import annotations

import asyncio
from typing import Any, Callable

from anomaly_detection.config import Settings
from anomaly_detection.intelligence.alerts import AlertDispatcher
from anomaly_detection.intelligence.forecast import ReportHistory
from anomaly_detection.intelligence.models import IntelligenceResult
from anomaly_detection.intelligence.service import IntelligenceService


class IntelligenceEngine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.history = ReportHistory()
        self.service = IntelligenceService(settings)
        self.alerts = AlertDispatcher(settings)
        self._task: asyncio.Task | None = None
        self._last_sent: list[str] = []

    def observe(self, report: dict[str, Any]) -> None:
        if (report.get("meta") or {}).get("connected"):
            self.history.add(report)

    def predictions(self, context: str) -> list[dict[str, Any]]:
        return self.history.predictions(context)

    async def generate(
        self,
        report: dict[str, Any],
        force: bool = False,
        notify: bool = False,
    ) -> dict[str, Any]:
        self.observe(report)
        context = str((report.get("meta") or {}).get("context") or "unknown")
        predictions = self.predictions(context)
        result = await self.service.analyze(report, predictions, force=force)
        sent = await self.alerts.send(result, predictions) if notify else []
        self._last_sent = sent
        return {
            "status": self.service.status().model_dump(),
            "predictions": predictions,
            "history_points": self.history.size(context),
            "result": result.model_dump(mode="json"),
            "notifications_sent": sent,
        }

    def snapshot(self, report: dict[str, Any]) -> dict[str, Any]:
        self.observe(report)
        context = str((report.get("meta") or {}).get("context") or "unknown")
        latest = self.service.latest(context)
        return {
            "status": self.service.status().model_dump(),
            "predictions": self.predictions(context),
            "history_points": self.history.size(context),
            "result": latest.model_dump(mode="json") if latest else None,
            "notifications_sent": self._last_sent,
        }

    def start(self, analyze: Callable[[], dict[str, Any]]) -> None:
        if not (self.settings.intelligence_auto_run and self.service.enabled):
            return
        self._task = asyncio.create_task(self._run(analyze), name="intelligence-auto-run")

    async def _run(self, analyze: Callable[[], dict[str, Any]]) -> None:
        while True:
            try:
                report = await asyncio.to_thread(analyze)
                if (report.get("meta") or {}).get("connected"):
                    await self.generate(report, force=True, notify=True)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # keep the dashboard alive when a provider or webhook fails
                self.service.last_error = str(exc)[:500]
            await asyncio.sleep(max(60, self.settings.intelligence_interval_seconds))

    async def aclose(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        await self.service.aclose()
        await self.alerts.aclose()
