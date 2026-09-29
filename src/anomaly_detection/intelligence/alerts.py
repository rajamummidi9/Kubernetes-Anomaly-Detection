from __future__ import annotations

import hashlib
import time
from typing import Any

import httpx

from anomaly_detection.config import Settings
from anomaly_detection.intelligence.models import IntelligenceResult

RANK = {"info": 0, "warning": 1, "critical": 2}


class AlertDispatcher:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.client = httpx.AsyncClient(timeout=15)
        self._sent: dict[str, float] = {}

    async def send(
        self,
        result: IntelligenceResult,
        predictions: list[dict[str, Any]],
    ) -> list[str]:
        severity = _severity(result, predictions)
        if RANK.get(severity, 0) < RANK.get(self.settings.alert_min_severity, 1):
            return []
        digest = hashlib.sha256(
            f"{severity}\0{result.alert_title}\0{result.alert_body}".encode()
        ).hexdigest()
        if time.monotonic() - self._sent.get(digest, 0) < self.settings.ai_cache_ttl_seconds:
            return []

        destinations = {
            "webhook": self.settings.alert_webhook_url,
            "slack": self.settings.slack_webhook_url or "",
            "teams": self.settings.teams_webhook_url or "",
        }
        sent = []
        for kind, url in destinations.items():
            if not url:
                continue
            body = _payload(kind, result, severity)
            try:
                response = await self.client.post(url, json=body)
                response.raise_for_status()
                sent.append(kind)
            except httpx.HTTPError as exc:
                sent.append(f"{kind}:error:{getattr(getattr(exc, 'response', None), 'status_code', 'network')}")
        if any(":error:" not in destination for destination in sent):
            self._sent[digest] = time.monotonic()
        return sent

    async def aclose(self) -> None:
        await self.client.aclose()


def _severity(result: IntelligenceResult, predictions: list[dict[str, Any]]) -> str:
    values = [str(p.get("severity", "info")) for p in predictions]
    if result.situation == "incident":
        values.append("critical")
    elif result.situation == "watch":
        values.append("warning")
    return max(values or ["info"], key=lambda s: RANK.get(s, 0))


def _payload(kind: str, result: IntelligenceResult, severity: str) -> dict[str, Any]:
    text = f"[{severity.upper()}] {result.alert_title}\n{result.alert_body}"
    if kind == "slack":
        return {"text": text}
    if kind == "teams":
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [{"type": "TextBlock", "weight": "Bolder", "text": result.alert_title},
                         {"type": "TextBlock", "wrap": True, "text": result.alert_body}],
            },
        }]}
    return {
        "severity": severity,
        "title": result.alert_title,
        "body": result.alert_body,
        "intelligence": result.model_dump(mode="json"),
    }
