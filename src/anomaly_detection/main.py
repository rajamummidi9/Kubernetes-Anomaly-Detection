from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse, PlainTextResponse

from anomaly_detection import __version__
from anomaly_detection.config import get_settings
from anomaly_detection.engine import AnomalyEngine
from anomaly_detection.intelligence import IntelligenceEngine
from anomaly_detection.intelligence.providers import ProviderError
from anomaly_detection.insights.report import ClusterAnalyzer, to_markdown
from anomaly_detection.models import EvaluationResult, Incident

settings = get_settings()
engine = AnomalyEngine(settings)
analyzer = ClusterAnalyzer(settings, ttl_seconds=settings.cache_ttl_seconds)
intelligence = IntelligenceEngine(settings)
STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    await engine.evaluate()
    intelligence.start(lambda: analyzer.analyze(settings.kube_context or None, True))
    yield
    await intelligence.aclose()
    await engine.aclose()


app = FastAPI(
    title="Kubernetes Anomaly Detection",
    version=__version__,
    description="Read-only cluster insights plus baseline anomaly scoring for any Kubernetes cluster.",
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
async def dashboard_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/assets/{name}", include_in_schema=False)
async def asset(name: str) -> FileResponse:
    media = {"dashboard.css": "text/css", "dashboard.js": "application/javascript"}
    if name not in media:
        raise HTTPException(status_code=404)
    return FileResponse(STATIC_DIR / name, media_type=media[name])


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "demo_mode": settings.demo_mode,
        "baseline": engine.status,
        "intelligence": intelligence.service.status().model_dump(),
    }


@app.get("/v1/contexts")
async def contexts() -> dict:
    items, default = await asyncio.to_thread(analyzer.clients.contexts)
    return {
        "default": default,
        "contexts": [{"name": c.name, "cluster": c.cluster, "user": c.user} for c in items],
    }


@app.get("/v1/analysis")
async def analysis(context: str | None = None, force: bool = False) -> dict:
    """Full read-only analysis of one cluster context."""
    report = await asyncio.to_thread(analyzer.analyze, context, force)
    intelligence.observe(report)
    return report


@app.get("/v1/report.md", response_class=PlainTextResponse)
async def report_markdown(context: str | None = None) -> str:
    report = await asyncio.to_thread(analyzer.analyze, context, False)
    if not report["meta"].get("connected"):
        raise HTTPException(status_code=502, detail=report["meta"].get("error"))
    return to_markdown(report)


@app.get("/v1/dashboard")
async def dashboard(context: str | None = None, force: bool = False) -> dict:
    """Cluster analysis plus Prometheus baseline incidents in one call."""
    report = await asyncio.to_thread(analyzer.analyze, context, force)
    ai = intelligence.snapshot(report)
    latest = engine.latest
    # The chat endpoint reads pod_catalog from the cached report. The page does not.
    cluster = {key: value for key, value in report.items() if key != "pod_catalog"}
    return {
        "cluster": cluster,
        "baseline": {
            "status": engine.status,
            "enabled": engine.enabled,
            "result": latest.model_dump(mode="json") if latest else None,
        },
        "intelligence": ai,
        "version": __version__,
    }


@app.get("/v1/intelligence")
async def intelligence_latest(context: str | None = None) -> dict:
    """Deterministic predictions and the latest AI analysis without spending tokens."""
    report = await asyncio.to_thread(analyzer.analyze, context, False)
    if not (report.get("meta") or {}).get("connected"):
        raise HTTPException(status_code=502, detail=(report.get("meta") or {}).get("error"))
    return intelligence.snapshot(report)


class ChatBody(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    history: list[dict] = Field(default_factory=list, max_length=8)


@app.post("/v1/chat")
async def cluster_chat(body: ChatBody, context: str | None = None) -> dict:
    """Answer one question from the current snapshot. Open questions use the configured model."""
    report = await asyncio.to_thread(analyzer.analyze, context, False)
    if not (report.get("meta") or {}).get("connected"):
        raise HTTPException(status_code=502, detail=(report.get("meta") or {}).get("error"))
    try:
        return await intelligence.chat(report, body.question, body.history)
    except ProviderError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/v1/intelligence")
async def run_intelligence(
    context: str | None = None,
    force: bool = False,
    notify: bool = False,
) -> dict:
    """Generate evidence-grounded RCA and optionally deliver configured alerts."""
    report = await asyncio.to_thread(analyzer.analyze, context, force)
    if not (report.get("meta") or {}).get("connected"):
        raise HTTPException(status_code=502, detail=(report.get("meta") or {}).get("error"))
    try:
        return await intelligence.generate(report, force=force, notify=notify)
    except ProviderError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/v1/evaluate", response_model=EvaluationResult)
async def evaluate() -> EvaluationResult:
    return await engine.evaluate()


@app.get("/v1/anomalies")
async def list_anomalies(min_contribution: float = Query(0.0, ge=0.0)):
    latest = engine.latest or await engine.evaluate()
    items = [a for a in latest.anomalies if a.contribution >= min_contribution]
    return {"count": len(items), "anomalies": items}


@app.get("/v1/incidents")
async def list_incidents(min_score: float = Query(0.0, ge=0.0, le=100.0)):
    incidents = [i for i in engine.list_incidents() if i.score >= min_score]
    return {"count": len(incidents), "incidents": incidents}


@app.get("/v1/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str) -> Incident:
    incident = engine.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
