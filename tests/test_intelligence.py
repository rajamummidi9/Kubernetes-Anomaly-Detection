from datetime import datetime, timedelta, timezone

import httpx
import pytest

from anomaly_detection.config import Settings
from anomaly_detection.intelligence.forecast import predict
from anomaly_detection.intelligence.service import IntelligenceService, evidence_bundle, redact


def test_redaction_removes_secret_fields_and_tokens():
    value = {
        "api_key": "do-not-send",
        "message": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        "nested": {"password": "also-secret"},
    }
    clean = redact(value)
    assert clean["api_key"] == "[REDACTED]"
    assert clean["nested"]["password"] == "[REDACTED]"
    assert "abcdefghijklmnopqrstuvwxyz" not in clean["message"]


def test_evidence_bundle_is_bounded_and_excludes_node_table():
    report = {
        "meta": {"context": "test", "generated_at": "2026-09-29T00:00:00+00:00"},
        "nodes": [{"name": "must-not-be-sent"}],
        "insights": [{"id": str(i), "summary": "x" * 200} for i in range(100)],
        "events": [],
    }
    value = evidence_bundle(report, [], 5000)
    assert len(value) <= 5000
    assert "must-not-be-sent" not in value


def test_predictions_warn_on_headroom_and_trend():
    start = datetime(2026, 9, 29, tzinfo=timezone.utc)
    points = []
    for index, memory in enumerate((70.0, 75.0, 81.0)):
        points.append({
            "at": (start + timedelta(hours=index)).isoformat(),
            "score": 75,
            "critical": 0,
            "warning": 2,
            "pods_ready": 10,
            "pods": 10,
            "cpu_usage": 20,
            "cpu_requests": 40,
            "memory_usage": memory,
            "memory_requests": 82,
            "pod_density": 30,
        })
    ids = {item.id for item in predict(points)}
    assert "memory_requests-headroom" in ids
    assert "memory_usage-trend" in ids


@pytest.mark.asyncio
async def test_openai_compatible_provider_and_schema():
    response = {
        "choices": [{"message": {"content": """{
          "summary":"One workload is unavailable.",
          "situation":"incident",
          "root_causes":[],
          "predicted_risks":["rollout capacity"],
          "actions":[{"priority":"now","title":"Inspect","rationale":"Confirm evidence","command":"kubectl get pods","risk":""}],
          "alert_title":"Cluster incident",
          "alert_body":"One workload is unavailable.",
          "limitations":["No application logs"]
        }"""}}]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer test-key"
        assert request.url.path == "/v1/chat/completions"
        return httpx.Response(200, json=response)

    settings = Settings(
        ai_provider="openai_compatible",
        ai_model="test-model",
        ai_api_key="test-key",
        ai_base_url="https://model.invalid/v1",
    )
    service = IntelligenceService(settings)
    await service.client.aclose()
    service.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await service.analyze(
        {"meta": {"context": "test", "connected": True}, "scores": {}, "insights": []},
        [],
    )
    assert result.situation == "incident"
    assert result.provider == "openai_compatible"
    assert service.latest("test").alert_title == "Cluster incident"
    await service.aclose()


def test_ai_disabled_without_key_or_model():
    assert not IntelligenceService(Settings(ai_provider="openai")).enabled
    assert IntelligenceService(Settings(ai_provider="ollama", ai_model="local")).enabled
