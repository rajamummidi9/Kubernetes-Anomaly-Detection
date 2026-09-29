import httpx
import pytest

from anomaly_detection.config import Settings
from anomaly_detection.intelligence.chat import chat_facts, direct_answer, finalize_model_reply
from anomaly_detection.intelligence.engine import IntelligenceEngine


def _report():
    return {
        "meta": {"context": "test", "generated_at": "2026-09-29T00:00:00+00:00", "connected": True},
        "scores": {"overall": 80, "grade": "B"},
        "summary": {"nodes": 1, "nodes_ready": 0, "pods": 2},
        "capacity": {
            "cpu": {"usage": 1.5, "requests": 2.0, "allocatable": 8.0},
            "memory": {"usage": 2 * 1024 ** 3, "requests": 4 * 1024 ** 3, "allocatable": 16 * 1024 ** 3},
            "notes": [],
        },
        "nodes": [{
            "name": "n1", "ready": False, "unschedulable": False, "pressure": ["MemoryPressure"],
            "kubelet": "v1.34.0", "pods": 2, "pod_capacity": 30,
            "usage": {"cpu": 1.2, "memory": 20 * 1024 ** 3},
            "requests": {"cpu": 2, "memory": 8 * 1024 ** 3},
            "allocatable": {"cpu": 8, "memory": 32 * 1024 ** 3},
        }],
        "pod_catalog": [
            {
                "namespace": "shop", "name": "payments-api", "workload": "Deployment/payments",
                "node": "n1", "phase": "Running", "ready": True, "restarts": 0,
                "cpu_cores": {"used": 0.25, "requested": 0.1, "limit": 1},
                "memory_mib": {"used": 256, "requested": 128, "limit": 512},
            },
            {
                "namespace": "shop", "name": "web", "workload": "Deployment/web",
                "node": "n1", "phase": "Running", "ready": True, "restarts": 1,
                "cpu_cores": {"used": 0.05, "requested": 0.1, "limit": None},
                "memory_mib": {"used": 64, "requested": 64, "limit": 128},
            },
        ],
        "events": [{
            "namespace": "", "resource": "n1", "kind": "Node", "reason": "NodeNotReady",
            "message": "kubelet stopped posting status", "count": 4,
        }],
        "insights": [{"id": "node-not-ready", "severity": "critical", "title": "Node n1 is not Ready", "summary": "n1"}],
        "advisors": {"investigations": []},
    }


def test_named_pod_cpu_is_answered_from_the_snapshot():
    reply = direct_answer(_report(), "what is the cpu of payments-api")
    assert reply["grounded"] == "snapshot"
    assert "250m used" in reply["answer"]
    assert "100m requested" in reply["answer"]
    assert "1.00 cores" in reply["answer"]
    assert reply["sources"] == ["shop/payments-api"]


def test_priority_question_lists_snapshot_actions():
    report = _report()
    report["quick_wins"] = [{
        "severity": "critical", "title": "Node n1 is not Ready",
        "action": "Inspect the kubelet before scheduling more pods there.",
    }]
    reply = direct_answer(report, "What should I look at first?")
    assert reply["grounded"] == "snapshot"
    assert "Node n1 is not Ready" in reply["answer"]


def test_node_down_uses_the_recorded_event():
    reply = direct_answer(_report(), "why did my node go down")
    assert "n1 is not Ready" in reply["answer"]
    assert "MemoryPressure" in reply["answer"]
    assert "kubelet stopped posting status" in reply["answer"]


def test_chat_facts_include_the_named_pod_and_drop_secrets():
    report = _report()
    report["insights"][0]["summary"] = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"
    report["pod_catalog"][0]["name"] = "payments-api"
    facts = chat_facts(report, "why is payments-api restarting", [], 8000)
    assert "payments-api" in facts
    assert "abcdefghijklmnopqrstuvwxyz" not in facts
    assert "web" not in facts or "pod_note" in facts


def test_model_reply_drops_unknown_sources_and_mutating_commands():
    facts = '{"nodes":[{"name":"n1"}]}'
    raw = """{"answer":"n1 is not Ready. kubectl delete node n1 would remove it.",
      "sources":["n1","invented-pod"],"unknown":""}"""
    reply = finalize_model_reply(raw, facts, provider="ollama", model="local", snapshot_at="t")
    assert "kubectl delete" not in reply["answer"]
    assert reply["sources"] == ["n1"]
    assert reply["grounded"] == "model"


@pytest.mark.asyncio
async def test_open_question_calls_the_provider_with_facts_only():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={"message": {"content": '{"answer":"n1 stopped reporting.","sources":["n1"],"unknown":"No syslog."}'}})

    settings = Settings(ai_provider="ollama", ai_model="local", ai_base_url="http://ollama.test")
    engine = IntelligenceEngine(settings)
    engine.service.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        reply = await engine.chat(_report(), "why is n1 not Ready", [])
    finally:
        await engine.service.client.aclose()
    assert reply["answer"] == "n1 stopped reporting."
    assert "FACTS_JSON" in seen["body"]
    assert "kubeconfig" not in seen["body"]
    assert "n1" in seen["body"]
