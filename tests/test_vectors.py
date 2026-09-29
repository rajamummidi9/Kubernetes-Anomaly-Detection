from anomaly_detection.config import Settings
from anomaly_detection.insights.report import build_report
from test_dashboard import snapshot


def test_vectors_cover_egress_and_repeated_failures():
    snap = snapshot()
    snap.coverage["network_policies"] = "ok"
    report = build_report(snap, Settings())
    ids = {item["id"] for item in report["insights"]}
    assert "open-egress" in ids
    assert "repeating-errors" in ids

    vectors = {item["id"]: item for item in report["vectors"]}
    assert set(vectors) == {"security_runtime", "performance", "logs", "cost"}
    assert vectors["security_runtime"]["status"] == "watch"
    assert any("Falco" in spot for spot in vectors["security_runtime"]["blind_spots"])
    assert any("flow logs" in spot for spot in vectors["security_runtime"]["blind_spots"])
    assert vectors["logs"]["status"] == "watch"
    assert any("LOKI_URL" in spot for spot in vectors["logs"]["blind_spots"])
