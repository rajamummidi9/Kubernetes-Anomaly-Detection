from anomaly_detection.collectors.demo import generate_demo_series
from anomaly_detection.detectors.baseline import detect_baseline_anomalies
from anomaly_detection.detectors.correlator import correlate_incidents
from anomaly_detection.config import load_detector_config


def test_demo_detects_svc01_incident():
    cfg = load_detector_config()
    series = generate_demo_series()
    anomalies = detect_baseline_anomalies(
        series,
        sensitivity=cfg["sensitivity"],
        weights=cfg["weights"],
    )
    incidents = correlate_incidents(anomalies)

    assert anomalies, "expected at least one anomaly signal"
    assert incidents, "expected at least one correlated incident"

    top = incidents[0]
    assert top.service == "svc01"
    assert top.namespace == "prod"
    assert top.score >= 70
    assert any(s.signal.value == "cpu" for s in top.signals)
    assert "svc01" in top.narrative


def test_healthy_service_not_critical():
    cfg = load_detector_config()
    series = [s for s in generate_demo_series() if s.service == "payments-api"]
    anomalies = detect_baseline_anomalies(
        series,
        sensitivity=cfg["sensitivity"],
        weights=cfg["weights"],
    )
    incidents = correlate_incidents(anomalies)
    assert all(i.score < 70 for i in incidents)
