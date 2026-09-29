from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from kubernetes.client import (
    CoreV1Event,
    V1Container,
    V1ContainerState,
    V1ContainerStateTerminated,
    V1ContainerStateWaiting,
    V1ContainerStatus,
    V1Deployment,
    V1DeploymentSpec,
    V1DeploymentStatus,
    V1LabelSelector,
    V1Namespace,
    V1Node,
    V1NodeCondition,
    V1NodeSpec,
    V1NodeStatus,
    V1NodeSystemInfo,
    V1ObjectMeta,
    V1ObjectReference,
    V1OwnerReference,
    V1Pod,
    V1PodSpec,
    V1PodStatus,
    V1PodTemplateSpec,
    V1Probe,
    V1ResourceRequirements,
    V2HorizontalPodAutoscaler,
    V2HorizontalPodAutoscalerSpec,
    V2HorizontalPodAutoscalerStatus,
    V2CrossVersionObjectReference,
)

from anomaly_detection import main
from anomaly_detection.collectors.metrics import MetricsCollector
from anomaly_detection.config import Settings
from anomaly_detection.insights.index import quantity, workload_of
from anomaly_detection.insights.report import build_report, to_markdown
from anomaly_detection.k8s.snapshot import ClusterSnapshot

NOW = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
ALL_OK = {k: "ok" for k in (
    "namespaces", "nodes", "pods", "deployments", "statefulsets", "daemonsets",
    "hpas", "pdbs", "events", "node_metrics", "pod_metrics",
)}


def node(name, cpu="8", memory="32Gi"):
    return V1Node(
        metadata=V1ObjectMeta(name=name, labels={"agentpool": "app"}, creation_timestamp=NOW - timedelta(days=10)),
        spec=V1NodeSpec(),
        status=V1NodeStatus(
            allocatable={"cpu": cpu, "memory": memory, "pods": "30"},
            capacity={"cpu": cpu, "memory": memory, "pods": "30"},
            conditions=[V1NodeCondition(type="Ready", status="True")],
            node_info=V1NodeSystemInfo(
                kubelet_version="v1.34.0", architecture="amd64", boot_id="", container_runtime_version="",
                kernel_version="", kube_proxy_version="", machine_id="", operating_system="linux",
                os_image="", system_uuid="",
            ),
        ),
    )


def pod(name, ns="shop", node_name="n1", workload="web", requests=None, limits=None,
        waiting=None, terminated=None, restarts=0, image="acr.io/web:1.0"):
    status = V1ContainerStatus(
        name="app", image=image, image_id="", ready=waiting is None, restart_count=restarts,
        state=V1ContainerState(waiting=V1ContainerStateWaiting(reason=waiting) if waiting else None),
        last_state=V1ContainerState(terminated=terminated),
    )
    return V1Pod(
        metadata=V1ObjectMeta(
            name=name, namespace=ns, labels={"pod-template-hash": "abc12", "app": workload},
            owner_references=[V1OwnerReference(api_version="apps/v1", kind="ReplicaSet", name=f"{workload}-abc12", uid="u")],
            creation_timestamp=NOW - timedelta(hours=2),
        ),
        spec=V1PodSpec(node_name=node_name, containers=[V1Container(
            name="app", image=image, resources=V1ResourceRequirements(requests=requests, limits=limits),
        )]),
        status=V1PodStatus(phase="Running", container_statuses=[status], qos_class="Burstable" if requests else "BestEffort"),
    )


def deployment(name, ns="shop", replicas=2, available=2, readiness=True):
    return V1Deployment(
        metadata=V1ObjectMeta(name=name, namespace=ns),
        spec=V1DeploymentSpec(
            replicas=replicas,
            selector=V1LabelSelector(match_labels={"app": name}),
            template=V1PodTemplateSpec(
                metadata=V1ObjectMeta(labels={"app": name}),
                spec=V1PodSpec(containers=[V1Container(
                    name="app", image="acr.io/web:1.0",
                    readiness_probe=V1Probe() if readiness else None,
                )]),
            ),
        ),
        status=V1DeploymentStatus(available_replicas=available),
    )


def pod_metric(name, ns, cpu, memory):
    return {"metadata": {"name": name, "namespace": ns}, "containers": [{"usage": {"cpu": cpu, "memory": memory}}]}


def snapshot() -> ClusterSnapshot:
    oom = V1ContainerStateTerminated(exit_code=137, reason="OOMKilled", finished_at=NOW - timedelta(minutes=10))
    pods = [
        pod("web-1", requests={"cpu": "100m", "memory": "128Mi"}, limits={"memory": "256Mi"}),
        pod("web-2", requests={"cpu": "100m", "memory": "128Mi"}, limits={"memory": "256Mi"}),
        pod("api-1", workload="api", waiting="CrashLoopBackOff", restarts=12,
            requests={"cpu": "100m", "memory": "128Mi"}, limits={"memory": "256Mi"}),
        pod("worker-1", workload="worker", terminated=oom, restarts=4, image="acr.io/worker:latest",
            requests={"cpu": "100m", "memory": "128Mi"}, limits={"memory": "256Mi"}),
        pod("batch-1", workload="batch"),  # no requests or limits
    ]
    event = CoreV1Event(
        metadata=V1ObjectMeta(name="e1", namespace="shop", creation_timestamp=NOW - timedelta(days=5)),
        involved_object=V1ObjectReference(kind="Pod", name="api-1"),
        reason="BackOff", message="Back-off restarting failed container", type="Warning", count=900,
        first_timestamp=NOW - timedelta(days=5), last_timestamp=NOW - timedelta(minutes=2),
    )
    fixed_hpa = V2HorizontalPodAutoscaler(
        metadata=V1ObjectMeta(name="web", namespace="shop"),
        spec=V2HorizontalPodAutoscalerSpec(
            min_replicas=2, max_replicas=2,
            scale_target_ref=V2CrossVersionObjectReference(kind="Deployment", name="web"),
        ),
        status=V2HorizontalPodAutoscalerStatus(current_replicas=2, desired_replicas=2),
    )
    return ClusterSnapshot(
        context="test", collected_at=NOW, server_version="v1.34.0",
        namespaces=[V1Namespace(metadata=V1ObjectMeta(name=n)) for n in ("shop", "kube-system")],
        nodes=[node("n1"), node("n2")],
        pods=pods,
        deployments=[deployment("web"), deployment("api", replicas=1, available=0, readiness=False)],
        hpas=[fixed_hpa],
        events=[event],
        node_metrics=[
            {"metadata": {"name": "n1"}, "usage": {"cpu": "2", "memory": "29Gi"}},
            {"metadata": {"name": "n2"}, "usage": {"cpu": "1", "memory": "4Gi"}},
        ],
        pod_metrics=[
            pod_metric("web-1", "shop", "50m", "240Mi"),
            pod_metric("web-2", "shop", "50m", "240Mi"),
            pod_metric("worker-1", "shop", "20m", "100Mi"),
            pod_metric("batch-1", "shop", "10m", "2Gi"),
        ],
        coverage=dict(ALL_OK),
    )


def test_quantities_and_workload_resolution():
    assert quantity("250m") == 0.25
    assert quantity("2Gi") == 2 * 1024**3
    assert quantity(None) == 0.0
    assert workload_of(pod("web-1")) == ("Deployment", "web")


def test_rules_detect_expected_problems():
    report = build_report(snapshot(), Settings())
    ids = {i["id"] for i in report["insights"]}
    assert not report["meta"]["rule_errors"]
    expected = {
        "workload-down", "crashloop", "oom-killed", "replicas-same-node", "missing-readiness",
        "event-backoff", "node-memory-hot", "missing-requests", "near-memory-limit",
        "mutable-image-tag", "hpa-fixed", "memory-request-coverage",
    }
    assert expected <= ids, expected - ids
    assert "hpa-maxed" not in ids  # min == max is reported as fixed, not maxed

    events = {i["id"]: i for i in report["insights"]}["event-backoff"]
    assert events["title"].startswith("Chronic:")
    assert report["scores"]["overall"] <= 69  # critical reliability issue caps the score
    assert report["capacity"]["pods"] == {"usage": 5, "allocatable": 60}
    assert report["quick_wins"][0]["severity"] == "critical"


def test_system_namespaces_excluded_from_hygiene_rules():
    snap = snapshot()
    snap.pods.append(pod("proxy", ns="kube-system", workload="proxy"))
    report = build_report(snap, Settings())
    missing = {i["id"]: i for i in report["insights"]}["missing-requests"]
    assert all(a["namespace"] != "kube-system" for a in missing["affected"])


def test_degrades_without_metrics_server():
    snap = snapshot()
    snap.pod_metrics, snap.node_metrics = [], []
    snap.coverage["pod_metrics"] = "unavailable"
    report = build_report(snap, Settings())
    ids = {i["id"] for i in report["insights"]}
    assert "metrics-unavailable" in ids
    assert "memory-request-coverage" not in ids
    assert not report["meta"]["rule_errors"]


def test_markdown_export_contains_findings():
    md = to_markdown(build_report(snapshot(), Settings()))
    assert md.startswith("# Cluster health report: test")
    assert "CrashLoopBackOff" in md


def test_promql_template_preserves_query_braces():
    query = MetricsCollector(Settings()).render_query("cpu_usage", namespace=".*", service=".*", pod=".*", window="1h")
    assert 'namespace=~".*"' in query and 'container!=""' in query


def test_api_serves_page_and_analysis(monkeypatch):
    report = build_report(snapshot(), Settings())
    report["meta"]["connected"] = True
    monkeypatch.setattr(main.analyzer, "analyze", lambda context=None, force=False: report)
    with TestClient(main.app) as client:
        assert "Kubernetes Anomaly Detection" in client.get("/").text
        assert client.get("/assets/dashboard.js").status_code == 200
        assert client.get("/assets/../main.py").status_code == 404
        body = client.get("/v1/dashboard?context=test").json()
        assert body["cluster"]["meta"]["context"] == "test"
        assert body["baseline"]["enabled"] is False
        assert client.get("/v1/report.md").text.startswith("# Cluster health report")
