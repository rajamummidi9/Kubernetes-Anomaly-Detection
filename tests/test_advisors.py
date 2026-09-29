from datetime import date

from kubernetes.client import (
    RbacV1Subject,
    V1ClusterRoleBinding,
    V1ObjectMeta,
    V1RoleRef,
    V1Service,
    V1ServiceSpec,
)

from anomaly_detection.advisors.security import security_advice
from anomaly_detection.advisors.upgrades import upgrade_advice
from anomaly_detection.config import Settings
from anomaly_detection.insights.report import build_report, to_markdown
from test_dashboard import snapshot


def test_security_advice_covers_admission_rbac_and_exposure():
    snap = snapshot()
    snap.coverage["cluster_role_bindings"] = "ok"
    snap.coverage["services"] = "ok"
    snap.coverage["ingresses"] = "ok"
    snap.cluster_role_bindings = [V1ClusterRoleBinding(
        metadata=V1ObjectMeta(name="devs-admin"),
        role_ref=V1RoleRef(api_group="rbac.authorization.k8s.io", kind="ClusterRole", name="cluster-admin"),
        subjects=[RbacV1Subject(kind="Group", name="devs", api_group="rbac.authorization.k8s.io")],
    )]
    snap.services = [V1Service(
        metadata=V1ObjectMeta(name="web", namespace="shop"),
        spec=V1ServiceSpec(type="LoadBalancer"),
    )]
    items = {i["id"]: i for i in security_advice(snap, Settings().system_namespace_set)}
    assert "psa-enforce" in items
    assert "shop" in items["psa-enforce"]["advice"]
    assert "kube-system" not in items["psa-enforce"]["advice"]
    assert "cluster-admin-bindings" in items
    assert "devs" in items["cluster-admin-bindings"]["advice"]
    assert "load-balancers" in items
    assert "default-service-account" in items


def test_upgrade_advice_flags_maintenance_and_patch_gap():
    advice = upgrade_advice(snapshot(), [], today=date(2026, 9, 29))
    assert advice["status"] == "maintenance"
    assert advice["eol"] == "2026-10-27"
    assert advice["latest_patch"] == "1.34.12"
    assert any("1.34.12" in step["title"] for step in advice["plan"])
    assert "1.35" in advice["supported"]
    assert "1.33" not in advice["supported"]


def test_upgrade_advice_marks_eol_versions_unsupported():
    snap = snapshot()
    snap.server_version = "v1.33.8"
    advice = upgrade_advice(snap, [], today=date(2026, 9, 29))
    assert advice["status"] == "unsupported"


def test_investigations_explain_crash_and_oom():
    report = build_report(snapshot(), Settings())
    cases = {c["id"]: c for c in report["advisors"]["investigations"]}
    assert "down-shop-api" in cases
    assert cases["down-shop-api"]["confidence"] == "high"
    assert "exits" in cases["down-shop-api"]["likely_cause"]
    assert "oom-shop-worker" in cases
    assert "limit is below" in cases["oom-shop-worker"]["likely_cause"]
    md = to_markdown(report)
    assert "## Advisors" in md
    assert "Investigations" in md
