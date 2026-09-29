"""Kubernetes version and upgrade advice."""

from __future__ import annotations

from datetime import date
from typing import Any

from anomaly_detection.advisors.releases import (
    CATALOG_AS_OF,
    CATALOG_URL,
    MAX_KUBELET_SKEW,
    RELEASES,
    parse_version,
)
from anomaly_detection.insights.model import Insight
from anomaly_detection.k8s.snapshot import ClusterSnapshot

# Findings that make a node drain or a minor upgrade unsafe to start today.
BLOCKERS = {
    "workload-down": "A workload has zero ready replicas. Restore it before draining nodes.",
    "node-not-ready": "A node is NotReady. Fix or replace it before starting a pool upgrade.",
    "node-pressure": "A node is under pressure and will evict pods during a drain.",
    "n-plus-one-memory": "The cluster cannot absorb losing its largest node. Free memory requests or add capacity first.",
    "n-plus-one-cpu": "The cluster cannot absorb losing its largest node. Free CPU requests or add capacity first.",
    "missing-pdb": "Workloads have no PodDisruptionBudget, so a drain can evict every replica.",
    "replicas-same-node": "Some workloads keep every replica on one node, so that node's drain is an outage.",
    "single-replica": "Single-replica workloads go down for the whole time their node is drained.",
}


def _step(title: str, detail: str) -> dict[str, str]:
    return {"title": title, "detail": detail}


def detect_provider(snapshot: ClusterSnapshot) -> str:
    labels: dict[str, str] = {}
    for node in snapshot.nodes:
        labels.update((node.metadata.labels or {}) if node.metadata else {})
    if any(k.startswith("kubernetes.azure.com") for k in labels):
        return "AKS"
    if any(k.startswith("eks.amazonaws.com") for k in labels):
        return "EKS"
    if any(k.startswith("cloud.google.com/gke") for k in labels):
        return "GKE"
    return ""


def upgrade_advice(
    snapshot: ClusterSnapshot,
    insights: list[Insight],
    today: date | None = None,
) -> dict[str, Any]:
    today = today or date.today()
    parsed = parse_version(snapshot.server_version)
    provider = detect_provider(snapshot)
    kubelets = _kubelets(snapshot)
    base = {
        "control_plane": snapshot.server_version or "unknown",
        "provider": provider,
        "status": "unknown",
        "headline": "Control plane version was not reported.",
        "eol": "",
        "latest_patch": "",
        "supported": _supported(today),
        "catalog_as_of": CATALOG_AS_OF.isoformat(),
        "catalog_url": CATALOG_URL,
        "skew_summary": _skew_summary(parsed, kubelets),
        "plan": [],
    }
    if parsed is None:
        base["plan"] = [_step(
            "Confirm the version",
            "kubectl version did not return a parseable control-plane version. Check API server reachability.",
        )]
        return base

    minor, patch = parsed
    info = RELEASES.get(minor)
    if info is None:
        newest = max(RELEASES)
        if minor > newest:
            base["status"] = "unknown"
            base["headline"] = f"v1.{minor} is newer than this catalog ({CATALOG_AS_OF.isoformat()})."
            base["plan"] = [_step(
                "Refresh the release catalog",
                f"Compare v1.{minor} with {CATALOG_URL} before deciding it is supported.",
            )]
        else:
            base["status"] = "unsupported"
            base["headline"] = f"v1.{minor} is outside the upstream support window."
            base["plan"] = _unsupported_plan(minor, provider)
        return base

    eol: date = info["eol"]
    latest = info["latest"]
    latest_patch = parse_version(latest)[1]
    base["eol"] = eol.isoformat()
    base["latest_patch"] = latest
    if today > eol:
        base["status"] = "unsupported"
        base["headline"] = f"v1.{minor} reached end of life on {eol.isoformat()} and no longer receives patches."
        base["plan"] = _unsupported_plan(minor, provider)
    elif today >= info["maintenance"]:
        days = (eol - today).days
        base["status"] = "maintenance"
        base["headline"] = (
            f"v1.{minor}.{patch} is in maintenance. Upstream support ends on {eol.isoformat()} ({days} days)."
        )
        base["plan"] = _maintenance_plan(minor, patch, latest, latest_patch, provider, insights)
    else:
        base["status"] = "supported"
        behind = patch < latest_patch
        base["headline"] = (
            f"v1.{minor}.{patch} is in the upstream support window until {eol.isoformat()}."
            + (f" It is behind the current patch {latest}." if behind else " It is on the current patch.")
        )
        base["plan"] = _supported_plan(minor, patch, latest, behind, provider, insights)

    skew = _skew_step(parsed, kubelets)
    if skew:
        base["plan"].append(skew)
    return base


def _supported(today: date) -> list[str]:
    open_minors = [minor for minor, info in RELEASES.items() if today <= info["eol"]]
    return [f"1.{minor}" for minor in sorted(open_minors)]


def _kubelets(snapshot: ClusterSnapshot) -> dict[int, int]:
    counts: dict[int, int] = {}
    for node in snapshot.nodes:
        info = node.status.node_info if node.status else None
        parsed = parse_version(info.kubelet_version) if info else None
        if parsed:
            counts[parsed[0]] = counts.get(parsed[0], 0) + 1
    return counts


def _skew_summary(control: tuple[int, int] | None, kubelets: dict[int, int]) -> str:
    if not kubelets:
        return "No kubelet versions were reported."
    versions = ", ".join(f"1.{m} ×{n}" for m, n in sorted(kubelets.items()))
    if control is None:
        return f"Kubelets: {versions}."
    worst = control[0] - min(kubelets)
    if worst > MAX_KUBELET_SKEW:
        return f"Kubelets ({versions}) trail the control plane by {worst} minors. Upstream allows {MAX_KUBELET_SKEW}."
    if len(kubelets) > 1:
        return f"Kubelets are mixed ({versions}). Finish lagging pools before the next minor."
    return f"Kubelets match the control plane ({versions})."


def _skew_step(control: tuple[int, int], kubelets: dict[int, int]) -> dict[str, str] | None:
    if not kubelets:
        return None
    if control[0] - min(kubelets) > MAX_KUBELET_SKEW:
        return _step(
            "Bring kubelets back within the skew policy",
            f"kubelet may be at most {MAX_KUBELET_SKEW} minors older than kube-apiserver. "
            "Upgrade the oldest node pools before moving the control plane further.",
        )
    return None


def _provider_note(provider: str, target: str) -> str:
    if provider:
        return (
            f" {provider} qualifies versions on its own calendar, so confirm {target} is offered "
            "in your region before scheduling the change."
        )
    return " Confirm the target is offered by your provider; managed services lag upstream by days or weeks."


def _maintenance_plan(minor: int, patch: int, latest: str, latest_patch: int, provider: str, insights: list[Insight]) -> list[dict[str, str]]:
    nxt = f"1.{minor + 1}"
    steps = []
    if patch < latest_patch:
        steps.append(_step(
            f"Patch to {latest} first",
            f"v1.{minor}.{patch} is behind the newest patch on this minor. "
            "Take the patch release before a minor upgrade so known fixes are already in place.",
        ))
    steps.append(_step(
        f"Plan the move to {nxt}",
        f"Upstream stops patching 1.{minor} on its end-of-life date. Upgrade one minor at a time; do not skip to a later release."
        + _provider_note(provider, nxt),
    ))
    steps.extend(_blockers(insights))
    steps.append(_step(
        "Upgrade one node pool at a time",
        "Cordon and drain a pool only after PodDisruptionBudgets are in place. Watch Pending pods before starting the next pool.",
    ))
    return steps


def _supported_plan(minor: int, patch: int, latest: str, behind: bool, provider: str, insights: list[Insight]) -> list[dict[str, str]]:
    steps = []
    if behind:
        steps.append(_step(
            f"Install patch {latest}",
            "Stay on this minor and take the current patch. Minor upgrades can wait until this branch enters maintenance.",
        ))
    else:
        steps.append(_step(
            "Stay on this minor",
            f"1.{minor} is supported and on the newest patch in the catalog. Apply the monthly patch when it is published."
            + _provider_note(provider, f"1.{minor}"),
        ))
    steps.extend(_blockers(insights))
    return steps


def _unsupported_plan(minor: int, provider: str) -> list[dict[str, str]]:
    # Step toward the oldest minor that this catalog still tracks as having an EOL, one at a time.
    return [
        _step(
            "Treat this cluster as missing security patches",
            f"1.{minor} is no longer maintained upstream. Known issues fixed in later patches will not reach it.",
        ),
        _step(
            f"Upgrade one minor at a time toward a supported release",
            "Move 1.{0} → 1.{1}, then continue, rather than jumping several minors in one change."
            .format(minor, minor + 1) + _provider_note(provider, f"1.{minor + 1}"),
        ),
        _step(
            "Make drains safe before the first pool",
            "Add PodDisruptionBudgets, a second replica for anything that must stay up, and enough free capacity to lose one node.",
        ),
    ]


def _blockers(insights: list[Insight]) -> list[dict[str, str]]:
    present = {i.id: i for i in insights}
    steps = []
    for item_id, detail in BLOCKERS.items():
        if item_id in present:
            steps.append(_step(f"Before the upgrade: {present[item_id].title}", detail))
    return steps[:4]
