"""Correlate failing workloads and warning events into a short investigation."""

from __future__ import annotations

from typing import Any

from anomaly_detection.insights.index import workload_of
from anomaly_detection.insights.model import Insight
from anomaly_detection.k8s.snapshot import ClusterSnapshot

SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}
MAX_CASES = 8

IMAGE_REASONS = {"ErrImagePull", "ImagePullBackOff", "FailedToRetrieveImagePullSecret"}
SECRET_REASONS = {"UpdateFailed", "InvalidProviderConfig"}
SCHEDULING_REASONS = {"FailedScheduling", "FailedScaleUp"}


def _case(
    case_id: str,
    severity: str,
    confidence: str,
    title: str,
    symptom: str,
    likely_cause: str,
    evidence: list[str],
    checks: list[str],
) -> dict[str, Any]:
    return {
        "id": case_id,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "symptom": symptom,
        "likely_cause": likely_cause,
        "evidence": evidence[:5],
        "checks": checks[:4],
    }


def investigations(snapshot: ClusterSnapshot, insights: list[Insight]) -> list[dict[str, Any]]:
    by_id = {i.id: i for i in insights}
    events = _events(snapshot)
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(case: dict[str, Any] | None) -> None:
        if case and case["id"] not in seen:
            seen.add(case["id"])
            cases.append(case)

    for affected in (by_id.get("workload-down").affected if by_id.get("workload-down") else []):
        add(_workload_down(snapshot, affected, events))
    for affected in (by_id.get("oom-killed").affected if by_id.get("oom-killed") else []):
        add(_oom(affected, events))
    if by_id.get("image-pull"):
        add(_image_pull(by_id["image-pull"], events))
    if by_id.get("pending-pods"):
        add(_pending(by_id, events))
    if by_id.get("evicted-pods") or by_id.get("node-pressure"):
        add(_pressure(by_id))
    add(_secret_sync(events))
    add(_load_balancer(events))
    add(_probes(by_id, events))

    cases.sort(key=lambda c: SEVERITY_RANK.get(c["severity"], 9))
    return cases[:MAX_CASES]


def _events(snapshot: ClusterSnapshot) -> list[dict[str, Any]]:
    rows = []
    for event in snapshot.events:
        obj = event.involved_object
        rows.append({
            "namespace": (obj.namespace if obj else None) or event.metadata.namespace or "",
            "name": (obj.name if obj else "") or "",
            "kind": (obj.kind if obj else "") or "",
            "reason": event.reason or "",
            "message": (event.message or "").strip().replace("\n", " ")[:220],
            "count": event.count or 1,
        })
    return rows


def _pods_for(snapshot: ClusterSnapshot, namespace: str, workload: str) -> list[Any]:
    return [
        pod for pod in snapshot.pods
        if pod.metadata.namespace == namespace and workload_of(pod)[1] == workload
    ]


def _waiting_reason(pod: Any) -> str:
    for status in (pod.status.container_statuses or []) if pod.status else []:
        waiting = status.state.waiting if status.state else None
        if waiting and waiting.reason:
            return waiting.reason
        terminated = status.last_state.terminated if status.last_state else None
        if terminated and terminated.reason:
            return terminated.reason
    return ""


def _related(events: list[dict[str, Any]], namespace: str, workload: str) -> list[dict[str, Any]]:
    return [
        e for e in events
        if e["namespace"] == namespace and (e["name"] == workload or e["name"].startswith(f"{workload}-"))
    ]


def _workload_down(snapshot: ClusterSnapshot, affected: Any, events: list[dict[str, Any]]) -> dict[str, Any]:
    ns, name, kind = affected.namespace, affected.name, affected.kind or "Deployment"
    pods = _pods_for(snapshot, ns, name)
    reasons = sorted({r for r in (_waiting_reason(p) for p in pods) if r})
    related = _related(events, ns, name)
    evidence = [f"{p.metadata.name}: {_waiting_reason(p) or (p.status.phase if p.status else 'unknown')}" for p in pods[:4]]
    evidence += [f"Event {e['reason']} ×{e['count']} on {e['kind']}/{e['name']}: {e['message']}" for e in related[:3]]
    unhealthy = [e for e in related if e["reason"] == "Unhealthy"]
    if any(r in {"OOMKilled"} or "OOM" in r for r in reasons):
        cause = "A container is being OOMKilled. The memory limit is below the process working set, or the process is leaking."
        confidence = "high"
    elif any(r in IMAGE_REASONS for r in reasons) or any(e["reason"] in IMAGE_REASONS for e in related):
        cause = "The node cannot pull the image. The tag is missing, or the pull secret or registry identity is invalid."
        confidence = "high"
    elif "CrashLoopBackOff" in reasons or any(e["reason"] in {"BackOff", "Failed"} for e in related):
        cause = "The process exits as soon as it starts. Logs from the previous container usually name the missing config, dependency, or exception."
        confidence = "high"
    elif any("Readiness" in e["message"] or "readiness" in e["message"] for e in unhealthy):
        cause = (
            "The pods are running, but the readiness probe is failing, so the Service has nothing to send traffic to. "
            "The event message has the status code or the timeout."
        )
        confidence = "high"
    elif unhealthy:
        cause = "A liveness or startup probe is failing. The probe message says whether the process is slow, refusing connections, or not listening yet."
        confidence = "high"
    else:
        cause = "Replicas are not becoming Ready. The next place to look is the pod events and the previous container log, not the Deployment replica count."
        confidence = "medium"
    return _case(
        f"down-{ns}-{name}", "critical", confidence,
        f"{kind}/{name} in {ns} has no available replicas",
        affected.detail or "0 available replicas.",
        cause, evidence,
        [
            f"kubectl -n {ns} describe {kind.lower()} {name}",
            f"kubectl -n {ns} get pods -l app={name} -o wide",
            f"kubectl -n {ns} logs -l app={name} --previous --tail=100",
        ],
    )


def _oom(affected: Any, events: list[dict[str, Any]]) -> dict[str, Any]:
    ns, name = affected.namespace, affected.name
    related = [e for e in _related(events, ns, name) if "OOM" in e["reason"] or "OOM" in e["message"]]
    evidence = [affected.detail] if affected.detail else []
    evidence += [f"{e['reason']} ×{e['count']}: {e['message']}" for e in related[:2]]
    kind = (affected.kind or "pod").lower()
    return _case(
        f"oom-{ns}-{name}", "critical", "high",
        f"{name} in {ns} is being OOMKilled",
        "A container hit its memory limit and the runtime killed it.",
        "The limit is below what the process needs at peak, or the process is leaking. "
        "Raising the limit without checking the trend only delays the next kill.",
        evidence,
        [
            f"kubectl -n {ns} describe {kind} {name}",
            f"kubectl -n {ns} logs -l app={name} --previous --tail=100",
            "Compare the limit with container_memory_working_set_bytes over the last day before raising it.",
        ],
    )


def _image_pull(insight: Insight, events: list[dict[str, Any]]) -> dict[str, Any]:
    secret = [e for e in events if e["reason"] in IMAGE_REASONS]
    first = insight.affected[0] if insight.affected else None
    ns = first.namespace if first else ""
    evidence = [a.detail for a in insight.affected[:3]]
    evidence += [f"{e['namespace']}/{e['name']}: {e['message']}" for e in secret[:2]]
    secret_cause = any(e["reason"] == "FailedToRetrieveImagePullSecret" for e in secret)
    return _case(
        "image-pull", "critical", "high",
        insight.title,
        "New pods stay in ImagePullBackOff, so rollouts and scale-out cannot finish.",
        "The image pull secret is missing or expired." if secret_cause
        else "The image name, tag, or registry credentials do not match what the node can pull.",
        evidence,
        [
            f"kubectl -n {ns} describe {(first.kind or 'pod').lower()} {first.name}" if first else "kubectl get pods -A --field-selector status.phase=Pending",
            "kubectl -n <namespace> get sa <serviceaccount> -o jsonpath='{.imagePullSecrets}'",
        ],
    )


def _pending(by_id: dict[str, Insight], events: list[dict[str, Any]]) -> dict[str, Any]:
    scheduling = [e for e in events if e["reason"] in SCHEDULING_REASONS]
    saturated = [i for key, i in by_id.items() if key.endswith("-requests-saturated")]
    if saturated:
        cause = saturated[0].summary + " The scheduler places pods by requests, so free usage does not help."
        confidence = "high"
    elif scheduling:
        cause = "The scheduler rejected the pods. The event message names the resource or constraint that did not fit."
        confidence = "medium"
    else:
        cause = "Pods are Pending. Describe one of them; Insufficient cpu/memory means requests, not usage."
        confidence = "low"
    evidence = [a.detail for a in by_id["pending-pods"].affected[:3]]
    evidence += [f"{e['reason']}: {e['message']}" for e in scheduling[:2]]
    return _case(
        "pending-capacity", "critical", confidence,
        by_id["pending-pods"].title,
        "Pods cannot be scheduled.",
        cause, evidence,
        ["kubectl describe pod <pending-pod>", "kubectl describe nodes | grep -A8 'Allocated resources'"],
    )


def _pressure(by_id: dict[str, Insight]) -> dict[str, Any]:
    pressure = by_id.get("node-pressure")
    evicted = by_id.get("evicted-pods")
    evidence = []
    if pressure:
        evidence += [a.detail or a.name for a in pressure.affected[:3]]
    if evicted:
        evidence += [f"{a.namespace}/{a.name} {a.detail}" for a in evicted.affected[:3]]
    return _case(
        "node-pressure", "critical" if pressure else "warning", "high" if pressure else "medium",
        "Node pressure is evicting pods" if evicted else "A node reports resource pressure",
        "The kubelet is protecting the node by refusing or evicting pods.",
        "The node is short of memory, disk, or PID slots. Evicted pods will return and be evicted again until the pressure drops.",
        evidence,
        ["kubectl describe node <name> | grep -A6 Conditions", "kubectl get pods -A --field-selector spec.nodeName=<name>"],
    )


def _secret_sync(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    hits = [e for e in events if e["reason"] in SECRET_REASONS or "ExternalSecret" in e["kind"]]
    if not hits:
        return None
    sample = hits[0]
    return _case(
        "secret-sync", "warning", "high",
        f"Secret sync is failing ({sample['reason']})",
        "An external-secret provider is rejecting updates, so workloads keep the previous Secret or never receive one.",
        "The provider config, credentials, or the path of the remote secret is wrong. "
        "This is independent of the pod that mounts the Secret.",
        [f"{e['namespace']}/{e['name']}: {e['reason']} ×{e['count']} {e['message']}" for e in hits[:4]],
        [
            f"kubectl -n {sample['namespace']} describe {sample['kind'].lower()} {sample['name']}" if sample["kind"] else "kubectl get events -A --field-selector type=Warning",
            "Check the provider identity and the secret path named in the message.",
        ],
    )


def _load_balancer(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    hits = [e for e in events if e["reason"] == "SyncLoadBalancerFailed"]
    if not hits:
        return None
    sample = hits[0]
    return _case(
        "load-balancer-sync", "warning", "medium",
        "Cloud load balancer sync is failing",
        "A Service asked for a load balancer and the cloud controller cannot reconcile it.",
        "Typical causes are a quota, a subnet or SKU mismatch, or an annotation the controller rejects. The Service stays without a working address.",
        [f"{e['namespace']}/{e['name']}: {e['message']}" for e in hits[:3]],
        [f"kubectl -n {sample['namespace']} describe svc {sample['name']}"],
    )


def _probes(by_id: dict[str, Insight], events: list[dict[str, Any]]) -> dict[str, Any] | None:
    if by_id.get("oom-killed"):
        return None
    unhealthy = [e for e in events if e["reason"] == "Unhealthy"]
    if not unhealthy or not by_id.get("recent-restarts"):
        return None
    total = sum(e["count"] for e in unhealthy)
    return _case(
        "probe-restarts", "warning", "medium",
        "Probes are failing and containers are restarting",
        f"Unhealthy probe events have fired {total:,} times and containers restarted inside the current window.",
        "A liveness probe is killing the process, or the process is wedged and the probe is correct. "
        "OOMKilled was not seen, so this is not a memory-limit kill.",
        [f"{e['namespace']}/{e['name']} ×{e['count']}: {e['message']}" for e in unhealthy[:3]],
        [
            "kubectl -n <namespace> describe pod <name> | grep -A5 Liveness",
            "Compare failureThreshold and timeoutSeconds with the application's real startup and latency.",
        ],
    )
