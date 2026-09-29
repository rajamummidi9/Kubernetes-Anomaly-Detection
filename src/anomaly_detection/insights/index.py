from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from kubernetes.utils.quantity import parse_quantity

from anomaly_detection.k8s.snapshot import ClusterSnapshot

TERMINAL_PHASES = {"Succeeded", "Failed"}


def quantity(value: Any) -> float:
    if value in (None, ""):
        return 0.0
    try:
        return float(parse_quantity(str(value)))
    except (ValueError, ArithmeticError):
        return 0.0


@dataclass
class Resources:
    cpu: float = 0.0  # cores
    memory: float = 0.0  # bytes

    def __iadd__(self, other: "Resources") -> "Resources":
        self.cpu += other.cpu
        self.memory += other.memory
        return self


@dataclass
class PodInfo:
    pod: Any
    namespace: str
    name: str
    node: str
    phase: str
    workload_kind: str
    workload_name: str
    requests: Resources
    limits: Resources
    usage: Resources | None
    containers_missing_requests: list[str]
    containers_missing_memory_limit: list[str]
    restarts: int
    ready: bool

    @property
    def active(self) -> bool:
        return self.phase not in TERMINAL_PHASES


@dataclass
class NodeInfo:
    node: Any
    name: str
    ready: bool
    unschedulable: bool
    allocatable: Resources
    capacity: Resources
    pod_capacity: int
    usage: Resources | None
    requests: Resources = field(default_factory=Resources)
    limits: Resources = field(default_factory=Resources)
    pods: int = 0
    pressure: list[str] = field(default_factory=list)


def _container_resources(containers: list[Any]) -> tuple[Resources, Resources, list[str], list[str]]:
    requests, limits = Resources(), Resources()
    missing_requests: list[str] = []
    missing_mem_limit: list[str] = []
    for container in containers or []:
        res = container.resources
        req = (res.requests if res else None) or {}
        lim = (res.limits if res else None) or {}
        # Kubernetes defaults requests to limits when only limits are set.
        cpu_req = req.get("cpu") or lim.get("cpu")
        mem_req = req.get("memory") or lim.get("memory")
        requests += Resources(quantity(cpu_req), quantity(mem_req))
        limits += Resources(quantity(lim.get("cpu")), quantity(lim.get("memory")))
        if not cpu_req or not mem_req:
            missing_requests.append(container.name)
        if not lim.get("memory"):
            missing_mem_limit.append(container.name)
    return requests, limits, missing_requests, missing_mem_limit


def workload_of(pod: Any) -> tuple[str, str]:
    owners = pod.metadata.owner_references or []
    if not owners:
        return "Pod", pod.metadata.name
    owner = owners[0]
    if owner.kind == "ReplicaSet":
        pod_hash = (pod.metadata.labels or {}).get("pod-template-hash")
        if pod_hash and owner.name.endswith(f"-{pod_hash}"):
            return "Deployment", owner.name[: -len(pod_hash) - 1]
    if owner.kind == "Job":
        base, _, suffix = owner.name.rpartition("-")
        if base and suffix.isdigit():
            return "CronJob", base
    return owner.kind, owner.name


class ClusterIndex:
    """Joins pods, nodes, and metrics into one queryable view."""

    def __init__(self, snapshot: ClusterSnapshot, system_namespaces: set[str]):
        self.snapshot = snapshot
        self.now: datetime = snapshot.collected_at
        self.system_namespaces = system_namespaces
        self.pod_usage = self._pod_usage(snapshot.pod_metrics)
        node_usage = {
            item["metadata"]["name"]: Resources(
                quantity(item["usage"].get("cpu")), quantity(item["usage"].get("memory"))
            )
            for item in snapshot.node_metrics
        }
        self.nodes: dict[str, NodeInfo] = {n.metadata.name: self._node(n, node_usage) for n in snapshot.nodes}
        self.pods: list[PodInfo] = [self._pod(p) for p in snapshot.pods]
        self.pods_by_workload: dict[tuple[str, str, str], list[PodInfo]] = defaultdict(list)
        for info in self.pods:
            self.pods_by_workload[(info.namespace, info.workload_kind, info.workload_name)].append(info)
            node = self.nodes.get(info.node)
            if node and info.active:
                node.requests += info.requests
                node.limits += info.limits
                node.pods += 1

    def is_system(self, namespace: str) -> bool:
        return namespace in self.system_namespaces

    @property
    def active_pods(self) -> list[PodInfo]:
        return [p for p in self.pods if p.active]

    @property
    def workload_pods(self) -> list[PodInfo]:
        return [p for p in self.active_pods if not self.is_system(p.namespace)]

    @staticmethod
    def _pod_usage(items: list[dict]) -> dict[tuple[str, str], Resources]:
        usage: dict[tuple[str, str], Resources] = {}
        for item in items:
            total = Resources()
            for container in item.get("containers", []):
                total += Resources(
                    quantity(container["usage"].get("cpu")),
                    quantity(container["usage"].get("memory")),
                )
            usage[(item["metadata"]["namespace"], item["metadata"]["name"])] = total
        return usage

    @staticmethod
    def _node(node: Any, usage: dict[str, Resources]) -> NodeInfo:
        status = node.status
        conditions = {c.type: c.status for c in (status.conditions or [])}
        alloc = status.allocatable or {}
        cap = status.capacity or {}
        return NodeInfo(
            node=node,
            name=node.metadata.name,
            ready=conditions.get("Ready") == "True",
            unschedulable=bool(node.spec.unschedulable),
            allocatable=Resources(quantity(alloc.get("cpu")), quantity(alloc.get("memory"))),
            capacity=Resources(quantity(cap.get("cpu")), quantity(cap.get("memory"))),
            pod_capacity=int(quantity(alloc.get("pods"))),
            usage=usage.get(node.metadata.name),
            pressure=[
                name
                for name in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable")
                if conditions.get(name) == "True"
            ],
        )

    def _pod(self, pod: Any) -> PodInfo:
        requests, limits, missing_req, missing_lim = _container_resources(pod.spec.containers)
        statuses = pod.status.container_statuses or []
        kind, name = workload_of(pod)
        return PodInfo(
            pod=pod,
            namespace=pod.metadata.namespace,
            name=pod.metadata.name,
            node=pod.spec.node_name or "",
            phase=pod.status.phase or "Unknown",
            workload_kind=kind,
            workload_name=name,
            requests=requests,
            limits=limits,
            usage=self.pod_usage.get((pod.metadata.namespace, pod.metadata.name)),
            containers_missing_requests=missing_req,
            containers_missing_memory_limit=missing_lim,
            restarts=sum(s.restart_count for s in statuses),
            ready=pod.status.phase == "Running" and bool(statuses) and all(s.ready for s in statuses),
        )
