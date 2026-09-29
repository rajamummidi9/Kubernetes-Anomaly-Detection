from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

from anomaly_detection.insights.index import ClusterIndex, PodInfo
from anomaly_detection.insights.model import Affected, Category, Insight

GIB = 1024**3
MIB = 1024**2

CRASH_REASONS = {"CrashLoopBackOff", "RunContainerError"}
IMAGE_REASONS = {"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "ErrImageNeverPull"}
CONFIG_REASONS = {"CreateContainerConfigError", "CreateContainerError"}
CRITICAL_EVENT_REASONS = {
    "BackOff", "FailedScheduling", "FailedMount", "FailedAttachVolume",
    "Evicted", "OOMKilling", "NodeNotReady", "FailedCreatePodSandBox",
}


@dataclass(frozen=True)
class Thresholds:
    window: timedelta = timedelta(hours=6)
    node_warn: float = 80.0
    node_crit: float = 90.0
    pod_density_warn: float = 90.0
    restart_warn: int = 3
    pending_grace: timedelta = timedelta(minutes=5)
    chronic_after: timedelta = timedelta(hours=24)


Rule = Callable[[ClusterIndex, Thresholds], list[Insight]]


def gib(value: float) -> str:
    return f"{value / GIB:.1f} GiB" if value >= GIB else f"{value / MIB:.0f} MiB"


def cores(value: float) -> str:
    return f"{value:.2f} cores" if value >= 1 else f"{value * 1000:.0f}m"


def pct(part: float, whole: float) -> float:
    return part / whole * 100 if whole else 0.0


def age(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    if days:
        return f"{days}d{hours}h"
    if hours:
        return f"{hours}h{rem // 60}m"
    return f"{rem // 60}m"


def _group_pods(pods: Iterable[PodInfo], detail: Callable[[PodInfo], str]) -> list[Affected]:
    grouped: dict[tuple[str, str, str], list[PodInfo]] = defaultdict(list)
    for pod in pods:
        grouped[(pod.namespace, pod.workload_kind, pod.workload_name)].append(pod)
    affected = []
    for (namespace, kind, name), members in grouped.items():
        suffix = f" ({len(members)} pods)" if len(members) > 1 else ""
        affected.append(Affected(namespace, name, detail(members[0]) + suffix, kind))
    return affected


def _workloads(pods: Iterable[PodInfo]) -> int:
    return len({(p.namespace, p.workload_kind, p.workload_name) for p in pods})


def _recent(ts: datetime | None, idx: ClusterIndex, t: Thresholds) -> bool:
    return bool(ts) and ts >= idx.now - t.window


def _templates(idx: ClusterIndex) -> list[tuple[str, Any]]:
    snap = idx.snapshot
    return [("Deployment", d) for d in snap.deployments] + [
        ("StatefulSet", s) for s in snap.statefulsets
    ]


# --------------------------------------------------------------------------- reliability


def node_health(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    out = []
    not_ready = [Affected("", n.name, "Ready condition is not True", "Node") for n in idx.nodes.values() if not n.ready]
    if not_ready:
        out.append(Insight(
            "node-not-ready", Category.reliability, "critical",
            f"{len(not_ready)} node(s) NotReady",
            "Pods on these nodes are not receiving traffic and will be evicted after the toleration period.",
            "Lost capacity and possible workload disruption.",
            "Check kubelet, container runtime, and cloud VM health. Cordon and drain if the node does not recover.",
            f"kubectl describe node {not_ready[0].name}",
            not_ready,
        ))
    pressured = [
        Affected("", n.name, ", ".join(n.pressure), "Node")
        for n in idx.nodes.values() if n.pressure
    ]
    if pressured:
        out.append(Insight(
            "node-pressure", Category.reliability, "critical",
            f"{len(pressured)} node(s) report resource pressure",
            "The kubelet has set pressure conditions and will start evicting pods.",
            "Evictions, failed scheduling, and cascading restarts.",
            "Free disk (image GC, log rotation) or memory on the node, and fix pods without memory limits.",
            f"kubectl describe node {pressured[0].name}",
            pressured,
        ))
    cordoned = [Affected("", n.name, "spec.unschedulable=true", "Node") for n in idx.nodes.values() if n.unschedulable]
    if cordoned:
        out.append(Insight(
            "node-cordoned", Category.configuration, "info",
            f"{len(cordoned)} node(s) cordoned",
            "Cordoned nodes accept no new pods.",
            "Reduced schedulable capacity; easy to forget after maintenance.",
            "Uncordon after maintenance or remove the node from the pool.",
            f"kubectl uncordon {cordoned[0].name}",
            cordoned,
        ))
    return out


def workload_availability(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    down, degraded = [], []
    snap = idx.snapshot
    rows: list[tuple[str, Any, int, int]] = []
    for d in snap.deployments:
        rows.append(("Deployment", d, d.spec.replicas or 0, d.status.available_replicas or 0))
    for s in snap.statefulsets:
        rows.append(("StatefulSet", s, s.spec.replicas or 0, s.status.ready_replicas or 0))
    for ds in snap.daemonsets:
        rows.append(("DaemonSet", ds, ds.status.desired_number_scheduled or 0, ds.status.number_available or 0))
    for kind, obj, desired, available in rows:
        if desired == 0 or available >= desired:
            continue
        item = Affected(obj.metadata.namespace, obj.metadata.name, f"{available}/{desired} available", kind)
        (down if available == 0 else degraded).append(item)
    out = []
    if down:
        first = down[0]
        out.append(Insight(
            "workload-down", Category.reliability, "critical",
            f"{len(down)} workload(s) have zero available replicas",
            "These workloads are fully unavailable.",
            "Outage for every client of these services.",
            "Inspect rollout status and pod events. Roll back if a recent change caused it.",
            f"kubectl -n {first.namespace} rollout status {first.kind.lower()}/{first.name}",
            down,
        ))
    if degraded:
        first = degraded[0]
        out.append(Insight(
            "workload-degraded", Category.reliability, "warning",
            f"{len(degraded)} workload(s) running below desired replicas",
            "Some replicas are unavailable.",
            "Reduced redundancy; one more failure may cause an outage.",
            "Check why the missing replicas are not ready (probes, scheduling, image, config).",
            f"kubectl -n {first.namespace} describe {first.kind.lower()} {first.name}",
            degraded,
        ))
    return out


def container_failures(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    buckets: dict[str, list[tuple[PodInfo, str]]] = defaultdict(list)
    for info in idx.active_pods:
        for status in info.pod.status.container_statuses or []:
            waiting = status.state.waiting if status.state else None
            if not waiting:
                continue
            if waiting.reason in CRASH_REASONS:
                buckets["crash"].append((info, waiting.reason))
            elif waiting.reason in IMAGE_REASONS:
                buckets["image"].append((info, waiting.reason))
            elif waiting.reason in CONFIG_REASONS:
                buckets["config"].append((info, waiting.message or waiting.reason))
    specs = {
        "crash": ("crashloop", "Containers in CrashLoopBackOff",
                  "The container starts and exits repeatedly.",
                  "Service unavailable or flapping; alert and log noise.",
                  "Read the previous container logs and termination reason; check config, secrets, and dependencies.",
                  "kubectl -n {ns} logs {pod} --previous"),
        "image": ("image-pull", "Image pull failures",
                  "The node cannot pull the container image.",
                  "New pods can never start; rollouts and scaling are blocked.",
                  "Verify the image tag exists and that imagePullSecrets or the registry identity are valid.",
                  "kubectl -n {ns} describe pod {pod}"),
        "config": ("container-config", "Container configuration errors",
                   "A referenced ConfigMap, Secret, or key is missing or invalid.",
                   "Pods cannot start until configuration is fixed.",
                   "Create the missing ConfigMap or Secret, or fix the reference in the pod spec.",
                   "kubectl -n {ns} describe pod {pod}"),
    }
    out = []
    for key, items in buckets.items():
        rule_id, title, summary, impact, rec, cmd = specs[key]
        details = {id(p): d for p, d in items}
        affected = _group_pods([p for p, _ in items], lambda p: details[id(p)])
        first = items[0][0]
        out.append(Insight(
            rule_id, Category.reliability, "critical", f"{title} ({len(affected)} workloads)",
            summary, impact, rec, cmd.format(ns=first.namespace, pod=first.name), affected,
        ))
    return out


def oom_and_restarts(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    oom, restarts = [], []
    for info in idx.active_pods:
        recent_oom = False
        recent_term = False
        for status in info.pod.status.container_statuses or []:
            term = status.last_state.terminated if status.last_state else None
            if term and _recent(term.finished_at, idx, t):
                recent_term = True
                if term.reason == "OOMKilled":
                    recent_oom = True
        if recent_oom:
            oom.append(info)
        elif recent_term and info.restarts >= t.restart_warn:
            restarts.append(info)
    out = []
    if oom:
        first = oom[0]
        out.append(Insight(
            "oom-killed", Category.reliability, "critical",
            f"OOMKilled containers in the last {age(t.window)} ({len(oom)} pods)",
            "Containers exceeded their memory limit and were killed by the kernel.",
            "Request failures, lost in-flight work, and restart loops.",
            "Raise the memory limit to observed peak plus 20–30% headroom, or fix the leak. Set requests equal to the steady state.",
            f"kubectl -n {first.namespace} describe pod {first.name}",
            _group_pods(oom, lambda p: f"limit {gib(p.limits.memory) if p.limits.memory else 'none'}, restarts {p.restarts}"),
        ))
    if restarts:
        first = restarts[0]
        out.append(Insight(
            "recent-restarts", Category.reliability, "warning",
            f"Containers restarting recently ({len(restarts)} pods)",
            f"Containers restarted {t.restart_warn}+ times, with at least one exit in the last {age(t.window)}.",
            "Intermittent errors; often failing liveness probes or unhandled exceptions.",
            "Check previous logs and liveness probe timing (initialDelaySeconds, timeoutSeconds).",
            f"kubectl -n {first.namespace} logs {first.name} --previous",
            _group_pods(restarts, lambda p: f"{p.restarts} restarts"),
        ))
    return out


def pending_and_evicted(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    pending, evicted = [], []
    for info in idx.pods:
        pod = info.pod
        created = pod.metadata.creation_timestamp
        if info.phase == "Pending" and created and idx.now - created > t.pending_grace:
            cond = next((c for c in pod.status.conditions or [] if c.type == "PodScheduled" and c.status == "False"), None)
            reason = (cond.message or cond.reason) if cond else "waiting to start"
            pending.append(Affected(info.namespace, info.name, f"{age(idx.now - created)}: {reason}", "Pod"))
        if info.phase == "Failed" and pod.status.reason == "Evicted":
            evicted.append(Affected(info.namespace, info.name, pod.status.message or "Evicted", "Pod"))
    out = []
    if pending:
        out.append(Insight(
            "pending-pods", Category.reliability, "critical",
            f"{len(pending)} pod(s) stuck Pending",
            "The scheduler cannot place these pods, or they are stuck starting.",
            "Missing capacity for scale-out and rollouts.",
            "Read the scheduler message: add node capacity, relax affinity or taints, or right-size requests.",
            f"kubectl -n {pending[0].namespace} describe pod {pending[0].name}",
            pending,
        ))
    if evicted:
        out.append(Insight(
            "evicted-pods", Category.reliability, "warning",
            f"{len(evicted)} evicted pod(s)",
            "The kubelet evicted pods because of node resource pressure.",
            "Evidence of past memory or disk exhaustion; evicted pod objects also clutter the API.",
            "Fix the pressure source (usually missing memory limits), then delete the evicted pod objects.",
            "kubectl get pods -A --field-selector=status.phase=Failed",
            evicted,
        ))
    return out


def resilience(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    snap = idx.snapshot
    ready_nodes = sum(1 for n in idx.nodes.values() if n.ready and not n.unschedulable)
    single, no_pdb, packed, no_readiness = [], [], [], []
    pdbs_by_ns: dict[str, list[Any]] = defaultdict(list)
    for pdb in snap.pdbs:
        pdbs_by_ns[pdb.metadata.namespace].append(pdb)

    for kind, obj in _templates(idx):
        ns, name = obj.metadata.namespace, obj.metadata.name
        if idx.is_system(ns):
            continue
        replicas = obj.spec.replicas if obj.spec.replicas is not None else 1
        if replicas == 0:
            continue
        labels = obj.spec.template.metadata.labels or {}
        if replicas == 1:
            single.append(Affected(ns, name, "replicas: 1", kind))
        elif snap.coverage.get("pdbs") == "ok" and not any(_pdb_matches(p, labels) for p in pdbs_by_ns[ns]):
            no_pdb.append(Affected(ns, name, f"replicas: {replicas}", kind))
        pods = [p for p in idx.pods_by_workload.get((ns, kind, name), []) if p.ready]
        if len(pods) >= 2 and ready_nodes > 1 and len({p.node for p in pods}) == 1:
            packed.append(Affected(ns, name, f"{len(pods)} replicas all on {pods[0].node}", kind))
        missing = [c.name for c in obj.spec.template.spec.containers if not c.readiness_probe]
        if missing:
            no_readiness.append(Affected(ns, name, "containers: " + ", ".join(missing), kind))

    out = []
    if packed:
        out.append(Insight(
            "replicas-same-node", Category.reliability, "warning",
            f"{len(packed)} workload(s) have every replica on one node",
            "Replicas are not spread across nodes.",
            "A single node failure takes down every replica, so the extra replicas give no protection.",
            "Add topologySpreadConstraints (topologyKey: kubernetes.io/hostname) or pod anti-affinity.",
            "topologySpreadConstraints:\n- maxSkew: 1\n  topologyKey: kubernetes.io/hostname\n  whenUnsatisfiable: ScheduleAnyway\n  labelSelector: {matchLabels: {app: <app>}}",
            packed,
        ))
    if no_readiness:
        out.append(Insight(
            "missing-readiness", Category.reliability, "warning",
            f"{len(no_readiness)} workload(s) without readiness probes",
            "Traffic is sent to pods as soon as the container starts.",
            "Errors during startup and rollouts; failed dependencies are not removed from load balancing.",
            "Add a readinessProbe on a lightweight health endpoint.",
            "readinessProbe:\n  httpGet: {path: /health, port: http}\n  periodSeconds: 10\n  failureThreshold: 3",
            no_readiness,
        ))
    if single:
        out.append(Insight(
            "single-replica", Category.reliability, "info",
            f"{len(single)} workload(s) run a single replica",
            "Any node drain, eviction, or crash causes downtime.",
            "Downtime during node upgrades and autoscaler scale-down.",
            "Run at least 2 replicas for request-serving workloads (acceptable for stage or batch).",
            f"kubectl -n {single[0].namespace} scale {single[0].kind.lower()}/{single[0].name} --replicas=2",
            single,
        ))
    if no_pdb:
        out.append(Insight(
            "missing-pdb", Category.reliability, "info",
            f"{len(no_pdb)} multi-replica workload(s) without a PodDisruptionBudget",
            "Voluntary disruptions (node drains, upgrades) can evict every replica at once.",
            "Outage during cluster upgrades or autoscaler consolidation.",
            "Create a PDB with minAvailable: 1 or maxUnavailable: 1.",
            f"kubectl -n {no_pdb[0].namespace} create pdb {no_pdb[0].name} --selector=app={no_pdb[0].name} --max-unavailable=1",
            no_pdb,
        ))
    return out


def _pdb_matches(pdb: Any, labels: dict[str, str]) -> bool:
    selector = pdb.spec.selector
    if selector is None:
        return False
    match = selector.match_labels or {}
    if not match:
        return True  # empty or expression-only selectors: assume covered, avoid false positives
    return all(labels.get(k) == v for k, v in match.items())


def warning_events(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in event_rows(idx, t):
        groups[row["reason"]].append(row)
    out = []
    for reason, rows in groups.items():
        chronic = [r for r in rows if r["chronic"]]
        total = sum(r["count"] for r in rows)
        severity = "critical" if reason in CRITICAL_EVENT_REASONS else "warning"
        first = rows[0]
        if len(rows) == 1:
            title = f"{reason} on {first['kind']}/{first['resource']} ({total:,}× over {first['age']})"
        else:
            title = f"{reason} on {len(rows)} objects ({total:,} occurrences)"
        if chronic:
            title = "Chronic: " + title
        out.append(Insight(
            f"event-{reason.lower()}", Category.reliability, severity,
            title,
            first["message"][:240],
            "Chronic warnings are ongoing problems that dashboards and on-call staff have learned to ignore."
            if chronic else "Active warning signals from the control plane or kubelet.",
            "Fix the root cause shown in the message. Events still firing after 24h are chronic and should be owned.",
            f"kubectl -n {first['namespace'] or 'default'} describe {first['kind'].lower()} {first['resource']}",
            [
                Affected(r["namespace"], r["resource"], f"{r['count']:,}×, first seen {r['age']} ago", r["kind"])
                for r in rows
            ],
            {"chronic": len(chronic), "occurrences": total},
        ))
    return out


def event_rows(idx: ClusterIndex, t: Thresholds) -> list[dict]:
    rows: dict[tuple[str, str, str], dict] = {}
    for ev in idx.snapshot.events:
        series = ev.series
        last = (series.last_observed_time if series else None) or ev.last_timestamp or ev.event_time or ev.metadata.creation_timestamp
        first = ev.first_timestamp or ev.event_time or ev.metadata.creation_timestamp or last
        if not last or last < idx.now - t.window:
            continue
        count = (series.count if series else None) or ev.count or 1
        key = (ev.metadata.namespace or "", ev.involved_object.name or "", ev.reason or "Warning")
        existing = rows.get(key)
        if existing:
            existing["count"] += count
            continue
        rows[key] = {
            "namespace": key[0],
            "resource": key[1],
            "kind": ev.involved_object.kind or "",
            "reason": key[2],
            "message": (ev.message or "").strip(),
            "count": count,
            "first_seen": first.isoformat() if first else None,
            "last_seen": last.isoformat(),
            "age": age(idx.now - first) if first else "?",
            "chronic": bool(first) and idx.now - first > t.chronic_after,
        }
    return sorted(rows.values(), key=lambda r: r["last_seen"], reverse=True)


# --------------------------------------------------------------------------- capacity


def node_utilization(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    out = []
    for label, attr in (("memory", "memory"), ("CPU", "cpu")):
        hot = []
        worst = 0.0
        for n in idx.nodes.values():
            if not n.usage:
                continue
            value = pct(getattr(n.usage, attr), getattr(n.allocatable, attr))
            if value >= t.node_warn:
                worst = max(worst, value)
                used = gib(n.usage.memory) if attr == "memory" else cores(n.usage.cpu)
                hot.append(Affected("", n.name, f"{value:.0f}% used ({used})", "Node"))
        if hot:
            out.append(Insight(
                f"node-{attr}-hot", Category.capacity, "critical" if worst >= t.node_crit else "warning",
                f"{len(hot)} node(s) above {t.node_warn:.0f}% {label} usage",
                f"Peak node {label} usage is {worst:.0f}% of allocatable.",
                "Memory: kernel OOM kills and kubelet evictions. CPU: throttling and latency."
                if attr == "memory" else "CPU contention causes throttling and higher latency.",
                "Rebalance or right-size the heaviest pods, add nodes, or enable cluster autoscaler headroom.",
                f"kubectl top pods -A --sort-by={attr} | head -20",
                hot,
            ))
    dense = [
        Affected("", n.name, f"{n.pods}/{n.pod_capacity} pods", "Node")
        for n in idx.nodes.values()
        if n.pod_capacity and pct(n.pods, n.pod_capacity) >= t.pod_density_warn
    ]
    if dense:
        out.append(Insight(
            "pod-density", Category.capacity, "warning",
            f"{len(dense)} node(s) near max pods",
            "These nodes are close to their maxPods limit.",
            "New pods will fail to schedule even with free CPU and memory.",
            "Add nodes or raise maxPods on the node pool (Azure CNI may also need more IPs).",
            "kubectl get nodes -o custom-columns=NAME:.metadata.name,PODS:.status.allocatable.pods",
            dense,
        ))
    return out


def request_coverage(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    if not idx.snapshot.metrics_available:
        return []
    measured = [p for p in idx.active_pods if p.usage]
    out = []
    for attr, label, fmt, severity_floor in (
        ("memory", "memory", gib, "warning"),
        ("cpu", "CPU", cores, "info"),
    ):
        used = sum(getattr(p.usage, attr) for p in measured)
        requested = sum(getattr(p.requests, attr) for p in measured)
        if used <= 0:
            continue
        coverage = pct(requested, used)
        if coverage >= 70:
            continue
        if attr == "memory":
            severity = "critical" if coverage < 30 else severity_floor
        else:
            severity = "warning" if coverage < 30 else severity_floor
        gaps = sorted(
            (p for p in measured if getattr(p.usage, attr) > getattr(p.requests, attr)),
            key=lambda p: getattr(p.usage, attr) - getattr(p.requests, attr),
            reverse=True,
        )
        out.append(Insight(
            f"{attr}-request-coverage", Category.capacity, severity,
            f"{label} requests cover only {coverage:.0f}% of real usage",
            f"Pods use {fmt(used)} of {label} but request only {fmt(requested)}.",
            "The scheduler packs pods based on requests, so nodes that look empty are actually full. "
            + ("Expect OOM kills and evictions when load rises." if attr == "memory"
               else "Expect CPU contention and noisy neighbours."),
            f"Set {label} requests close to observed steady-state usage (P50–P90), starting with the largest gaps listed.",
            f"resources:\n  requests:\n    {attr}: <observed usage>\n  limits:\n    memory: <peak + 25%>",
            _group_pods(gaps[:60], lambda p, a=attr, f=fmt: f"uses {f(getattr(p.usage, a))}, requests {f(getattr(p.requests, a))}"),
            {"used": used, "requested": requested, "coverage_percent": round(coverage, 1)},
        ))
    return out


def request_saturation(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    nodes = [n for n in idx.nodes.values() if n.ready and not n.unschedulable]
    out = []
    for attr, label, fmt in (("memory", "memory", gib), ("cpu", "CPU", cores)):
        alloc = sum(getattr(n.allocatable, attr) for n in nodes)
        req = sum(getattr(n.requests, attr) for n in nodes)
        share = pct(req, alloc)
        if share < t.node_warn:
            continue
        full = sorted(
            (n for n in nodes if pct(getattr(n.requests, attr), getattr(n.allocatable, attr)) >= t.node_warn),
            key=lambda n: pct(getattr(n.requests, attr), getattr(n.allocatable, attr)),
            reverse=True,
        )
        out.append(Insight(
            f"{attr}-requests-saturated", Category.capacity,
            "critical" if share >= 95 else "warning",
            f"{label.capitalize()} requests reserve {share:.0f}% of schedulable capacity",
            f"Pods request {fmt(req)} of {fmt(alloc)} allocatable {label}.",
            "The scheduler places pods by requests, not usage. New pods, rollout surges, and HPA scale-out will go Pending.",
            "Right-size over-requested workloads first (see the efficiency findings), then add capacity or enable the cluster autoscaler.",
            "kubectl describe nodes | grep -A8 'Allocated resources'",
            [
                Affected("", n.name, f"{pct(getattr(n.requests, attr), getattr(n.allocatable, attr)):.0f}% requested "
                         f"({fmt(getattr(n.requests, attr))} of {fmt(getattr(n.allocatable, attr))})", "Node")
                for n in full
            ],
            {"requested": req, "allocatable": alloc, "percent": round(share, 1)},
        ))
    return out


def headroom(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    nodes = [n for n in idx.nodes.values() if n.ready and not n.unschedulable]
    if len(nodes) < 2:
        return []
    out = []
    for attr, label, fmt in (("memory", "memory", gib), ("cpu", "CPU", cores)):
        total = sum(getattr(n.allocatable, attr) for n in nodes)
        largest = max(getattr(n.allocatable, attr) for n in nodes)
        demand_usage = sum(getattr(n.usage, attr) for n in nodes if n.usage)
        demand_requests = sum(getattr(n.requests, attr) for n in nodes)
        demand = max(demand_usage, demand_requests)
        survivable = total - largest
        if demand > survivable:
            out.append(Insight(
                f"n-plus-one-{attr}", Category.capacity, "warning",
                f"Cluster cannot absorb losing its largest node ({label})",
                f"Current {label} demand is {fmt(demand)}; without the largest node only {fmt(survivable)} remains.",
                "A single node failure or upgrade surge leaves pods unschedulable or OOM-killed.",
                "Keep N+1 headroom: add a node, enable the cluster autoscaler, or reduce demand.",
                "kubectl get nodes -L agentpool,node.kubernetes.io/instance-type",
                [Affected("", "cluster", f"demand {fmt(demand)} vs N-1 capacity {fmt(survivable)}", "Cluster")],
                {"demand": demand, "survivable": survivable},
            ))
    return out


# --------------------------------------------------------------------------- efficiency


def missing_resources(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    pods = idx.workload_pods
    no_req = [p for p in pods if p.containers_missing_requests]
    no_lim = [p for p in pods if p.containers_missing_memory_limit]
    out = []
    if no_req:
        besteffort = sum(1 for p in no_req if (p.pod.status.qos_class or "") == "BestEffort")
        out.append(Insight(
            "missing-requests", Category.efficiency, "warning",
            f"{_workloads(no_req)} workload(s) missing CPU/memory requests",
            f"{len(no_req)} of {len(pods)} pods have containers without requests ({besteffort} BestEffort).",
            "Unpredictable scheduling. BestEffort pods are evicted first under pressure and HPA cannot use CPU utilisation.",
            "Define requests for every container. Enforce with a LimitRange default or an admission policy.",
            "apiVersion: v1\nkind: LimitRange\nmetadata: {name: defaults}\nspec:\n  limits:\n  - type: Container\n    defaultRequest: {cpu: 50m, memory: 128Mi}\n    default: {memory: 512Mi}",
            _group_pods(no_req, lambda p: "containers: " + ", ".join(p.containers_missing_requests)),
            {"pods": len(no_req), "besteffort": besteffort},
        ))
    if no_lim:
        out.append(Insight(
            "missing-memory-limits", Category.efficiency, "info",
            f"{_workloads(no_lim)} workload(s) without memory limits",
            f"{len(no_lim)} pods can grow memory without bound.",
            "One leaking pod can exhaust a node and trigger evictions for its neighbours.",
            "Set a memory limit at observed peak plus headroom.",
            "",
            _group_pods(no_lim, lambda p: "containers: " + ", ".join(p.containers_missing_memory_limit)),
        ))
    return out


def rightsizing(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    if not idx.snapshot.metrics_available:
        return []
    per_workload: dict[tuple[str, str, str], list[PodInfo]] = defaultdict(list)
    near_limit = []
    for p in idx.active_pods:
        if not p.usage:
            continue
        per_workload[(p.namespace, p.workload_kind, p.workload_name)].append(p)
        if p.limits.memory and p.usage.memory >= 0.9 * p.limits.memory:
            near_limit.append(p)

    idle: list[tuple[float, float, Affected]] = []
    for (ns, kind, name), pods in per_workload.items():
        req_cpu = sum(p.requests.cpu for p in pods)
        req_mem = sum(p.requests.memory for p in pods)
        use_cpu = sum(p.usage.cpu for p in pods)
        use_mem = sum(p.usage.memory for p in pods)
        spare_cpu = max(0.0, req_cpu - use_cpu * 1.3) if req_cpu >= 0.2 and use_cpu < 0.25 * req_cpu else 0.0
        spare_mem = max(0.0, req_mem - use_mem * 1.3) if req_mem >= 256 * MIB and use_mem < 0.35 * req_mem else 0.0
        if spare_cpu or spare_mem:
            idle.append((spare_cpu, spare_mem, Affected(
                ns, name,
                f"CPU {cores(use_cpu)}/{cores(req_cpu)}, memory {gib(use_mem)}/{gib(req_mem)} used/requested",
                kind,
            )))
    out = []
    if idle:
        idle.sort(key=lambda x: (x[1] / GIB) + x[0], reverse=True)
        cpu_total = sum(i[0] for i in idle)
        mem_total = sum(i[1] for i in idle)
        out.append(Insight(
            "overprovisioned", Category.efficiency, "info",
            f"Reclaim ~{cores(cpu_total)} and ~{gib(mem_total)} of idle requests",
            f"{len(idle)} workload(s) request far more than they use.",
            "Reserved but idle capacity blocks scheduling and adds node cost.",
            "Lower requests to P90 usage plus ~30% headroom. Validate with a week of metrics or the VPA recommender.",
            "kubectl top pods -A --sort-by=memory",
            [i[2] for i in idle],
            {"reclaimable_cpu": cpu_total, "reclaimable_memory": mem_total},
        ))
    if near_limit:
        out.append(Insight(
            "near-memory-limit", Category.efficiency, "warning",
            f"{len(near_limit)} pod(s) using ≥90% of their memory limit",
            "These containers are one spike away from being OOMKilled.",
            "Imminent OOM kills and restarts.",
            "Raise the memory limit or investigate memory growth before it fails.",
            f"kubectl -n {near_limit[0].namespace} top pod {near_limit[0].name} --containers",
            _group_pods(near_limit, lambda p: f"{gib(p.usage.memory)} of {gib(p.limits.memory)} limit"),
        ))
    return out


def leftovers(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    done = [p for p in idx.pods if p.phase in {"Succeeded", "Failed"} and p.pod.status.reason != "Evicted"]
    if len(done) < 10:
        return []
    return [Insight(
        "finished-pods", Category.efficiency, "info",
        f"{len(done)} completed or failed pods left in the cluster",
        "Finished pod objects are never garbage-collected unless configured.",
        "API and etcd load, noisy kubectl output, and slower controllers.",
        "Set ttlSecondsAfterFinished on Jobs and successfulJobsHistoryLimit/failedJobsHistoryLimit on CronJobs.",
        "kubectl delete pods -A --field-selector=status.phase==Succeeded",
        _group_pods(done, lambda p: p.phase),
    )]


# --------------------------------------------------------------------------- security


def security(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    privileged, root, mutable = [], [], []
    for p in idx.workload_pods:
        spec = p.pod.spec
        pod_sc = spec.security_context
        host = [n for n, v in (("hostNetwork", spec.host_network), ("hostPID", spec.host_pid), ("hostIPC", spec.host_ipc)) if v]
        priv = [c.name for c in spec.containers if c.security_context and c.security_context.privileged]
        if host or priv:
            privileged.append((p, ", ".join(host + [f"privileged:{c}" for c in priv])))
        pod_nonroot = bool(pod_sc and (pod_sc.run_as_non_root or (pod_sc.run_as_user or 0) > 0))
        for c in spec.containers:
            sc = c.security_context
            if not (pod_nonroot or (sc and (sc.run_as_non_root or (sc.run_as_user or 0) > 0))):
                root.append(p)
                break
        bad = [c.image for c in spec.containers if _mutable_tag(c.image)]
        if bad:
            mutable.append((p, ", ".join(bad)))
    out = []
    if privileged:
        details = {id(p): d for p, d in privileged}
        out.append(Insight(
            "privileged", Category.security, "warning",
            f"{_workloads(p for p, _ in privileged)} workload(s) with privileged or host access",
            "Containers run privileged or share host namespaces.",
            "A container compromise becomes a node compromise.",
            "Remove privileged, hostNetwork, and hostPID unless strictly needed; enforce Pod Security Admission 'baseline'.",
            "kubectl label ns <namespace> pod-security.kubernetes.io/enforce=baseline",
            _group_pods([p for p, _ in privileged], lambda p: details[id(p)]),
        ))
    if mutable:
        details = {id(p): d for p, d in mutable}
        out.append(Insight(
            "mutable-image-tag", Category.security, "warning",
            f"{_workloads(p for p, _ in mutable)} workload(s) use ':latest' or untagged images",
            "The image a pod runs depends on when it was pulled.",
            "Non-reproducible rollouts, silent version drift between replicas, and no clean rollback.",
            "Pin images to an immutable version tag or digest from your CI pipeline.",
            "image: myregistry.azurecr.io/app:1.4.2   # or @sha256:<digest>",
            _group_pods([p for p, _ in mutable], lambda p: details[id(p)]),
        ))
    if root:
        out.append(Insight(
            "run-as-root", Category.security, "info",
            f"{_workloads(root)} workload(s) may run as root",
            "Neither runAsNonRoot nor a non-zero runAsUser is set.",
            "Larger blast radius if the container is compromised.",
            "Set securityContext.runAsNonRoot: true and build images with a non-root USER.",
            "securityContext:\n  runAsNonRoot: true\n  allowPrivilegeEscalation: false",
            _group_pods(root, lambda p: "no runAsNonRoot"),
        ))
    return out


def _mutable_tag(image: str) -> bool:
    if "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


# --------------------------------------------------------------------------- configuration


def autoscaling(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    maxed, broken, fixed = [], [], []
    for hpa in idx.snapshot.hpas:
        ns, name = hpa.metadata.namespace, hpa.metadata.name
        current = hpa.status.current_replicas or 0
        minimum = hpa.spec.min_replicas or 1
        if minimum >= hpa.spec.max_replicas:
            fixed.append(Affected(ns, name, f"min {minimum} = max {hpa.spec.max_replicas}", "HorizontalPodAutoscaler"))
        elif current >= hpa.spec.max_replicas:
            maxed.append(Affected(ns, name, f"{current}/{hpa.spec.max_replicas} replicas", "HorizontalPodAutoscaler"))
        for cond in hpa.status.conditions or []:
            if cond.type in {"ScalingActive", "AbleToScale"} and cond.status == "False":
                broken.append(Affected(ns, name, f"{cond.reason}: {cond.message}", "HorizontalPodAutoscaler"))
                break
    out = []
    if maxed:
        out.append(Insight(
            "hpa-maxed", Category.configuration, "warning",
            f"{len(maxed)} HPA(s) pinned at maxReplicas",
            "Demand exceeds what these autoscalers are allowed to provide.",
            "Latency and errors grow with load, with no further scale-out.",
            "Raise maxReplicas (and check node capacity), or optimise the workload.",
            f"kubectl -n {maxed[0].namespace} describe hpa {maxed[0].name}",
            maxed,
        ))
    if broken:
        out.append(Insight(
            "hpa-broken", Category.configuration, "warning",
            f"{len(broken)} HPA(s) unable to scale",
            "The autoscaler cannot read metrics or reach its target.",
            "Autoscaling is silently disabled.",
            "Usually missing CPU requests on the target or a broken metrics pipeline; fix the reported reason.",
            f"kubectl -n {broken[0].namespace} describe hpa {broken[0].name}",
            broken,
        ))
    if fixed:
        out.append(Insight(
            "hpa-fixed", Category.configuration, "info",
            f"{len(fixed)} HPA(s) have minReplicas equal to maxReplicas",
            "These autoscalers can never scale.",
            "The HPA object gives a false sense of elasticity.",
            "Set maxReplicas above minReplicas, or remove the HPA and set replicas explicitly.",
            f"kubectl -n {fixed[0].namespace} patch hpa {fixed[0].name} -p '{{\"spec\":{{\"maxReplicas\":4}}}}'",
            fixed,
        ))
    return out


def platform(idx: ClusterIndex, t: Thresholds) -> list[Insight]:
    snap = idx.snapshot
    out = []
    versions: dict[str, list[str]] = defaultdict(list)
    for n in idx.nodes.values():
        versions[n.node.status.node_info.kubelet_version].append(n.name)
    if len(versions) > 1:
        out.append(Insight(
            "kubelet-skew", Category.configuration, "info",
            f"{len(versions)} kubelet versions across nodes",
            "Node pools are on different Kubernetes versions: " + ", ".join(sorted(versions)),
            "Inconsistent behaviour between nodes; upgrade drift.",
            "Upgrade the lagging node pools to match the control plane.",
            "kubectl get nodes -o wide",
            [Affected("", v, f"{len(names)} node(s)", "Version") for v, names in versions.items()],
        ))
    if snap.coverage.get("pod_metrics") != "ok" or not snap.pod_metrics:
        out.append(Insight(
            "metrics-unavailable", Category.configuration, "warning",
            "Metrics API (metrics-server) is not available",
            f"metrics.k8s.io returned: {snap.coverage.get('pod_metrics', 'no data')}.",
            "Usage-based insights, kubectl top, and CPU/memory HPAs do not work.",
            "Install or repair metrics-server.",
            "kubectl get apiservice v1beta1.metrics.k8s.io",
        ))
    gaps = {k: v for k, v in snap.coverage.items() if v != "ok" and not k.endswith("metrics")}
    if gaps:
        out.append(Insight(
            "coverage-gaps", Category.configuration, "info",
            f"Analysis is partial: {len(gaps)} resource type(s) not readable",
            ", ".join(f"{k}: {v}" for k, v in gaps.items()),
            "Insights depending on these resources are skipped.",
            "Grant list/watch on these resources to the analyzer identity (see k8s/rbac.yaml).",
            "kubectl auth can-i --list",
        ))
    return out


RULES: list[Rule] = [
    node_health, workload_availability, container_failures, oom_and_restarts,
    pending_and_evicted, resilience, warning_events,
    node_utilization, request_saturation, request_coverage, headroom,
    missing_resources, rightsizing, leftovers,
    security, autoscaling, platform,
]
