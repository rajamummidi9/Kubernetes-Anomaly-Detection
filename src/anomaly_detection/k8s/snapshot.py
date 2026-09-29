from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from kubernetes import client
from kubernetes.client.rest import ApiException

REQUEST_TIMEOUT = 30
PAGE_SIZE = 500


@dataclass
class ClusterSnapshot:
    context: str
    collected_at: datetime
    server_version: str = ""
    namespaces: list[Any] = field(default_factory=list)
    nodes: list[Any] = field(default_factory=list)
    pods: list[Any] = field(default_factory=list)
    deployments: list[Any] = field(default_factory=list)
    statefulsets: list[Any] = field(default_factory=list)
    daemonsets: list[Any] = field(default_factory=list)
    hpas: list[Any] = field(default_factory=list)
    pdbs: list[Any] = field(default_factory=list)
    events: list[Any] = field(default_factory=list)
    services: list[Any] = field(default_factory=list)
    ingresses: list[Any] = field(default_factory=list)
    cluster_role_bindings: list[Any] = field(default_factory=list)
    network_policies: list[Any] = field(default_factory=list)
    jobs: list[Any] = field(default_factory=list)
    cronjobs: list[Any] = field(default_factory=list)
    node_metrics: list[dict] = field(default_factory=list)
    pod_metrics: list[dict] = field(default_factory=list)
    # resource name -> "ok" | "forbidden" | "unavailable" | "error: ..."
    coverage: dict[str, str] = field(default_factory=dict)

    @property
    def metrics_available(self) -> bool:
        return self.coverage.get("pod_metrics") == "ok" and bool(self.pod_metrics)


def _paged(fn: Callable[..., Any], **kwargs: Any) -> list[Any]:
    items: list[Any] = []
    token: str | None = None
    while True:
        resp = fn(limit=PAGE_SIZE, _continue=token, _request_timeout=REQUEST_TIMEOUT, **kwargs)
        items.extend(resp.items)
        token = resp.metadata._continue
        if not token:
            return items


def _status(exc: Exception) -> str:
    if isinstance(exc, ApiException):
        if exc.status == 403:
            return "forbidden"
        if exc.status == 404:
            return "unavailable"
        return f"error: HTTP {exc.status} {exc.reason}"
    return f"error: {type(exc).__name__}: {exc}"


def fetch_snapshot(api: client.ApiClient, context: str) -> ClusterSnapshot:
    """Fetch every resource the analyzers need; missing access degrades, never fails."""
    core = client.CoreV1Api(api)
    apps = client.AppsV1Api(api)
    autoscaling = client.AutoscalingV2Api(api)
    policy = client.PolicyV1Api(api)
    custom = client.CustomObjectsApi(api)
    networking = client.NetworkingV1Api(api)
    rbac = client.RbacAuthorizationV1Api(api)
    batch = client.BatchV1Api(api)

    def metrics(plural: str) -> list[dict]:
        result = custom.list_cluster_custom_object(
            "metrics.k8s.io", "v1beta1", plural, _request_timeout=REQUEST_TIMEOUT
        )
        return result.get("items", [])

    jobs: dict[str, Callable[[], Any]] = {
        "namespaces": lambda: _paged(core.list_namespace),
        "nodes": lambda: _paged(core.list_node),
        "pods": lambda: _paged(core.list_pod_for_all_namespaces),
        "deployments": lambda: _paged(apps.list_deployment_for_all_namespaces),
        "statefulsets": lambda: _paged(apps.list_stateful_set_for_all_namespaces),
        "daemonsets": lambda: _paged(apps.list_daemon_set_for_all_namespaces),
        "hpas": lambda: _paged(autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces),
        "pdbs": lambda: _paged(policy.list_pod_disruption_budget_for_all_namespaces),
        "events": lambda: _paged(core.list_event_for_all_namespaces, field_selector="type=Warning"),
        "services": lambda: _paged(core.list_service_for_all_namespaces),
        "ingresses": lambda: _paged(networking.list_ingress_for_all_namespaces),
        "cluster_role_bindings": lambda: _paged(rbac.list_cluster_role_binding),
        "network_policies": lambda: _paged(networking.list_network_policy_for_all_namespaces),
        "jobs": lambda: _paged(batch.list_job_for_all_namespaces),
        "cronjobs": lambda: _paged(batch.list_cron_job_for_all_namespaces),
        "node_metrics": lambda: metrics("nodes"),
        "pod_metrics": lambda: metrics("pods"),
    }

    snapshot = ClusterSnapshot(context=context, collected_at=datetime.now(timezone.utc))
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {name: pool.submit(job) for name, job in jobs.items()}
        for name, future in futures.items():
            try:
                setattr(snapshot, name, future.result())
                snapshot.coverage[name] = "ok"
            except Exception as exc:  # noqa: BLE001 - recorded as coverage gap
                snapshot.coverage[name] = _status(exc)

    try:
        info = client.VersionApi(api).get_code(_request_timeout=REQUEST_TIMEOUT)
        snapshot.server_version = info.git_version
    except Exception:  # noqa: BLE001
        pass
    return snapshot
