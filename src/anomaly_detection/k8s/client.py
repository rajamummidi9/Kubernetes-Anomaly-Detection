from __future__ import annotations

import os
import threading
from dataclasses import dataclass

from kubernetes import client, config

from anomaly_detection.config import Settings

IN_CLUSTER = "in-cluster"
_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


@dataclass(frozen=True)
class ContextInfo:
    name: str
    cluster: str
    user: str
    namespace: str | None = None


def running_in_cluster() -> bool:
    return bool(os.getenv("KUBERNETES_SERVICE_HOST")) and os.path.exists(_TOKEN_PATH)


class KubeClientFactory:
    """Creates isolated API clients per context without mutating global config."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._clients: dict[str, client.ApiClient] = {}
        self._lock = threading.Lock()

    def contexts(self) -> tuple[list[ContextInfo], str | None]:
        if running_in_cluster() and not self.settings.kubeconfig:
            return [ContextInfo(IN_CLUSTER, IN_CLUSTER, "serviceaccount")], IN_CLUSTER
        try:
            raw, active = config.list_kube_config_contexts(
                config_file=self.settings.kubeconfig or None
            )
        except (config.ConfigException, FileNotFoundError):
            return [], None
        items = [
            ContextInfo(
                name=ctx["name"],
                cluster=ctx.get("context", {}).get("cluster", ""),
                user=ctx.get("context", {}).get("user", ""),
                namespace=ctx.get("context", {}).get("namespace"),
            )
            for ctx in raw
        ]
        default = self.settings.kube_context or (active or {}).get("name")
        return items, default

    def default_context(self) -> str | None:
        return self.contexts()[1]

    def get(self, context: str | None) -> tuple[client.ApiClient, str]:
        name = context or self.default_context() or IN_CLUSTER
        with self._lock:
            if name not in self._clients:
                self._clients[name] = self._build(name)
            return self._clients[name], name

    def _build(self, name: str) -> client.ApiClient:
        if name == IN_CLUSTER:
            configuration = client.Configuration()
            config.load_incluster_config(client_configuration=configuration)
            return client.ApiClient(configuration)
        return config.new_client_from_config(
            config_file=self.settings.kubeconfig or None,
            context=name,
        )
