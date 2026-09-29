from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "config"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = "dev"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8080

    # Empty URL disables the Prometheus-compatible baseline detector.
    mimir_url: str = ""
    prometheus_url: str = ""
    metrics_backend: str = "prometheus"
    loki_url: str = ""
    tempo_url: str = ""

    kubeconfig: str | None = None
    kube_context: str = ""
    watch_namespaces: str = ""
    event_window_hours: int = 6
    system_namespaces: str = (
        "kube-system,kube-public,kube-node-lease,gatekeeper-system,"
        "calico-system,tigera-operator,cert-manager,ingress-nginx"
    )
    node_warn_percent: float = 80.0
    node_critical_percent: float = 90.0
    cache_ttl_seconds: int = 30

    baseline_window: str = "7d"
    eval_interval_seconds: int = 60
    anomaly_threshold: float = 70.0

    slack_webhook_url: str | None = None
    teams_webhook_url: str | None = None

    demo_mode: bool = False
    config_path: Path = CONFIG_DIR / "default.yaml"
    queries_path: Path = CONFIG_DIR / "queries.yaml"

    @property
    def namespaces(self) -> list[str]:
        return [n.strip() for n in self.watch_namespaces.split(",") if n.strip()]

    @property
    def system_namespace_set(self) -> set[str]:
        return {n.strip() for n in self.system_namespaces.split(",") if n.strip()}

    @property
    def metrics_url(self) -> str:
        if self.metrics_backend.lower() == "mimir":
            return self.mimir_url.rstrip("/")
        return self.prometheus_url.rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return yaml.safe_load(f) or {}


def load_detector_config(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    return load_yaml(settings.config_path)


def load_queries(settings: Settings | None = None) -> dict[str, str]:
    settings = settings or get_settings()
    raw = load_yaml(settings.queries_path)
    return {k: (v.strip() if isinstance(v, str) else v) for k, v in raw.items()}
