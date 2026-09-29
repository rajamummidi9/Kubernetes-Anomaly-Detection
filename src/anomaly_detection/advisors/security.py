"""Security posture advice derived from a read-only snapshot."""

from __future__ import annotations

from typing import Any

from anomaly_detection.insights.index import workload_of
from anomaly_detection.k8s.snapshot import ClusterSnapshot

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH"}
PSA_LABEL = "pod-security.kubernetes.io/enforce"
ADMIN_ROLES = {"cluster-admin"}
# Local accounts Azure Kubernetes Service creates on every cluster.
AKS_LOCAL_USERS = {"clusterAdmin", "clusterUser", "masterclient"}


def _item(item_id: str, severity: str, title: str, advice: str, action: str = "") -> dict[str, str]:
    return {"id": item_id, "severity": severity, "title": title, "advice": advice, "action": action}


def _names(pairs: list[tuple[str, str]], limit: int = 8) -> str:
    shown = [f"{ns}/{name}" for ns, name in pairs[:limit]]
    extra = len(pairs) - len(shown)
    text = ", ".join(shown)
    return f"{text} (+{extra} more)" if extra > 0 else text


def security_advice(snapshot: ClusterSnapshot, system_namespaces: set[str]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    items.extend(_pod_security(snapshot, system_namespaces))
    items.extend(_admission(snapshot, system_namespaces))
    items.extend(_rbac(snapshot, system_namespaces))
    items.extend(_exposure(snapshot))
    rank = {"warning": 0, "info": 1}
    items.sort(key=lambda i: rank.get(i["severity"], 9))
    return items


def _pod_security(snapshot: ClusterSnapshot, system_namespaces: set[str]) -> list[dict[str, str]]:
    caps: list[tuple[str, str]] = []
    host_paths: list[tuple[str, str]] = []
    default_sa: list[tuple[str, str]] = []
    seen_caps: set[tuple[str, str]] = set()
    seen_host: set[tuple[str, str]] = set()
    seen_sa: set[tuple[str, str]] = set()
    for pod in snapshot.pods:
        if (pod.status.phase if pod.status else "") in {"Succeeded", "Failed"}:
            continue
        meta = pod.metadata
        if meta.namespace in system_namespaces:
            continue
        spec = pod.spec
        if spec is None:
            continue
        kind, name = workload_of(pod)
        key = (meta.namespace, f"{kind}/{name}")
        added = []
        for container in spec.containers or []:
            sc = container.security_context
            added.extend((sc.capabilities.add or []) if sc and sc.capabilities else [])
        if any(c in DANGEROUS_CAPS for c in added) and key not in seen_caps:
            seen_caps.add(key)
            caps.append(key)
        if any(v.host_path for v in spec.volumes or []) and key not in seen_host:
            seen_host.add(key)
            host_paths.append(key)
        account = spec.service_account_name or spec.service_account or "default"
        if account == "default" and spec.automount_service_account_token is not False and key not in seen_sa:
            seen_sa.add(key)
            default_sa.append(key)

    out = []
    if caps:
        out.append(_item(
            "dangerous-capabilities", "warning",
            f"{len(caps)} workload(s) add high-risk capabilities",
            "Capabilities such as SYS_ADMIN or NET_ADMIN are close to full root on the node. "
            f"Seen on {_names(caps)}.",
            "securityContext:\n  capabilities:\n    drop: [\"ALL\"]\n    add: []   # only the specific cap the process needs",
        ))
    if host_paths:
        out.append(_item(
            "host-path", "warning",
            f"{len(host_paths)} workload(s) mount hostPath volumes",
            "A hostPath mount lets a container read or write the node filesystem. "
            f"Seen on {_names(host_paths)}. Prefer an emptyDir, a PVC, or a projected volume.",
            "kubectl -n <namespace> get pod <name> -o jsonpath='{.spec.volumes}'",
        ))
    if default_sa:
        out.append(_item(
            "default-service-account", "info",
            f"{len(default_sa)} workload(s) use the default ServiceAccount with a mounted token",
            "The default account is easy to grant permissions to by accident, and the token is "
            f"available inside the container. Seen on {_names(default_sa)}.",
            "automountServiceAccountToken: false\n# or a dedicated ServiceAccount with a tight Role",
        ))
    return out


def _admission(snapshot: ClusterSnapshot, system_namespaces: set[str]) -> list[dict[str, str]]:
    if snapshot.coverage.get("namespaces") not in (None, "ok"):
        return []
    weak = []
    for ns in snapshot.namespaces:
        name = ns.metadata.name
        if name in system_namespaces:
            continue
        level = (ns.metadata.labels or {}).get(PSA_LABEL)
        if level not in {"baseline", "restricted"}:
            weak.append((name, level or "unset"))
    if not weak:
        return []
    shown = ", ".join(f"{name} ({level})" for name, level in weak[:8])
    extra = f" (+{len(weak) - 8} more)" if len(weak) > 8 else ""
    return [_item(
        "psa-enforce", "warning",
        f"{len(weak)} namespace(s) do not enforce Pod Security baseline",
        "Without pod-security.kubernetes.io/enforce, privileged pods can be created "
        f"in application namespaces. {shown}{extra}.",
        "kubectl label ns <namespace> pod-security.kubernetes.io/enforce=baseline "
        "pod-security.kubernetes.io/warn=restricted --overwrite",
    )]


def _rbac(snapshot: ClusterSnapshot, system_namespaces: set[str]) -> list[dict[str, str]]:
    status = snapshot.coverage.get("cluster_role_bindings")
    if status is None:
        return []
    if status != "ok":
        return [_item(
            "rbac-unreadable", "info",
            "Cluster-admin bindings were not reviewed",
            f"clusterrolebindings: {status}. Grant get/list on clusterrolebindings to include this check.",
            "kubectl auth can-i list clusterrolebindings",
        )]
    flagged, aks_local, aks_command = [], [], []
    for binding in snapshot.cluster_role_bindings:
        ref = binding.role_ref
        if ref is None or ref.kind != "ClusterRole" or ref.name not in ADMIN_ROLES:
            continue
        binding_name = binding.metadata.name
        for subject in binding.subjects or []:
            if _builtin_subject(subject, system_namespaces):
                continue
            who = _subject_label(subject)
            kind = _subject_bucket(subject, binding_name)
            if kind == "aks-local":
                aks_local.append(who)
            elif kind == "aks-command":
                aks_command.append(f"{who} via {binding_name}")
            else:
                flagged.append(f"{who} via {binding_name}")
    out = []
    if flagged:
        out.append(_item(
            "cluster-admin-bindings", "warning",
            f"{len(flagged)} cluster-admin binding(s) outside the control plane",
            "cluster-admin can read Secrets and change anything in the cluster. "
            + "; ".join(flagged[:6]) + ("…" if len(flagged) > 6 else "") + ". "
            "Grant each subject only the verbs it needs. An application account should have a namespace Role. "
            "A backup tool such as Velero needs its own ClusterRole, not cluster-admin.",
            "kubectl get clusterrolebindings -o wide",
        ))
    if aks_command:
        out.append(_item(
            "aks-run-command", "warning",
            f"{len(aks_command)} AKS run-command {'identity' if len(aks_command) == 1 else 'identities'} still have cluster-admin",
            "AKS creates a ServiceAccount in aks-command for each run command and binds it to cluster-admin. "
            "Finished commands should not leave that binding behind. "
            + "; ".join(aks_command[:4]) + ("…" if len(aks_command) > 4 else ""),
            "kubectl delete clusterrolebinding <name>  # only after the command has finished",
        ))
    if aks_local:
        out.append(_item(
            "aks-local-accounts", "info",
            "AKS local accounts have cluster-admin",
            "clusterAdmin and clusterUser are the local accounts AKS creates. "
            "Disable local accounts and use Azure RBAC if nobody signs in with them. "
            + ", ".join(sorted(set(aks_local))),
            "az aks update -g <group> -n <cluster> --disable-local-accounts",
        ))
    return out


def _subject_label(subject: Any) -> str:
    if subject.kind == "ServiceAccount":
        return f"ServiceAccount {subject.namespace}/{subject.name}"
    return f"{subject.kind} {subject.name}"


def _subject_bucket(subject: Any, binding_name: str) -> str:
    if subject.kind == "User" and (subject.name or "") in AKS_LOCAL_USERS:
        return "aks-local"
    if binding_name == "aks-cluster-admin-binding" and subject.kind == "User":
        return "aks-local"
    if subject.kind == "ServiceAccount" and subject.namespace == "aks-command":
        return "aks-command"
    return "other"


def _builtin_subject(subject: Any, system_namespaces: set[str]) -> bool:
    name = subject.name or ""
    if name.startswith("system:"):
        return True
    return subject.kind == "ServiceAccount" and (subject.namespace or "") in system_namespaces


def _exposure(snapshot: ClusterSnapshot) -> list[dict[str, str]]:
    out = []
    if snapshot.coverage.get("services") == "ok":
        public = []
        for svc in snapshot.services:
            if svc.spec and svc.spec.type == "LoadBalancer":
                public.append((svc.metadata.namespace, svc.metadata.name))
        if public:
            out.append(_item(
                "load-balancers", "info",
                f"{len(public)} LoadBalancer service(s) publish a port outside the cluster",
                "Confirm each one should be reachable, and prefer an internal load balancer "
                f"for private APIs. {_names(public)}.",
                "kubectl get svc -A --field-selector spec.type=LoadBalancer",
            ))
    if snapshot.coverage.get("ingresses") == "ok":
        plain = []
        for ing in snapshot.ingresses:
            if not (ing.spec and ing.spec.tls):
                plain.append((ing.metadata.namespace, ing.metadata.name))
        if plain:
            out.append(_item(
                "ingress-without-tls", "warning",
                f"{len(plain)} Ingress(es) have no TLS section",
                f"Traffic to these hosts can travel in clear text. {_names(plain)}.",
                "spec:\n  tls:\n    - hosts: [app.example.com]\n      secretName: app-tls",
            ))
    return out


def security_summary(items: list[dict[str, str]]) -> tuple[str, str]:
    warnings = sum(i["severity"] == "warning" for i in items)
    if warnings:
        return "needs-attention", f"{warnings} security item(s) to review before this cluster is treated as hardened."
    if items:
        return "fair", "No high-risk access stood out. A few hardening steps are still open."
    return "good", "No privileged host access, clear-text ingresses, or unexpected cluster-admin bindings stood out."
