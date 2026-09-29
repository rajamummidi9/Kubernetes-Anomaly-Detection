# k8s-anomaly-detection

Read-only health, security, upgrade, and incident analysis. Install it in the
cluster you want to analyze. It uses a ServiceAccount and never writes to the API.

```bash
helm install anomaly charts/k8s-anomaly-detection \
  --namespace anomaly-detection --create-namespace
```

Source: https://github.com/rajamummidi9/Kubernetes-Anomaly-Detection

The default image is `ghcr.io/rajamummidi9/kubernetes-anomaly-detection`.
Build and push the Dockerfile to that registry before the first install, or
override `image.repository`.

```bash
kubectl -n anomaly-detection port-forward svc/anomaly-k8s-anomaly-detection 8080:8080
```

The release name is prefixed to the chart name, so the Service name above matches
`helm install anomaly`. `helm status` prints the exact port-forward command.

## What you should set

| Value | Why |
|---|---|
| `image.repository` | Defaults to `ghcr.io/rajamummidi9/kubernetes-anomaly-detection`. Tag defaults to the chart `appVersion`. |
| `config.prometheusUrl` | Enables the baseline detector. Leave empty to disable it. |
| `config.watchNamespaces` | Limit the analysis. Empty means the whole cluster. |
| `config.systemNamespaces` | Namespaces skipped by hygiene and security-admission checks. |
| `ingress.enabled` | Off by default. Add an auth annotation before turning it on. |
| `networkPolicy.enabled` | Limits who can open the dashboard. Egress stays open for the API server. |
| `kubeconfig.existingSecret` | Only when this install should analyze a different cluster. The Secret key must be `kubeconfig`. |

## Permissions

The ClusterRole is `get`, `list`, and `watch` on pods, nodes, events, namespaces,
services, workloads, HPAs, PodDisruptionBudgets, Ingresses, ClusterRoleBindings,
and the Metrics API. It cannot create, update, or delete anything.
