# Contributing

```bash
make install
make test
```

`make test` runs the unit tests. They build a cluster from Kubernetes API
objects, so they do not need a kubeconfig.

## Where changes go

- A new health check is a function in `src/anomaly_detection/insights/rules.py`,
  appended to `RULES`. It receives the `ClusterIndex` and returns `Insight`s.
  Raise nothing on purpose: a failing rule is recorded and the rest of the
  report still renders.
- Security advice, the upgrade plan, and incident investigations live in
  `src/anomaly_detection/advisors/`. Keep them explanatory. A check command is
  fine; a change that mutates the cluster is not.
- The release catalog in `advisors/releases.py` is dated. Update it when you
  cut a release so upgrade advice does not drift from [kubernetes.io/releases](https://kubernetes.io/releases/).

## Helm

The chart in `charts/k8s-anomaly-detection` is the supported install.
`k8s/` is a minimal example of the same workload. When you add an API resource
to the snapshot, add the matching `get`/`list`/`watch` rule to both RBAC files.

```bash
helm lint charts/k8s-anomaly-detection
helm template anomaly charts/k8s-anomaly-detection >/dev/null
```
