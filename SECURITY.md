# Security

## Reporting a vulnerability

Open a private security advisory on
[rajamummidi9/Kubernetes-Anomaly-Detection](https://github.com/rajamummidi9/Kubernetes-Anomaly-Detection/security/advisories/new).
Please do not file a public issue for an unfixed vulnerability.

## What this project is allowed to do

The analyzer is read-only. The Helm chart and `k8s/rbac.yaml` grant `get`,
`list`, and `watch` only. It does not need a kubeconfig with write access, and
the container runs as a non-root user with a read-only root filesystem.

The dashboard and `/v1/analysis` show workload names, warning events, resource
requests, image references, and security gaps. Treat that response as cluster
internals.

## How to deploy it safely

- Keep the Service as `ClusterIP` and reach it with `kubectl port-forward`, or
  put an authenticating proxy in front of Ingress. The chart leaves Ingress off
  for this reason.
- Do not publish the Service as a public LoadBalancer.
- Give it the chart's ClusterRole, not `cluster-admin`.
- Leave `kubeconfig.existingSecret` empty unless this install must analyze a
  different cluster. That Secret is mounted read-only.
- Set `config.prometheusUrl` only to a metrics endpoint you trust. The process
  sends PromQL there. It does not send cluster data anywhere else.

## AI data boundary

The optional intelligence layer sends a compact report to the configured model
provider: scores, resource totals, finding text, warning events, deterministic
investigations, and forecasts. It does not send Kubernetes Secret objects,
environment variables, a kubeconfig, or raw pod specs. Secret-like fields,
authorization headers, JWTs, and private-key blocks are redacted and the payload
is size-limited.

Kubernetes object names and event messages are treated as untrusted prompt
content. The model has no tools and cannot call Kubernetes. Its JSON response is
schema-validated, but it is still a hypothesis. Do not automatically execute AI
commands or remediation.

Keep `AI_API_KEY` and webhook URLs in a Kubernetes Secret referenced by
`intelligence.existingSecret`; never put them in Helm values or Git.

## Scope

Advisors suggest checks. They do not apply changes, open shells on nodes, or
collect Secrets. Confirm a recommendation before acting on it.
