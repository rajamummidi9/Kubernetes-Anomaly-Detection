# PromQL reference

Templates live in `config/queries.yaml`. The collector substitutes `{namespace}`, `{service}`, `{pod}`, and `{window}`.

## Core queries

### CPU

```promql
sum by (namespace, pod) (
  rate(container_cpu_usage_seconds_total{namespace="prod", container!="", container!="POD"}[5m])
)
```

### Memory

```promql
sum by (namespace, pod) (
  container_memory_working_set_bytes{namespace="prod", container!="", container!="POD"}
)
```

### Restarts

```promql
sum by (namespace, pod) (
  increase(kube_pod_container_status_restarts_total{namespace="prod"}[1h])
)
```

### Error rate

```promql
sum by (namespace, service) (
  rate(http_server_request_duration_seconds_count{namespace="prod", http_response_status_code=~"5.."}[5m])
)
/
clamp_min(
  sum by (namespace, service) (
    rate(http_server_request_duration_seconds_count{namespace="prod"}[5m])
  ),
  1e-9
)
```

### Latency p95

```promql
histogram_quantile(
  0.95,
  sum by (le, namespace, service) (
    rate(http_server_request_duration_seconds_bucket{namespace="prod"}[5m])
  )
)
```

## Notes

- Metric names assume kube-state-metrics + cAdvisor + RED-style HTTP instrumentation.
- If your cluster uses different label names (`job`, `exported_service`, Istio `destination_service_name`), adjust the templates in `config/queries.yaml`.
- For Grafana Mimir, the same `/api/v1/query_range` path works when the engine points at the Mimir query frontend.
