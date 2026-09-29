# Architecture

## Goal

Detect Kubernetes / platform anomalies using **dynamic baselines** and **correlated incident scores**, not independent static thresholds.

## Signal sources (v1+)

| Source | Signals |
|--------|---------|
| Prometheus / Mimir | CPU, memory, restarts, RPS, error rate, latency, node saturation |
| Loki | OOMKilled, CrashLoopBackOff, exceptions, timeouts (planned) |
| Kubernetes API | Deployments, pod phases, events, node conditions, HPA |
| Tempo | Latency breakdown / failing spans (optional later) |

## Detection pipeline

1. **Collect** current + historical series for watched namespaces/services.
2. **Baseline** each series (rolling mean / std over configurable window).
3. **Score** each signal: how far is “now” from expected band?
4. **Correlate** co-occurring signals on the same service / namespace into one incident.
5. **Weight** into a 0–100 incident score.
6. **Narrate** a short investigation summary for humans / Slack.

## Why baselines first

Static alert:

```
CPU > 80% → ALERT
```

Baseline alert:

```
Normal CPU 09:00–11:00 → 35–38%
Current 11:05 → 91%
Expected 35–45%, observed 91% → anomaly score ~97
```

This cuts noise for workloads that legitimately run hot, and catches silent regressions that stay under a hard ceiling.

## Deployment topology

```
Namespace: anomaly-detection
  Deployment  anomaly-engine
  Service     anomaly-engine:8080
  ConfigMap   detector config + PromQL
  ServiceAccount + ClusterRole (pods/events/deployments/nodes read)
```

Recommended scrape path: engine queries Prometheus/Mimir over HTTP; optionally expose `/metrics` for self-monitoring.
