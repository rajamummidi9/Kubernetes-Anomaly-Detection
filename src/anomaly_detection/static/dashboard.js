"use strict";

const GIB = 1024 ** 3;
const MIB = 1024 ** 2;
const CATEGORIES = ["reliability", "capacity", "efficiency", "security", "configuration"];
const params = new URLSearchParams(location.search);
const state = {
  data: null,
  context: params.get("context") || "",
  ns: params.get("ns") || "",
  severity: "",
  category: "",
  query: "",
  open: new Set(),
  sort: {},
  timer: null,
};

const $ = (id) => document.getElementById(id);
const esc = (v = "") => String(v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const pct = (a, b) => (b ? (a / b) * 100 : 0);
const bytes = (v) => (v == null ? "–" : v >= GIB ? `${(v / GIB).toFixed(1)} GiB` : `${Math.round(v / MIB)} MiB`);
const cpu = (v) => (v == null ? "–" : v >= 1 ? `${v.toFixed(2)}` : `${Math.round(v * 1000)}m`);
const tone = (p, warn = 80, crit = 90) => (p >= crit ? "crit" : p >= warn ? "warn" : "");
const scoreTone = (s) => (s >= 85 ? "var(--ok)" : s >= 70 ? "var(--warning)" : "var(--critical)");
const timeAgo = (iso) => {
  if (!iso) return "–";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return `${Math.round(s)}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 172800) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};
const bar = (p, t = tone(p)) => `<div class="bar"><span class="${t}" style="width:${Math.min(100, p).toFixed(1)}%"></span></div>`;

function toast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => el.classList.add("hidden"), 1800);
}

function syncUrl() {
  const p = new URLSearchParams();
  if (state.context) p.set("context", state.context);
  if (state.ns) p.set("ns", state.ns);
  history.replaceState(null, "", `${location.pathname}${p.toString() ? `?${p}` : ""}`);
  $("export-md").href = `/v1/report.md${state.context ? `?context=${encodeURIComponent(state.context)}` : ""}`;
}

async function getJson(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

// ------------------------------------------------------------------ loading

async function loadContexts() {
  try {
    const { contexts, default: fallback } = await getJson("/v1/contexts");
    const select = $("context-select");
    select.innerHTML = contexts.length
      ? contexts.map((c) => `<option value="${esc(c.name)}">${esc(c.name)}</option>`).join("")
      : `<option value="">(no kubeconfig contexts)</option>`;
    if (!state.context || !contexts.some((c) => c.name === state.context)) state.context = fallback || "";
    select.value = state.context;
  } catch (err) {
    showError(`Could not list contexts: ${err.message}`);
  }
}

async function load(force = false) {
  const btn = $("refresh");
  btn.disabled = true;
  btn.textContent = "Analyzing…";
  syncUrl();
  try {
    const q = new URLSearchParams({ force: String(force) });
    if (state.context) q.set("context", state.context);
    state.data = await getJson(`/v1/dashboard?${q}`);
    render();
  } catch (err) {
    showError(`Analysis request failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Refresh";
  }
}

function showError(msg) {
  $("error-banner").textContent = msg;
  $("error-banner").classList.remove("hidden");
}

// ------------------------------------------------------------------ filters

function systemNamespaces() {
  return new Set((state.data?.cluster?.namespaces || []).filter((n) => n.system).map((n) => n.namespace));
}

function nsMatch(ns, system) {
  if (!state.ns) return true;
  if (state.ns === "__workloads") return !ns || !system.has(ns);
  return ns === state.ns;
}

function filteredInsights() {
  const system = systemNamespaces();
  const q = state.query.toLowerCase();
  return (state.data?.cluster?.insights || [])
    .map((ins) => {
      const namespaced = ins.affected.some((a) => a.namespace);
      if (!namespaced) return state.ns && state.ns !== "__workloads" ? null : ins;
      const affected = ins.affected.filter((a) => nsMatch(a.namespace, system));
      return affected.length ? { ...ins, affected, affected_count: state.ns ? affected.length : ins.affected_count } : null;
    })
    .filter(Boolean)
    .filter((i) => !state.severity || i.severity === state.severity)
    .filter((i) => !state.category || i.category === state.category)
    .filter((i) => {
      if (!q) return true;
      const hay = [i.title, i.summary, i.recommendation, ...i.affected.map((a) => `${a.namespace}/${a.name} ${a.detail}`)].join(" ").toLowerCase();
      return hay.includes(q);
    });
}

// ------------------------------------------------------------------ render

function render() {
  const report = state.data.cluster;
  const meta = report.meta || {};
  if (!meta.connected) {
    showError(`Cannot analyze "${meta.context}": ${meta.error}`);
    $("status-line").textContent = `${meta.context} · disconnected`;
    return;
  }
  $("error-banner").classList.add("hidden");
  $("status-line").textContent =
    `${meta.context} · Kubernetes ${meta.server_version || "?"} · analyzed ${timeAgo(meta.generated_at)} in ${meta.duration_ms ?? "–"} ms`;

  renderNamespaceOptions(report.namespaces);
  renderScores(report);
  renderCapacity(report.capacity, meta.metrics_available);
  renderQuickWins(report.quick_wins);
  renderAdvisors(report.advisors);
  renderInsights();
  renderNodes(report.nodes);
  renderNamespaces(report.namespaces);
  renderPods(report.top_pods);
  renderEvents(report.events, meta.window_hours);
  renderBaseline(state.data.baseline);
}

function renderNamespaceOptions(rows) {
  const select = $("namespace-select");
  const names = rows.map((r) => r.namespace).sort();
  const fixed = `<option value="">All namespaces</option><option value="__workloads">Exclude system</option>`;
  select.innerHTML = fixed + names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
  select.value = names.includes(state.ns) || state.ns === "__workloads" ? state.ns : "";
}

function renderScores(report) {
  const { scores, summary, meta } = report;
  const ring = $("score-ring");
  ring.style.setProperty("--score", scores.overall);
  ring.style.setProperty("--tone", scoreTone(scores.overall));
  $("score-grade").textContent = scores.grade;
  $("score-value").textContent = `${scores.overall}/100`;
  $("score-headline").textContent =
    summary.critical ? `${summary.critical} critical ${summary.critical > 1 ? "issues need" : "issue needs"} attention`
      : summary.warning ? `${summary.warning} warnings to review` : "Healthy";
  $("score-summary").textContent =
    `${summary.nodes_ready}/${summary.nodes} nodes ready · ${summary.pods_ready}/${summary.pods} pods ready · ${summary.workloads} workloads · ${summary.namespaces} namespaces`;

  const coverage = Object.entries(meta.coverage || {});
  const gaps = coverage.filter(([, v]) => v !== "ok");
  $("coverage").innerHTML =
    `<span class="chip ${meta.metrics_available ? "ok" : "bad"}">metrics-server ${meta.metrics_available ? "ok" : "missing"}</span>` +
    `<span class="chip ${gaps.length ? "bad" : "ok"}">${gaps.length ? `${gaps.length} API gaps` : `${coverage.length}/${coverage.length} APIs readable`}</span>` +
    (meta.rule_errors?.length ? `<span class="chip bad">${meta.rule_errors.length} rule errors</span>` : "");

  $("category-tiles").innerHTML = CATEGORIES.map((name) => {
    const c = scores.categories[name];
    return `<button class="tile ${state.category === name ? "active" : ""}" data-category="${name}" type="button">
      <span class="label">${name}</span>
      <span class="tile-score" style="color:${scoreTone(c.score)}">${c.score}</span>
      <div class="bar"><span style="width:${c.score}%;background:${scoreTone(c.score)}"></span></div>
      <span class="tile-counts"><span class="t-critical">${c.critical} crit</span><span class="t-warning">${c.warning} warn</span><span class="t-info">${c.info} info</span></span>
    </button>`;
  }).join("");
}

function gauge(values, fmt, unit) {
  const { usage, requests, limits, allocatable } = values;
  const scale = Math.max(allocatable, usage || 0, requests || 0) || 1;
  const pos = (v) => `${Math.min(100, (v / scale) * 100).toFixed(1)}%`;
  const row = (color, label, v) =>
    `<span><span class="dot" style="background:${color}"></span>${label}</span><span class="num">${fmt(v)} ${unit}</span><span class="pc">${v == null ? "" : `${pct(v, allocatable).toFixed(0)}%`}</span>`;
  return `
    <div class="gauge" role="img" aria-label="usage ${pct(usage, allocatable).toFixed(0)} percent of allocatable">
      <div class="fill" style="width:${pos(usage || 0)}"></div>
      ${requests != null ? `<div class="marker req" style="left:${pos(requests)}" data-label="req"></div>` : ""}
      ${limits != null ? `<div class="marker lim" style="left:${pos(Math.min(limits, scale))}" data-label="${limits > scale ? "lim ›" : "lim"}"></div>` : ""}
    </div>
    <div class="legend">
      ${row("var(--usage)", "Usage", usage)}
      ${requests != null ? row("var(--requests)", "Requests", requests) : ""}
      ${limits != null ? row("var(--limits)", "Limits", limits) : ""}
      ${row("#40524d", "Allocatable", allocatable)}
    </div>`;
}

function renderCapacity(cap, metrics) {
  const card = (title, headline, body) =>
    `<div class="cap"><div class="cap-head"><span class="label">${title}</span><strong>${headline}</strong></div>${body}</div>`;
  $("capacity").innerHTML = [
    card("CPU", metrics ? `${pct(cap.cpu.usage, cap.cpu.allocatable).toFixed(0)}% used` : "no metrics", gauge(cap.cpu, cpu, "cores")),
    card("Memory", metrics ? `${pct(cap.memory.usage, cap.memory.allocatable).toFixed(0)}% used` : "no metrics",
      gauge(cap.memory, (v) => (v == null ? "–" : (v / GIB).toFixed(1)), "GiB")),
    card("Pods", `${cap.pods.usage}/${cap.pods.allocatable}`,
      gauge({ usage: cap.pods.usage, requests: null, limits: null, allocatable: cap.pods.allocatable }, (v) => v ?? "–", "")),
  ].join("");
  $("capacity-notes").innerHTML = (cap.notes || []).map((n) => `<li>${esc(n)}</li>`).join("");
}

function fixBlock(fix) {
  if (!fix) return "";
  return `<pre class="fix"><button class="ghost copy" type="button" data-copy="${esc(fix)}">Copy</button>${esc(fix)}</pre>`;
}

function renderQuickWins(wins) {
  $("quick-wins").innerHTML = wins.length
    ? wins.map((w) => `<li>
        <div>
          <h3><span class="sev ${w.severity}">${w.severity}</span>${esc(w.title)}</h3>
          <p>${esc(w.action)}</p>
        </div>
        <button class="ghost jump" type="button" data-jump="${esc(w.id)}">Details</button>
      </li>`).join("")
    : `<li class="empty" style="display:block">No actions — the cluster passes every check.</li>`;
}

function renderAdvisors(advisors) {
  if (!advisors) {
    $("advisor-grid").innerHTML = `<div class="empty">Advisor data is not in this report. Refresh to reload.</div>`;
    return;
  }
  const security = advisors.security || { items: [], summary: "" };
  const upgrades = advisors.upgrades || { plan: [], headline: "" };
  const cases = advisors.investigations || [];
  const item = (severity, title, body, extra) => `<li>
    <h3><span class="sev ${severity}">${severity}</span>${esc(title)}</h3>
    <p>${esc(body)}</p>
    ${extra || ""}
  </li>`;
  const securityBody = security.items.length
    ? `<ul class="advice">${security.items.map((i) => item(i.severity, i.title, i.advice, fixBlock(i.action))).join("")}</ul>`
    : `<div class="empty">Nothing to flag.</div>`;
  const upgradeBody = `<ul class="advice">${(upgrades.plan || []).map((s) => item("info", s.title, s.detail)).join("")}</ul>
    <p class="muted catalog">Catalog ${esc(upgrades.catalog_as_of || "")}${upgrades.supported?.length ? ` · supported now: ${esc(upgrades.supported.join(", "))}` : ""}. <a href="${esc(upgrades.catalog_url || "https://kubernetes.io/releases/")}" target="_blank" rel="noopener">kubernetes.io/releases</a></p>`;
  const caseBody = cases.length
    ? cases.map((c) => `<article class="investigation ${c.severity}">
        <h3><span class="sev ${c.severity}">${c.severity}</span>${esc(c.title)} <span class="tag">${esc(c.confidence)} confidence</span></h3>
        <p>${esc(c.likely_cause)}</p>
        ${c.evidence?.length ? `<ul class="evidence">${c.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : ""}
        ${c.checks?.length ? `<pre class="fix">${c.checks.map((line) => esc(line)).join("\n")}</pre>` : ""}
      </article>`).join("")
    : `<div class="empty">No incident pattern is active. A note appears here when pods crash, images fail to pull, or nodes come under pressure.</div>`;
  $("advisor-grid").innerHTML = [
    `<article class="advisor"><p class="label">Security · ${esc(security.posture || "")}</p><h3>${esc(security.summary || "")}</h3>${securityBody}</article>`,
    `<article class="advisor"><p class="label">Upgrades · ${esc(upgrades.status || "")}${upgrades.provider ? ` · ${esc(upgrades.provider)}` : ""}</p><h3>${esc(upgrades.headline || "")}</h3>${upgrades.skew_summary ? `<p class="muted">${esc(upgrades.skew_summary)}</p>` : ""}${upgradeBody}</article>`,
    `<article class="advisor"><p class="label">Root cause</p><h3>${cases.length ? `${cases.length} investigation${cases.length > 1 ? "s" : ""}` : "No active incident"}</h3>${caseBody}</article>`,
  ].join("");
}

function renderInsights() {
  const items = filteredInsights();
  const total = state.data.cluster.insights.length;
  $("insight-count").textContent = items.length === total ? `(${total})` : `(${items.length} of ${total})`;
  $("insights").innerHTML = items.length ? items.map((i) => {
    const rows = i.affected.map((a) =>
      `<tr><td>${esc(a.kind)}</td><td><span class="ellipsis" title="${esc(`${a.namespace}/${a.name}`)}">${esc([a.namespace, a.name].filter(Boolean).join("/"))}</span></td><td class="wrap">${esc(a.detail)}</td></tr>`).join("");
    const more = i.affected_count > i.affected.length ? `<p class="muted">Showing ${i.affected.length} of ${i.affected_count}. Export the Markdown report for the full list.</p>` : "";
    return `<details class="insight ${i.severity}" id="ins-${esc(i.id)}" ${state.open.has(i.id) ? "open" : ""}>
      <summary>
        <span class="edge"></span>
        <span class="sev ${i.severity}">${i.severity}</span>
        <span class="title">${esc(i.title)}<small>${esc(i.summary)}</small></span>
        <span><span class="tag">${i.category}</span> <span class="affected-n">${i.affected_count} affected</span></span>
      </summary>
      <div class="body">
        <dl class="kv">
          <dt>Impact</dt><dd>${esc(i.impact)}</dd>
          <dt>Recommendation</dt><dd>${esc(i.recommendation)}</dd>
        </dl>
        ${fixBlock(i.fix)}
        ${rows ? `<div class="table-wrap" style="max-height:320px"><table><thead><tr><th>Kind</th><th>Resource</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table></div>${more}` : ""}
      </div>
    </details>`;
  }).join("") : `<div class="empty">No findings match the current filters.</div>`;
}

// ------------------------------------------------------------------ tables

function table(id, columns, rows, defaultSort) {
  const s = state.sort[id] || defaultSort;
  const col = columns.find((c) => c.key === s.key);
  const sorted = col?.sort ? [...rows].sort((a, b) => {
    const x = col.sort(a), y = col.sort(b);
    return (x > y ? 1 : x < y ? -1 : 0) * (s.dir === "asc" ? 1 : -1);
  }) : rows;
  const head = columns.map((c) => {
    const arrow = s.key === c.key ? (s.dir === "asc" ? " ▲" : " ▼") : "";
    return `<th class="${c.num ? "num" : ""} ${c.sort ? "sortable" : ""}" data-table="${id}" data-key="${c.key}">${c.label}${arrow}</th>`;
  }).join("");
  const body = sorted.length
    ? sorted.map((r) => `<tr>${columns.map((c) => `<td class="${c.num ? "num" : ""} ${c.wrap ? "wrap" : ""}">${c.render(r)}</td>`).join("")}</tr>`).join("")
    : `<tr><td colspan="${columns.length}" class="empty">No data</td></tr>`;
  $(id).innerHTML = `<thead><tr>${head}</tr></thead><tbody>${body}</tbody>`;
  table.defs[id] = () => table(id, columns, rows, defaultSort);
}
table.defs = {};

function dual(label1, v1, label2, v2) {
  return `<div class="dual">
    <div class="row"><span>${label1}</span>${bar(v1)}<span>${v1 == null ? "–" : `${v1.toFixed(0)}%`}</span></div>
    <div class="row"><span>${label2}</span>${bar(v2, tone(v2, 85, 100) || "")}<span>${v2.toFixed(0)}%</span></div>
  </div>`;
}

function renderNodes(nodes) {
  const cpuUse = (n) => (n.usage ? pct(n.usage.cpu, n.allocatable.cpu) : null);
  const memUse = (n) => (n.usage ? pct(n.usage.memory, n.allocatable.memory) : null);
  table("nodes-table", [
    { key: "name", label: "Node", sort: (n) => n.name, render: (n) =>
      `<strong>${esc(n.name)}</strong><br><small class="muted">${esc([n.pool, n.instance_type, n.zone].filter(Boolean).join(" · "))}</small>` },
    { key: "status", label: "Status", sort: (n) => (n.ready ? 1 : 0), render: (n) =>
      `${n.ready ? `<span class="t-ok">Ready</span>` : `<span class="t-critical">NotReady</span>`}${n.unschedulable ? ` <span class="tag">cordoned</span>` : ""}${n.pressure.map((p) => ` <span class="sev critical">${esc(p)}</span>`).join("")}` },
    { key: "cpu", label: "CPU used / requested", sort: (n) => cpuUse(n) ?? -1, render: (n) =>
      dual("used", cpuUse(n), "req", pct(n.requests.cpu, n.allocatable.cpu)) },
    { key: "mem", label: "Memory used / requested", sort: (n) => memUse(n) ?? -1, render: (n) =>
      dual("used", memUse(n), "req", pct(n.requests.memory, n.allocatable.memory)) },
    { key: "alloc", label: "Allocatable", num: true, sort: (n) => n.allocatable.memory, render: (n) =>
      `${cpu(n.allocatable.cpu)} cpu<br><small class="muted">${bytes(n.allocatable.memory)}</small>` },
    { key: "pods", label: "Pods", num: true, sort: (n) => pct(n.pods, n.pod_capacity), render: (n) =>
      `<span class="pill ${tone(pct(n.pods, n.pod_capacity), 80, 90)}">${n.pods}/${n.pod_capacity}</span>` },
    { key: "kubelet", label: "Kubelet", sort: (n) => n.kubelet, render: (n) => esc(n.kubelet) },
    { key: "age", label: "Age", render: (n) => esc(n.age) },
  ], nodes, { key: "mem", dir: "desc" });
}

function renderNamespaces(rows) {
  const system = systemNamespaces();
  const data = rows.filter((r) => nsMatch(r.namespace, system));
  table("namespaces-table", [
    { key: "namespace", label: "Namespace", sort: (r) => r.namespace, render: (r) =>
      `<button class="ghost ns-link" type="button" data-ns="${esc(r.namespace)}" style="padding:2px 6px">${esc(r.namespace)}</button>${r.system ? ` <span class="tag">system</span>` : ""}` },
    { key: "score", label: "Health", num: true, sort: (r) => r.score, render: (r) =>
      `<span class="pill ${r.score < 60 ? "crit" : r.score < 85 ? "warn" : ""}">${r.score}</span>` },
    { key: "issues", label: "C / W / I", num: true, sort: (r) => r.critical * 100 + r.warning * 10 + r.info, render: (r) =>
      `<span class="t-critical">${r.critical}</span> / <span class="t-warning">${r.warning}</span> / <span class="t-info">${r.info}</span>` },
    { key: "pods", label: "Pods", num: true, sort: (r) => r.pods, render: (r) =>
      `${r.pods}${r.not_ready ? ` <span class="t-critical">(${r.not_ready} ✕)</span>` : ""}` },
    { key: "mem", label: "Memory use / req", num: true, sort: (r) => r.usage.memory, render: (r) =>
      `${bytes(r.usage.memory)}<br><small class="muted">${bytes(r.requests.memory)} req</small>` },
    { key: "cpu", label: "CPU use / req", num: true, sort: (r) => r.usage.cpu, render: (r) =>
      `${cpu(r.usage.cpu)}<br><small class="muted">${cpu(r.requests.cpu)} req</small>` },
    { key: "restarts", label: "Restarts", num: true, sort: (r) => r.restarts, render: (r) => r.restarts },
  ], data, { key: "score", dir: "asc" });
}

function renderPods(pods) {
  const system = systemNamespaces();
  const data = pods.filter((p) => nsMatch(p.namespace, system));
  const memCell = (p) => {
    const lim = p.limits.memory;
    const ofLimit = lim ? pct(p.usage.memory, lim) : null;
    const vsReq = p.requests.memory ? pct(p.usage.memory, p.requests.memory) : null;
    return `<div class="mini">${ofLimit != null ? bar(ofLimit, tone(ofLimit, 80, 90)) : bar(0)}
      <small>${bytes(p.usage.memory)} · req ${p.requests.memory ? bytes(p.requests.memory) : "none"} · lim ${lim ? bytes(lim) : "none"}</small>
      ${vsReq != null && vsReq > 150 ? `<small class="t-warning">${vsReq.toFixed(0)}% of request</small>` : ""}</div>`;
  };
  table("pods-table", [
    { key: "pod", label: "Pod", sort: (p) => `${p.namespace}/${p.name}`, render: (p) =>
      `<span class="ellipsis" title="${esc(`${p.namespace}/${p.name}`)}">${esc(p.name)}</span><br><small class="muted">${esc(p.namespace)}</small>` },
    { key: "mem", label: "Memory (bar = % of limit)", sort: (p) => p.usage.memory, render: memCell },
    { key: "cpu", label: "CPU", num: true, sort: (p) => p.usage.cpu, render: (p) =>
      `${cpu(p.usage.cpu)}<br><small class="muted">req ${p.requests.cpu ? cpu(p.requests.cpu) : "none"}</small>` },
    { key: "qos", label: "QoS", sort: (p) => p.qos, render: (p) =>
      `<span class="tag" style="${p.qos === "BestEffort" ? "color:var(--warning)" : ""}">${esc(p.qos)}</span>` },
    { key: "restarts", label: "Restarts", num: true, sort: (p) => p.restarts, render: (p) => p.restarts },
  ], data, { key: "mem", dir: "desc" });
}

function renderEvents(events, windowHours) {
  const system = systemNamespaces();
  const data = events.filter((e) => nsMatch(e.namespace, system));
  const chronic = data.filter((e) => e.chronic).length;
  $("events-caption").textContent =
    `Last ${windowHours}h, deduplicated per object and reason. ${chronic} chronic (first seen more than 24h ago and still firing).`;
  table("events-table", [
    { key: "reason", label: "Reason", sort: (e) => e.reason, render: (e) =>
      `<strong>${esc(e.reason)}</strong>${e.chronic ? `<span class="badge-chronic">CHRONIC</span>` : ""}` },
    { key: "object", label: "Object", sort: (e) => `${e.namespace}/${e.resource}`, render: (e) =>
      `<span class="ellipsis" title="${esc(`${e.namespace}/${e.resource}`)}">${esc(`${e.kind}/${e.resource}`)}</span><br><small class="muted">${esc(e.namespace)}</small>` },
    { key: "message", label: "Message", wrap: true, render: (e) => `<span class="muted">${esc(e.message.slice(0, 300))}</span>` },
    { key: "count", label: "Count", num: true, sort: (e) => e.count, render: (e) => e.count.toLocaleString() },
    { key: "first", label: "First seen", num: true, sort: (e) => e.first_seen || "", render: (e) => timeAgo(e.first_seen) },
    { key: "last", label: "Last seen", num: true, sort: (e) => e.last_seen, render: (e) => timeAgo(e.last_seen) },
  ], data, { key: "last", dir: "desc" });
}

function renderBaseline(baseline) {
  $("baseline-status").textContent = `Prometheus/Cortex baseline detector: ${baseline.status}`;
  const incidents = baseline.result?.incidents || [];
  $("incidents").innerHTML = incidents.length ? incidents.map((i) => `
    <article class="incident">
      <div class="incident-head"><div><span class="sev ${i.severity}">${i.severity}</span> <h3 style="display:inline">${esc(`${i.namespace}/${i.service}`)}</h3></div><strong>${Math.round(i.score)}</strong></div>
      <p class="muted">${esc(i.narrative)}</p>
      <div class="signal-tags">${i.signals.map((s) => `<span>${esc(s.signal)} z=${s.z_score.toFixed(1)} +${s.contribution.toFixed(0)}</span>`).join("")}</div>
    </article>`).join("")
    : `<div class="empty">${baseline.enabled ? "No baseline deviations detected." : "Set PROMETHEUS_URL (Prometheus, Cortex, Mimir, Thanos) to enable time-series baselines."}</div>`;
}

// ------------------------------------------------------------------ events

document.addEventListener("click", async (ev) => {
  const t = ev.target.closest("button, th, a");
  if (!t) {
    $("export-menu").classList.add("hidden");
    return;
  }
  if (t.matches(".copy")) {
    ev.preventDefault();
    await navigator.clipboard.writeText(t.dataset.copy);
    toast("Copied to clipboard");
  } else if (t.matches(".tile")) {
    state.category = state.category === t.dataset.category ? "" : t.dataset.category;
    $("category-filter").value = state.category;
    renderScores(state.data.cluster);
    renderInsights();
  } else if (t.matches(".jump")) {
    state.severity = ""; state.category = ""; state.query = "";
    $("search").value = ""; $("category-filter").value = "";
    document.querySelectorAll("#severity-filters button").forEach((b) => b.classList.toggle("active", !b.dataset.severity));
    state.open.add(t.dataset.jump);
    renderInsights();
    document.getElementById(`ins-${t.dataset.jump}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
  } else if (t.matches(".ns-link")) {
    state.ns = t.dataset.ns;
    syncUrl();
    render();
  } else if (t.matches("th.sortable")) {
    const id = t.dataset.table, key = t.dataset.key;
    const cur = state.sort[id];
    state.sort[id] = { key, dir: cur?.key === key && cur.dir === "desc" ? "asc" : "desc" };
    table.defs[id]?.();
  } else if (t.id === "export-btn") {
    $("export-menu").classList.toggle("hidden");
  } else if (t.id === "export-json") {
    const blob = new Blob([JSON.stringify(state.data?.cluster, null, 2)], { type: "application/json" });
    const a = Object.assign(document.createElement("a"), {
      href: URL.createObjectURL(blob),
      download: `cluster-report-${state.context || "current"}-${new Date().toISOString().slice(0, 16)}.json`,
    });
    a.click();
    URL.revokeObjectURL(a.href);
    $("export-menu").classList.add("hidden");
  }
});

document.addEventListener("toggle", (ev) => {
  const el = ev.target;
  if (!el.matches?.("details.insight")) return;
  const id = el.id.slice(4);
  el.open ? state.open.add(id) : state.open.delete(id);
}, true);

$("severity-filters").addEventListener("click", (ev) => {
  const b = ev.target.closest("button");
  if (!b) return;
  state.severity = b.dataset.severity;
  document.querySelectorAll("#severity-filters button").forEach((x) => x.classList.toggle("active", x === b));
  renderInsights();
});
$("category-filter").addEventListener("change", (e) => { state.category = e.target.value; renderScores(state.data.cluster); renderInsights(); });
$("search").addEventListener("input", (e) => { state.query = e.target.value; renderInsights(); });
$("namespace-select").addEventListener("change", (e) => { state.ns = e.target.value; syncUrl(); render(); });
$("context-select").addEventListener("change", (e) => { state.context = e.target.value; state.ns = ""; state.open.clear(); load(); });
$("refresh").addEventListener("click", () => load(true));
$("evaluate").addEventListener("click", async () => {
  const b = $("evaluate");
  b.disabled = true;
  try { await getJson("/v1/evaluate", { method: "POST" }); await load(); }
  catch (err) { showError(`Baseline evaluation failed: ${err.message}`); }
  finally { b.disabled = false; }
});

function schedule() {
  clearInterval(state.timer);
  if ($("auto-refresh").checked) state.timer = setInterval(() => load(), 60_000);
}
$("auto-refresh").addEventListener("change", schedule);

(async () => {
  $("insights").innerHTML = `<div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div>`;
  await loadContexts();
  await load();
  schedule();
})();
