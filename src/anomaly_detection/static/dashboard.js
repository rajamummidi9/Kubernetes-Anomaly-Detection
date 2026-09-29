"use strict";

const GIB = 1024 ** 3;
const MIB = 1024 ** 2;
const CATEGORIES = ["reliability", "capacity", "efficiency", "security", "configuration"];
const params = new URLSearchParams(location.search);
const state = {
  data: null,
  context: params.get("context") || "",
  chat: [],
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
const HELP = {
  cluster: ["Cluster", "Each entry is a kubeconfig context, or the in-cluster ServiceAccount when this page runs inside Kubernetes. Switching cluster reloads every block. Nothing here changes the cluster."],
  namespace: ["Namespace filter", "Limits every table and finding to one namespace. Exclude system hides control-plane namespaces so application problems are easier to see. Clicking a namespace in the table sets this filter."],
  health: ["Cluster health", "One score from 0 to 100 and a letter grade. Reliability weighs the most, then capacity, efficiency, security, and configuration. A critical reliability finding holds the grade at D or below, because users are already affected. The chips say whether metrics-server and the other APIs could be read."],
  "category-reliability": ["Reliability", "Can the workloads serve traffic right now? NotReady nodes, crash loops, unavailable deployments, and pods stuck Pending live here. A low score means fix this before tuning cost or security."],
  "category-capacity": ["Capacity", "Is there room for the next pod, rollout, or node loss? This uses requests as well as real usage, because the scheduler places pods by requests. A high request percentage with low usage still means new pods can sit Pending."],
  "category-efficiency": ["Efficiency", "Are you reserving CPU and memory that nobody uses, or running without a request so the scheduler cannot plan? This is where idle reservations, missing requests, and unbounded CPU show up."],
  "category-security": ["Security", "How far could one compromised container reach? Privileged pods, host access, and mutable image tags enlarge that blast radius. A finding here is a weakness, not proof of an intrusion."],
  "category-configuration": ["Configuration", "Will the cluster behave predictably during a drain, a scale-up, or an upgrade? Missing probes, disruption budgets, broken autoscalers, and version skew live here."],
  capacity: ["Usage vs requests vs limits", "Three different numbers are easy to mix up. Usage is what the process consumes now. Requests are what the scheduler reserves. Limits are the ceiling: CPU is throttled and memory is killed. A cluster can look idle in usage and still be full on requests."],
  "capacity-cpu": ["CPU gauge", "The bar is current usage. The green marker is reserved requests and the blue marker is the limit ceiling. Limits past 100% mean pods can demand more CPU than the nodes have, so they throttle together under load."],
  "capacity-memory": ["Memory gauge", "Read the request marker against allocatable, not only the usage bar. Requests near the end of the bar mean the scheduler treats the cluster as full. A pod that crosses its own memory limit is OOMKilled."],
  "capacity-pods": ["Pod slots", "Nodes cap how many pods they will run, separate from CPU and memory. A high fraction means a rollout can fail even when CPU looks free. There is no request or limit for a pod count."],
  vectors: ["Detection vectors", "Four questions the page tries to answer: is something able to break out, is something degrading, is an error repeating, and is spend about to jump? Watch means this snapshot already has a finding. The note under each card names the sensor this API view cannot replace."],
  actions: ["Top actions", "The six findings worth doing first, ordered by severity and how many workloads they touch. Details jumps to the full finding, including the command to copy. Info-only notes stay out of this list unless the cluster is otherwise quiet."],
  advisors: ["Advisors", "Three written recommendations from the same snapshot. Security is the posture to tighten. Upgrades is the version path and what to fix before a drain. Root cause groups related failures into one likely explanation and the next read-only checks."],
  "advisor-security": ["Security advisor", "A short hardening list: admission policy, admin bindings, host mounts, and published services. Confirm each item; some, such as a backup tool, need broad access but should still not be cluster-admin."],
  "advisor-upgrades": ["Upgrade advisor", "Where this Kubernetes version sits in the upstream support window, the patch you are behind, and the drains that are unsafe today. Provider calendars differ, so confirm the target version is offered before scheduling it."],
  "advisor-rca": ["Root cause", "Built only when signals agree: a crash, a probe failure, a secret sync, a scheduling refusal, or a load balancer error. Confidence says how directly the evidence supports the cause. Run the checks before changing anything."],
  intelligence: ["AI investigation and early warnings", "Early warnings are calculated here from capacity and from the slope across refreshes. They do not call a model. Generate investigation sends a redacted summary to your configured API and asks for a hypothesis with evidence. A normal refresh does not spend tokens."],
  chat: ["Ask about this cluster", "Type a question about the cluster currently selected. A pod name, CPU, memory, or node status is read from this snapshot. An open question, such as why something failed, is sent to your configured AI provider with only the matching facts. The assistant cannot change the cluster or run kubectl."],
  insights: ["Insights", "Every check that fired, with impact, what to change, a command or snippet, and the affected objects. Filter by severity or category, or search a namespace. Open a row rather than treating the title as the whole finding."],
  nodes: ["Nodes", "One row per machine. Compare used with requested: used is the live process, requested is the reservation. A node can be under 30% used and still be unschedulable because requests are full. Pressure means the kubelet will start evicting pods."],
  namespaces: ["Namespaces", "Which namespace would hurt users if you ignore it. Health falls as critical and warning findings accumulate. Click the name to filter the rest of the page. System namespaces are marked so platform noise is visible but separate."],
  pods: ["Top pods by memory", "The largest memory consumers, not every pod. The bar is usage against the memory limit. No limit means the bar cannot show a ceiling, and the pod can grow until the node evicts something. QoS BestEffort has no requests, so it is evicted first."],
  events: ["Warning events", "Kubernetes warning events, one row per object and reason. Count is how many times it fired. Chronic means it started more than a day ago and is still firing, so it is not a blip from the last deploy."],
  baseline: ["Baseline anomalies", "Optional time-series check against Prometheus, Cortex, Mimir, or Thanos. A high score means the service left its own recent normal range, even if it is under a static threshold. It stays empty until PROMETHEUS_URL or MIMIR_URL is set."],
  "vector-security_runtime": ["Security and runtime", "Looks for privilege, new admin identities, and namespaces with no NetworkPolicy. A hit means the blast radius is large or egress is unrestricted. Syscall exploits and the exact external IP a pod contacted need Falco, Tetragon, or flow logs."],
  "vector-performance": ["Performance and infrastructure", "Looks for crashes, restarts, hot nodes, and autoscalers that cannot add pods. A memory leak is only called out after several refreshes show a rising slope. Transaction drops need application metrics from Prometheus."],
  "vector-logs": ["Log and event patterns", "Groups the same warning text so a dependency failure is not mistaken for harmless noise. Count at least 100 repetitions. Similar lines inside application logs need Loki or your log store."],
  "vector-cost": ["Cost and capacity waste", "Looks for idle reservations, CPU with no ceiling, nodes added in the last few hours, and batch jobs with no deadline. These are the in-cluster signs of a surprise bill. The cloud invoice is not read."],
  "col-cpu-used": ["CPU used / requested", "Used is live consumption divided by allocatable. Requested is what pods have reserved. Sort here to find the node most likely to throttle or to reject new pods."],
  "col-mem-used": ["Memory used / requested", "Same split as CPU. Requested near 100% is a scheduling problem. Used near 100% is an eviction problem."],
  "col-allocatable": ["Allocatable", "CPU and memory the kubelet will actually give pods, after system reserves. Compare requests and usage with this, not with the cloud VM size."],
  "col-pods": ["Pod slots on the node", "Running pods over the node maximum. This fills up before CPU on clusters with many small pods."],
  "col-kubelet": ["Kubelet version", "The Kubernetes version on that node. Mixed versions during an upgrade are expected briefly. A node several minors behind the control plane is not."],
  "col-health": ["Namespace health", "100 minus the findings in that namespace. A namespace at 40 needs attention even if the cluster grade looks acceptable."],
  "col-cwi": ["Critical / warning / info", "How many findings name this namespace. Critical counts affect users now. Info is hygiene."],
  "col-mem-bar": ["Memory bar", "The bar is how close usage is to the limit. The text underneath is usage, request, and limit. Usage far above the request means the scheduler is reserving too little."],
  "col-qos": ["Quality of service", "Guaranteed has equal requests and limits. Burstable has a request. BestEffort has neither and is the first pod evicted when a node is under pressure."],
  "col-count": ["Event count", "Times Kubernetes recorded this reason for this object. A large count is one repeating problem, not thousands of unrelated problems."],
  "col-chronic": ["First seen", "When this warning started. A first-seen time of many hours or days, with a recent last-seen time, is marked Chronic."],
};
function helpBtn(key) {
  const [title] = HELP[key] || ["Help"];
  return `<button type="button" class="help" data-help="${esc(key)}" aria-label="Help: ${esc(title)}">?</button>`;
}

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
  renderVectors(report.vectors);
  renderQuickWins(report.quick_wins);
  renderAdvisors(report.advisors);
  renderIntelligence(state.data.intelligence);
  renderInsights();
  renderNodes(report.nodes);
  renderNamespaces(report.namespaces);
  renderPods(report.top_pods);
  renderEvents(report.events, meta.window_hours);
  renderBaseline(state.data.baseline);
  const ai = state.data.intelligence?.status;
  $("chat-status").textContent = ai?.enabled
    ? `Snapshot answers are instant. Open questions use ${ai.provider} / ${ai.model}.`
    : "Pod CPU, memory, and node status come from this snapshot. Open questions need an AI provider.";
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
    return `<div class="tile-wrap">${helpBtn(`category-${name}`)}<button class="tile ${state.category === name ? "active" : ""}" data-category="${name}" type="button">
      <span class="label">${name}</span>
      <span class="tile-score" style="color:${scoreTone(c.score)}">${c.score}</span>
      <div class="bar"><span style="width:${c.score}%;background:${scoreTone(c.score)}"></span></div>
      <span class="tile-counts"><span class="t-critical">${c.critical} crit</span><span class="t-warning">${c.warning} warn</span><span class="t-info">${c.info} info</span></span>
    </button></div>`;
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
  const card = (title, help, headline, body) =>
    `<div class="cap"><div class="cap-head"><span class="label">${title} ${helpBtn(help)}</span><strong>${headline}</strong></div>${body}</div>`;
  $("capacity").innerHTML = [
    card("CPU", "capacity-cpu", metrics ? `${pct(cap.cpu.usage, cap.cpu.allocatable).toFixed(0)}% used` : "no metrics", gauge(cap.cpu, cpu, "cores")),
    card("Memory", "capacity-memory", metrics ? `${pct(cap.memory.usage, cap.memory.allocatable).toFixed(0)}% used` : "no metrics",
      gauge(cap.memory, (v) => (v == null ? "–" : (v / GIB).toFixed(1)), "GiB")),
    card("Pods", "capacity-pods", `${cap.pods.usage}/${cap.pods.allocatable}`,
      gauge({ usage: cap.pods.usage, requests: null, limits: null, allocatable: cap.pods.allocatable }, (v) => v ?? "–", "")),
  ].join("");
  $("capacity-notes").innerHTML = (cap.notes || []).map((n) => `<li>${esc(n)}</li>`).join("");
}

function fixBlock(fix) {
  if (!fix) return "";
  return `<pre class="fix"><button class="ghost copy" type="button" data-copy="${esc(fix)}">Copy</button>${esc(fix)}</pre>`;
}

function renderVectors(vectors) {
  $("vectors").innerHTML = (vectors || []).map((vector) => `
    <article class="vector ${vector.status}">
      <p class="label">${esc(vector.status)} ${helpBtn(`vector-${vector.id}`)}</p>
      <h3>${esc(vector.title)}</h3>
      <p>${esc(vector.detects)}</p>
      <ul>${(vector.findings || []).map((item) => `<li><button class="jump link" type="button" data-jump="${esc(item.id)}">${esc(item.title)}</button></li>`).join("") || "<li>No active finding in this snapshot.</li>"}</ul>
      <p class="muted">${(vector.blind_spots || []).map(esc).join(" ")}</p>
    </article>`).join("");
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
    `<article class="advisor"><p class="label">Security · ${esc(security.posture || "")} ${helpBtn("advisor-security")}</p><h3>${esc(security.summary || "")}</h3>${securityBody}</article>`,
    `<article class="advisor"><p class="label">Upgrades · ${esc(upgrades.status || "")}${upgrades.provider ? ` · ${esc(upgrades.provider)}` : ""} ${helpBtn("advisor-upgrades")}</p><h3>${esc(upgrades.headline || "")}</h3>${upgrades.skew_summary ? `<p class="muted">${esc(upgrades.skew_summary)}</p>` : ""}${upgradeBody}</article>`,
    `<article class="advisor"><p class="label">Root cause ${helpBtn("advisor-rca")}</p><h3>${cases.length ? `${cases.length} investigation${cases.length > 1 ? "s" : ""}` : "No active incident"}</h3>${caseBody}</article>`,
  ].join("");
}

function renderIntelligence(ai) {
  const status = ai?.status || {};
  const predictions = ai?.predictions || [];
  const result = ai?.result;
  $("intelligence-status").textContent =
    `${status.status || "not configured"} · ${ai?.history_points || 0} history point(s)` +
    (status.provider ? ` · ${status.provider}/${status.model}` : "");
  $("run-intelligence").disabled = !status.enabled;
  $("predictions").innerHTML = predictions.length
    ? `<h3>Early warnings</h3><div class="prediction-grid">${predictions.map((p) => `
      <article class="prediction ${p.severity}">
        <h3><span class="sev ${p.severity}">${p.severity}</span>${esc(p.title)}</h3>
        <p>${esc(p.probability)} probability · ${esc(p.horizon)}</p>
        <ul>${p.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
        <strong>${esc(p.recommendation)}</strong>
      </article>`).join("")}</div>`
    : `<div class="empty">Collecting history. Capacity risks appear immediately; trend forecasts need at least three forced refreshes.</div>`;
  if (!result) {
    $("ai-investigation").innerHTML = `<div class="empty">${status.enabled
      ? "Select Generate investigation to ask the configured model. No tokens are spent during normal refreshes."
      : "Set AI_PROVIDER, AI_MODEL, and AI_API_KEY in a Secret. Ollama does not require a key."}</div>`;
    return;
  }
  const roots = result.root_causes || [];
  $("ai-investigation").innerHTML = `
    <div class="ai-summary"><span class="tag">${esc(result.situation)}</span><strong>${esc(result.summary)}</strong>
      <span class="muted">${esc(result.provider)}/${esc(result.model)} · ${timeAgo(result.generated_at)}${result.cached ? " · cached" : ""}</span></div>
    ${roots.map((r) => `<article class="root-cause">
      <h3>${esc(r.title)} <span class="tag">${esc(r.confidence)} confidence</span></h3>
      <p>${esc(r.hypothesis)}</p>
      <ul class="evidence">${r.evidence.map((e) => `<li><strong>${esc(e.source)}:</strong> ${esc(e.observation)}</li>`).join("")}</ul>
      ${r.disconfirming_checks.length ? `<p class="muted"><strong>Disprove it:</strong> ${esc(r.disconfirming_checks.join(" · "))}</p>` : ""}
    </article>`).join("")}
    <h3>Prioritised actions</h3>
    <ul class="advice">${(result.actions || []).map((a) =>
      `<li><h3><span class="tag">${esc(a.priority)}</span>${esc(a.title)}</h3><p>${esc(a.rationale)}</p>${fixBlock(a.command)}</li>`
    ).join("")}</ul>
    ${result.limitations?.length ? `<p class="muted"><strong>Limitations:</strong> ${esc(result.limitations.join(" · "))}</p>` : ""}`;
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
    const help = c.help ? helpBtn(c.help) : "";
    return `<th class="${c.num ? "num" : ""} ${c.sort ? "sortable" : ""}" data-table="${id}" data-key="${c.key}">${c.label}${help}${arrow}</th>`;
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
    { key: "cpu", label: "CPU used / requested", help: "col-cpu-used", sort: (n) => cpuUse(n) ?? -1, render: (n) =>
      dual("used", cpuUse(n), "req", pct(n.requests.cpu, n.allocatable.cpu)) },
    { key: "mem", label: "Memory used / requested", help: "col-mem-used", sort: (n) => memUse(n) ?? -1, render: (n) =>
      dual("used", memUse(n), "req", pct(n.requests.memory, n.allocatable.memory)) },
    { key: "alloc", label: "Allocatable", help: "col-allocatable", num: true, sort: (n) => n.allocatable.memory, render: (n) =>
      `${cpu(n.allocatable.cpu)} cpu<br><small class="muted">${bytes(n.allocatable.memory)}</small>` },
    { key: "pods", label: "Pods", help: "col-pods", num: true, sort: (n) => pct(n.pods, n.pod_capacity), render: (n) =>
      `<span class="pill ${tone(pct(n.pods, n.pod_capacity), 80, 90)}">${n.pods}/${n.pod_capacity}</span>` },
    { key: "kubelet", label: "Kubelet", help: "col-kubelet", sort: (n) => n.kubelet, render: (n) => esc(n.kubelet) },
    { key: "age", label: "Age", render: (n) => esc(n.age) },
  ], nodes, { key: "mem", dir: "desc" });
}

function renderNamespaces(rows) {
  const system = systemNamespaces();
  const data = rows.filter((r) => nsMatch(r.namespace, system));
  table("namespaces-table", [
    { key: "namespace", label: "Namespace", sort: (r) => r.namespace, render: (r) =>
      `<button class="ghost ns-link" type="button" data-ns="${esc(r.namespace)}" style="padding:2px 6px">${esc(r.namespace)}</button>${r.system ? ` <span class="tag">system</span>` : ""}` },
    { key: "score", label: "Health", help: "col-health", num: true, sort: (r) => r.score, render: (r) =>
      `<span class="pill ${r.score < 60 ? "crit" : r.score < 85 ? "warn" : ""}">${r.score}</span>` },
    { key: "issues", label: "C / W / I", help: "col-cwi", num: true, sort: (r) => r.critical * 100 + r.warning * 10 + r.info, render: (r) =>
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
    { key: "mem", label: "Memory (bar = % of limit)", help: "col-mem-bar", sort: (p) => p.usage.memory, render: memCell },
    { key: "cpu", label: "CPU", num: true, sort: (p) => p.usage.cpu, render: (p) =>
      `${cpu(p.usage.cpu)}<br><small class="muted">req ${p.requests.cpu ? cpu(p.requests.cpu) : "none"}</small>` },
    { key: "qos", label: "QoS", help: "col-qos", sort: (p) => p.qos, render: (p) =>
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
    { key: "count", label: "Count", help: "col-count", num: true, sort: (e) => e.count, render: (e) => e.count.toLocaleString() },
    { key: "first", label: "First seen", help: "col-chronic", num: true, sort: (e) => e.first_seen || "", render: (e) => timeAgo(e.first_seen) },
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

function hideHelp() {
  $("help-pop").classList.add("hidden");
  document.querySelectorAll(".help[aria-expanded='true']").forEach((button) => button.setAttribute("aria-expanded", "false"));
}

function showHelp(button) {
  const entry = HELP[button.dataset.help];
  if (!entry) return;
  const pop = $("help-pop");
  const reopen = button.getAttribute("aria-expanded") === "true";
  hideHelp();
  if (reopen) return;
  $("help-pop-title").textContent = entry[0];
  $("help-pop-body").textContent = entry[1];
  pop.classList.remove("hidden");
  const rect = button.getBoundingClientRect();
  const width = pop.offsetWidth;
  const left = Math.min(Math.max(8, rect.left), window.innerWidth - width - 8);
  const below = rect.bottom + 8;
  const top = below + pop.offsetHeight > window.innerHeight - 8 ? Math.max(8, rect.top - pop.offsetHeight - 8) : below;
  pop.style.left = `${left}px`;
  pop.style.top = `${top}px`;
  button.setAttribute("aria-expanded", "true");
}

document.addEventListener("click", async (ev) => {
  const help = ev.target.closest(".help");
  if (help) {
    ev.preventDefault();
    ev.stopPropagation();
    showHelp(help);
    return;
  }
  if (!ev.target.closest("#help-pop")) hideHelp();
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
$("context-select").addEventListener("change", (e) => {
  state.context = e.target.value;
  state.ns = "";
  state.open.clear();
  state.chat = [];
  renderChat();
  load();
});
$("refresh").addEventListener("click", () => load(true));
$("evaluate").addEventListener("click", async () => {
  const b = $("evaluate");
  b.disabled = true;
  try { await getJson("/v1/evaluate", { method: "POST" }); await load(); }
  catch (err) { showError(`Baseline evaluation failed: ${err.message}`); }
  finally { b.disabled = false; }
});
$("run-intelligence").addEventListener("click", async () => {
  const b = $("run-intelligence");
  b.disabled = true;
  b.textContent = "Investigating…";
  try {
    const q = new URLSearchParams({ context: state.context, force: "true" });
    state.data.intelligence = await getJson(`/v1/intelligence?${q}`, { method: "POST" });
    renderIntelligence(state.data.intelligence);
    toast("AI investigation generated");
  } catch (err) {
    showError(`AI investigation failed: ${err.message}`);
  } finally {
    b.textContent = "Generate investigation";
    b.disabled = !state.data?.intelligence?.status?.enabled;
  }
});

function schedule() {
  clearInterval(state.timer);
  if ($("auto-refresh").checked) state.timer = setInterval(() => load(), 60_000);
}
$("auto-refresh").addEventListener("change", schedule);
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Escape") return;
  if (!$("help-pop").classList.contains("hidden")) {
    hideHelp();
    return;
  }
  closeChat();
});

function renderChat() {
  const log = $("chat-log");
  log.innerHTML = state.chat.map((turn) => {
    const meta = turn.meta ? `<span class="meta">${esc(turn.meta)}</span>` : "";
    return `<div class="chat-msg ${turn.role}">${esc(turn.content)}${meta}</div>`;
  }).join("");
  log.scrollTop = log.scrollHeight;
  $("chat-suggestions").classList.toggle("hidden", state.chat.length > 0);
}

function openChat() {
  $("chat-panel").classList.remove("hidden");
  $("chat-open").classList.add("hidden");
  $("chat-input").focus();
}

function closeChat() {
  $("chat-panel").classList.add("hidden");
  $("chat-open").classList.remove("hidden");
}

async function sendChat(question) {
  const text = question.trim();
  if (!text || $("chat-send").disabled) return;
  state.chat.push({ role: "user", content: text });
  renderChat();
  $("chat-input").value = "";
  $("chat-send").disabled = true;
  try {
    const history = state.chat.slice(0, -1).slice(-8).map((turn) => ({ role: turn.role, content: turn.content }));
    const q = new URLSearchParams({ context: state.context });
    const res = await fetch(`/v1/chat?${q}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: text, history }),
    });
    const reply = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof reply.detail === "string" ? reply.detail : `${res.status} ${res.statusText}`);
    const bits = [];
    if (reply.grounded === "snapshot") bits.push("From this snapshot");
    else if (reply.provider) bits.push(`${reply.provider} / ${reply.model}`);
    if (reply.sources?.length) bits.push(reply.sources.join(", "));
    if (reply.unknown) bits.push(reply.unknown);
    state.chat.push({ role: "assistant", content: reply.answer, meta: bits.join(" · ") });
  } catch (err) {
    let detail = err.message;
    state.chat.push({ role: "assistant", content: detail, meta: "Request failed" });
  } finally {
    $("chat-send").disabled = false;
    renderChat();
  }
}

$("chat-open").addEventListener("click", openChat);
$("chat-close").addEventListener("click", closeChat);
$("chat-suggestions").addEventListener("click", (ev) => {
  const button = ev.target.closest("button");
  if (button?.dataset.question) sendChat(button.dataset.question);
});
$("chat-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  sendChat($("chat-input").value);
});
$("chat-input").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && !ev.shiftKey) {
    ev.preventDefault();
    sendChat($("chat-input").value);
  }
});

(async () => {
  $("insights").innerHTML = `<div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div>`;
  await loadContexts();
  await load();
  schedule();
})();
