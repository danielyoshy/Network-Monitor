// --- STATE --------------------------------------------------------------
let isPaused = false;
let latestSnapshot = null;   // most recent snapshot, kept for search + drawer re-render
let filterText = "";
let roleFilter = "all";      // "all" | "service" | "personal"
const HISTORY = 60;          // seconds of history retained on the time-series charts

// --- FORMATTING HELPERS -------------------------------------------------
function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / Math.pow(1024, i)).toFixed(i ? 2 : 0)} ${units[i]}`;
}
function fmtRate(bps) { return `${fmtBytes(bps)}/s`; }

// --- CHART.JS SETUP -----------------------------------------------------
Chart.defaults.color = "#a6adc8";
Chart.defaults.borderColor = "#313244";

const bandwidthChart = new Chart(document.getElementById("bandwidthChart"), {
  type: "line",
  data: {
    labels: Array(HISTORY).fill(""),
    datasets: [
      {
        label: "Download", data: Array(HISTORY).fill(0),
        borderColor: "#89b4fa", backgroundColor: "rgba(137,180,250,0.2)",
        fill: true, tension: 0.4, pointRadius: 0, borderWidth: 2,
      },
      {
        label: "Upload", data: Array(HISTORY).fill(0),
        borderColor: "#fab387", backgroundColor: "rgba(250,179,135,0.15)",
        fill: true, tension: 0.4, pointRadius: 0, borderWidth: 2,
      },
    ],
  },
  options: {
    responsive: true, maintainAspectRatio: false, animation: false,
    plugins: {
      title: { display: true, text: "Throughput (Download / Upload)" },
      legend: { display: true },
    },
    scales: { y: { beginAtZero: true, ticks: { callback: (v) => fmtRate(v) } } },
  },
});

const flowsChart = new Chart(document.getElementById("flowsChart"), {
  type: "line",
  data: {
    labels: Array(HISTORY).fill(""),
    datasets: [{
      label: "Active Flows", data: Array(HISTORY).fill(0),
      borderColor: "#a6e3a1", backgroundColor: "rgba(166,227,161,0.15)",
      fill: true, tension: 0.2, pointRadius: 0, borderWidth: 2,
    }],
  },
  options: {
    responsive: true, maintainAspectRatio: false, animation: false,
    plugins: { title: { display: true, text: "Concurrent Flows" }, legend: { display: false } },
    scales: { y: { beginAtZero: true, precision: 0 } },
  },
});

const PROTO_COLORS = ["#89b4fa", "#fab387", "#f9e2af", "#a6e3a1", "#f38ba8",
                      "#cba6f7", "#94e2d5", "#a6adc8"];
const protocolChart = new Chart(document.getElementById("protocolChart"), {
  type: "doughnut",
  data: { labels: [], datasets: [{ data: [], backgroundColor: PROTO_COLORS, borderWidth: 0 }] },
  options: {
    responsive: true, maintainAspectRatio: false, cutout: "70%",
    plugins: { title: { display: true, text: "Protocol Distribution" }, legend: { position: "right" } },
  },
});

function pushSeries(chart, datasetIndex, value) {
  const ds = chart.data.datasets[datasetIndex].data;
  ds.shift();
  ds.push(value);
}

// --- WEBSOCKET ----------------------------------------------------------
const ws = new WebSocket(`ws://${location.host}/ws/packets`);

ws.onopen = () => setStatus("Live &mdash; capturing", "healthy");
ws.onclose = () => setStatus("Disconnected", "alert");
ws.onerror = () => setStatus("Connection error", "alert");

ws.onmessage = (event) => {
  const snap = JSON.parse(event.data);
  latestSnapshot = snap;
  if (isPaused) return;
  render(snap);
};

function setStatus(html, cls) {
  const el = document.getElementById("globalStatus");
  el.innerHTML = html;
  el.className = `status-text ${cls}`;
}

// --- RENDER -------------------------------------------------------------
function render(snap) {
  const g = snap.global;

  // KPI cards
  document.getElementById("kpiDownload").textContent = fmtRate(g.download_bps);
  document.getElementById("kpiUpload").textContent = fmtRate(g.upload_bps);
  document.getElementById("kpiHosts").textContent = g.active_hosts ?? "0";
  document.getElementById("kpiFlows").textContent = g.active_flows;
  document.getElementById("kpiPeakDown").textContent = fmtRate(g.peak_download_bps);
  document.getElementById("kpiPeakUp").textContent = fmtRate(g.peak_upload_bps);
  document.getElementById("kpiTotalDown").textContent = fmtBytes(g.total_down_bytes);
  document.getElementById("kpiTotalUp").textContent = fmtBytes(g.total_up_bytes);

  // Time-series charts
  pushSeries(bandwidthChart, 0, g.download_bps);
  pushSeries(bandwidthChart, 1, g.upload_bps);
  bandwidthChart.update();
  pushSeries(flowsChart, 0, g.active_flows);
  flowsChart.update();

  // Protocol donut
  const labels = Object.keys(snap.protocols);
  protocolChart.data.labels = labels;
  protocolChart.data.datasets[0].data = labels.map((k) => snap.protocols[k]);
  protocolChart.update();

  renderHosts(snap.hosts || []);
  renderAlerts(snap.alerts || []);
}

// --- ANOMALY ALERTS -----------------------------------------------------
const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function renderAlerts(alerts) {
  const list = document.getElementById("alertsList");
  document.getElementById("alertCount").textContent = alerts.length ? `(${alerts.length})` : "";

  if (!alerts.length) {
    list.innerHTML = `<div class="no-alerts">No anomalies detected.</div>`;
    setStatus("Live &mdash; no anomalies", "healthy");
    return;
  }

  // Drive the top-bar status from the most severe active alert.
  const worst = alerts.reduce((a, b) =>
    (SEV_RANK[b.severity] < SEV_RANK[a.severity] ? b : a));
  setStatus(`${alerts.length} anomal${alerts.length > 1 ? "ies" : "y"} &mdash; ${worst.severity}`, "alert");

  list.innerHTML = "";
  const frag = document.createDocumentFragment();
  alerts.forEach((a) => {
    const el = document.createElement("div");
    el.className = `alert-item sev-${a.severity.toLowerCase()}`;
    const score = a.score != null && a.score !== "-" ? `<span class="alert-score">${a.score}</span>` : "";
    el.innerHTML = `
      <span class="alert-badge">${a.severity}</span>
      <span class="alert-type">${a.type}</span>
      <span class="alert-msg">${a.message}</span>
      <span class="alert-indicators">${(a.indicators || []).join(" · ")}</span>
      ${score}`;
    frag.appendChild(el);
  });
  list.appendChild(frag);
}

// A host's category drives its icon and the coloured "Type" badge.
const CATEGORY = {
  self:      { icon: "💻", label: "This device", cls: "cat-self" },
  gateway:   { icon: "📶", label: "Router",       cls: "cat-gateway" },
  lan:       { icon: "🖥️", label: "Local device", cls: "cat-lan" },
  dns:       { icon: "🧭", label: "DNS",          cls: "cat-dns" },
  provider:  { icon: "🌐", label: "Service",      cls: "cat-provider" },
  multicast: { icon: "📡", label: "Multicast",    cls: "cat-mcast" },
  broadcast: { icon: "📣", label: "Broadcast",    cls: "cat-bcast" },
  internet:  { icon: "🌍", label: "Internet",     cls: "cat-internet" },
};
function category(cat) { return CATEGORY[cat] || CATEGORY.internet; }

// Role: server/service vs personal computer.
const ROLE = {
  service:  { label: "Server / Service", cls: "role-service" },
  personal: { label: "Personal computer", cls: "role-personal" },
};
function role(r) { return ROLE[r] || ROLE.service; }

// Primary service Category -> icon + badge colour. Keys match labels.py.
const SERVICE_CAT = {
  "Gaming Infrastructure":      { icon: "🎮", cls: "svc-gaming" },
  "CDN & Cloud Hosting":        { icon: "☁️", cls: "svc-cloud" },
  "Secure Web Traffic (HTTPS)": { icon: "🔒", cls: "svc-web" },
  "Network System Services":    { icon: "🧩", cls: "svc-core" },
  "Local Endpoint / Loopback":  { icon: "🏠", cls: "svc-local" },
  "Other Service":              { icon: "🌍", cls: "svc-other" },
};
function serviceCat(name) {
  return SERVICE_CAT[name] || { icon: "•", cls: "svc-other" };
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function matchesFilter(h) {
  if (roleFilter !== "all" && (h.role || "service") !== roleFilter) return false;
  if (!filterText) return true;
  const hay = `${h.name} ${h.ip} ${h.hostname} ${h.country} ${h.asn} ${h.org} `
    + `${(h.apps || []).join(" ")} ${h.service_category || ""} ${role(h.role).label} `
    + `${h.is_lan ? "lan" : ""}`.toLowerCase();
  return hay.includes(filterText);
}

// "Where is this host": LAN, or country + org for internet peers.
function locationLabel(h) {
  if (h.is_lan) return "Local network";
  const parts = [];
  if (h.country) parts.push(h.country);
  if (h.org) parts.push(h.org);
  else if (h.asn) parts.push(h.asn);
  return parts.join(" · ") || "—";
}

function renderHosts(hosts) {
  const tbody = document.getElementById("flowsBody");

  // Tab counts always reflect the full host set (before the role/text filter).
  const nService = hosts.filter((h) => (h.role || "service") === "service").length;
  const nPersonal = hosts.filter((h) => (h.role || "service") === "personal").length;
  document.getElementById("countAll").textContent = `(${hosts.length})`;
  document.getElementById("countService").textContent = `(${nService})`;
  document.getElementById("countPersonal").textContent = `(${nPersonal})`;

  const visible = hosts.filter(matchesFilter);
  document.getElementById("flowCount").textContent =
    `(${visible.length}${hosts.length !== visible.length ? ` / ${hosts.length}` : ""})`;

  tbody.innerHTML = "";
  const frag = document.createDocumentFragment();
  visible.forEach((h) => {
    const cat = category(h.category);
    const rl = role(h.role);
    const sc = serviceCat(h.service_category);
    // Host cell = the specific Service/Host name; keep the raw IP as a subtitle
    // unless the name already *is* the IP (then don't repeat it).
    const sub = h.name === h.ip ? "" : `<div class="sub">${escapeHtml(h.ip)}</div>`;
    const apps = (h.apps || []).slice(0, 3).map((a) => `<span class="pill">${escapeHtml(a)}</span>`).join(" ");
    const moreApps = (h.apps || []).length > 3 ? `<span class="sub">+${h.apps.length - 3}</span>` : "";
    // Category cell = primary Category badge + subtitle (or the role as fallback).
    const catSub = h.service_subtitle || rl.label;
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><strong>${cat.icon} ${escapeHtml(h.name)}</strong>${sub}</td>
      <td>
        <span class="svc-badge ${sc.cls}">${sc.icon} ${escapeHtml(h.service_category || "—")}</span>
        <div class="role-tag ${rl.cls}">${escapeHtml(catSub)}</div>
      </td>
      <td class="sub">${escapeHtml(locationLabel(h))}</td>
      <td>${apps} ${moreApps}</td>
      <td>${fmtRate(h.down_bps)}<div class="sub">${fmtBytes(h.down_bytes)}</div></td>
      <td>${fmtRate(h.up_bps)}<div class="sub">${fmtBytes(h.up_bytes)}</div></td>
      <td>${h.flow_count}</td>
      <td><button class="btn-inspect" data-key="${escapeHtml(h.ip)}">Inspect</button></td>`;
    frag.appendChild(row);
  });
  tbody.appendChild(frag);
}

// --- FLOW INSPECTION DRAWER --------------------------------------------
const drawer = document.getElementById("sideDrawer");
document.getElementById("closeDrawer").addEventListener("click", () => drawer.classList.remove("open"));

document.getElementById("flowsBody").addEventListener("click", (e) => {
  const btn = e.target.closest(".btn-inspect");
  if (btn) openDrawer(btn.dataset.key);
});

function openDrawer(ip) {
  if (!latestSnapshot) return;
  const h = (latestSnapshot.hosts || []).find((x) => x.ip === ip);
  if (!h) return;
  const cat = category(h.category);
  document.getElementById("drawerTitle").textContent = `${cat.icon} ${h.name}`;

  const catText = h.service_category
    ? (h.service_subtitle ? `${h.service_category} (${h.service_subtitle})` : h.service_category)
    : "—";
  const rows = [
    ["Category", catText],
    ["Kind", role(h.role).label],
    ["Type", cat.label],
    ["IP address", h.ip],
    ["Hostname", h.hostname || "(unresolved)"],
    ["Location", h.is_lan ? "Local network" : (h.country || "—")],
    ["Organisation", h.org || "—"],
    ["ASN", h.asn || "—"],
    ["Apps", (h.apps || []).join(", ") || "—"],
    ["Download", `${fmtRate(h.down_bps)} — ${fmtBytes(h.down_bytes)} total`],
    ["Upload", `${fmtRate(h.up_bps)} — ${fmtBytes(h.up_bytes)} total`],
    ["Packets", h.packets],
    ["Connections", h.flow_count],
  ];

  // Per-connection breakdown so the aggregate is still drillable.
  const conns = (h.connections || [])
    .slice()
    .sort((a, b) => (b.down_bps + b.up_bps) - (a.down_bps + a.up_bps))
    .map((c) => `
      <tr>
        <td><span class="pill">${escapeHtml(c.app_proto)}</span></td>
        <td class="sub">${escapeHtml(c.proto)} :${c.remote_port}</td>
        <td>${fmtRate(c.down_bps)}</td>
        <td>${fmtRate(c.up_bps)}</td>
        <td>${c.packets}</td>
      </tr>`).join("");

  document.getElementById("drawerBody").innerHTML = `
    <dl class="detail-list">
      ${rows.map(([k, v]) => `<dt>${k}</dt><dd>${escapeHtml(v)}</dd>`).join("")}
    </dl>
    <h4 class="drawer-subhead">Connections</h4>
    <table class="conn-table">
      <thead><tr><th>App</th><th>Port</th><th>&darr;</th><th>&uarr;</th><th>Pkts</th></tr></thead>
      <tbody>${conns || `<tr><td colspan="5" class="sub">No active connections.</td></tr>`}</tbody>
    </table>`;
  drawer.classList.add("open");
}

// --- CONTROLS -----------------------------------------------------------
document.getElementById("globalSearch").addEventListener("input", (e) => {
  filterText = e.target.value.trim().toLowerCase();
  if (latestSnapshot) renderHosts(latestSnapshot.hosts || []);  // re-filter without waiting for next tick
});

// Role tabs: separate servers/services from personal computers.
document.getElementById("hostTabs").addEventListener("click", (e) => {
  const tab = e.target.closest(".host-tab");
  if (!tab) return;
  roleFilter = tab.dataset.role;
  document.querySelectorAll(".host-tab").forEach((t) =>
    t.classList.toggle("active", t === tab));
  if (latestSnapshot) renderHosts(latestSnapshot.hosts || []);
});

document.getElementById("togglePause").addEventListener("click", (e) => {
  isPaused = !isPaused;
  e.target.textContent = isPaused ? "Resume Traffic" : "Pause Traffic";
  e.target.classList.toggle("paused", isPaused);
  if (!isPaused && latestSnapshot) render(latestSnapshot);
});
