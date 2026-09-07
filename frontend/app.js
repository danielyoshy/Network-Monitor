// --- STATE --------------------------------------------------------------
let isPaused = false;
let latestSnapshot = null;   // most recent snapshot, kept for search + drawer re-render
let filterText = "";
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

  renderFlows(snap.flows);
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

function matchesFilter(f) {
  if (!filterText) return true;
  const hay = `${f.remote_ip} ${f.hostname} ${f.country} ${f.asn} ${f.org} `
    + `${f.app_proto} ${f.proto} ${f.remote_port} ${f.traffic_type} `
    + `${f.is_lan ? "lan" : ""}`.toLowerCase();
  return hay.includes(filterText);
}

// Scope label for the remote endpoint: LAN / multicast / broadcast / country.
function scopeLabel(f) {
  if (f.traffic_type === "multicast") return { text: "MCAST", cls: "scope-mcast" };
  if (f.traffic_type === "broadcast") return { text: "BCAST", cls: "scope-bcast" };
  if (f.is_lan) return { text: "LAN", cls: "scope-lan" };
  if (f.country) return { text: f.country, cls: "scope-country" };
  return { text: "—", cls: "" };
}

function renderFlows(flows) {
  const tbody = document.getElementById("flowsBody");
  const visible = flows.filter(matchesFilter);
  document.getElementById("flowCount").textContent =
    `(${visible.length}${flows.length !== visible.length ? ` / ${flows.length}` : ""})`;

  tbody.innerHTML = "";
  const frag = document.createDocumentFragment();
  visible.forEach((f) => {
    const host = f.hostname || f.remote_ip;
    const scope = scopeLabel(f);
    const org = f.asn ? `${f.asn}${f.org ? " · " + f.org : ""}` : (f.org || "—");
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><strong>${host}</strong><div class="sub">${f.remote_ip}:${f.remote_port}</div></td>
      <td><span class="scope ${scope.cls}">${scope.text}</span></td>
      <td class="sub">${org}</td>
      <td><span class="pill">${f.app_proto}</span></td>
      <td>${fmtRate(f.down_bps)}<div class="sub">${fmtBytes(f.down_bytes)}</div></td>
      <td>${fmtRate(f.up_bps)}<div class="sub">${fmtBytes(f.up_bytes)}</div></td>
      <td>${f.packets}</td>
      <td><button class="btn-inspect" data-key="${f.key}">Inspect</button></td>`;
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

function openDrawer(key) {
  if (!latestSnapshot) return;
  const f = latestSnapshot.flows.find((x) => x.key === key);
  if (!f) return;
  document.getElementById("drawerTitle").textContent = f.hostname || f.remote_ip;
  const rows = [
    ["Remote IP", `${f.remote_ip}:${f.remote_port}`],
    ["Hostname", f.hostname || "(unresolved)"],
    ["Country", f.country || "—"],
    ["ASN", f.asn || "—"],
    ["Organisation", f.org || "—"],
    ["Local IP", f.local_ip],
    ["Scope", f.is_lan ? "LAN (local network)" : "Internet"],
    ["Traffic type", f.traffic_type],
    ["Transport", f.proto],
    ["Application", f.app_proto],
    ["Download", `${fmtRate(f.down_bps)} — ${fmtBytes(f.down_bytes)} total`],
    ["Upload", `${fmtRate(f.up_bps)} — ${fmtBytes(f.up_bytes)} total`],
    ["Packets", f.packets],
  ];
  document.getElementById("drawerBody").innerHTML = rows
    .map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
  drawer.classList.add("open");
}

// --- CONTROLS -----------------------------------------------------------
document.getElementById("globalSearch").addEventListener("input", (e) => {
  filterText = e.target.value.trim().toLowerCase();
  if (latestSnapshot) renderFlows(latestSnapshot.flows);  // re-filter without waiting for next tick
});

document.getElementById("togglePause").addEventListener("click", (e) => {
  isPaused = !isPaused;
  e.target.textContent = isPaused ? "Resume Traffic" : "Pause Traffic";
  e.target.classList.toggle("paused", isPaused);
  if (!isPaused && latestSnapshot) render(latestSnapshot);
});
