// Copyright (c) 2026 Florian Fischer
// SPDX-License-Identifier: MIT

const SEVERITY_COLORS = {
  CRITICAL: "#e5484d",
  HIGH: "#f2994a",
  MEDIUM: "#f2c94c",
  LOW: "#6fcf97",
  NONE: "#6b7280",
  UNKNOWN: "#6b7280",
};
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];

Chart.defaults.color = "#9aa3af";
Chart.defaults.borderColor = "#262b36";

const charts = { severity: null, vendors: null, trend: null };

function renderStatCards(stats) {
  const container = document.getElementById("stat-cards");
  const cards = [
    { label: "Total CVEs", value: stats.total.toLocaleString() },
    ...SEVERITY_ORDER.filter((s) => stats.by_severity[s]).map((s) => ({
      label: s,
      value: stats.by_severity[s].toLocaleString(),
    })),
  ];
  container.innerHTML = cards
    .map((c) => `<div class="stat-card"><div class="value">${c.value}</div><div class="label">${c.label}</div></div>`)
    .join("");
}

function renderSeverityChart(stats) {
  const labels = SEVERITY_ORDER.filter((s) => stats.by_severity[s]);
  const data = labels.map((s) => stats.by_severity[s]);
  charts.severity?.destroy();
  charts.severity = new Chart(document.getElementById("severity-chart"), {
    type: "doughnut",
    data: {
      labels,
      datasets: [{ data, backgroundColor: labels.map((s) => SEVERITY_COLORS[s]) }],
    },
    options: { plugins: { legend: { position: "bottom" } } },
  });
}

function renderVendorsChart(stats) {
  const labels = stats.top_vendors.map((v) => v.name);
  const data = stats.top_vendors.map((v) => v.count);
  charts.vendors?.destroy();
  charts.vendors = new Chart(document.getElementById("vendors-chart"), {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "CVEs", data, backgroundColor: "#5b9dff" }],
    },
    options: {
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true } },
    },
  });
}

function renderTrendChart(stats) {
  const labels = stats.ingestion_trend.map((p) => p.month);
  const data = stats.ingestion_trend.map((p) => p.count);
  charts.trend?.destroy();
  charts.trend = new Chart(document.getElementById("trend-chart"), {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Published CVEs",
          data,
          borderColor: "#5b9dff",
          backgroundColor: "rgba(91, 157, 255, 0.15)",
          fill: true,
          tension: 0.25,
          pointRadius: 0,
        },
      ],
    },
    options: { plugins: { legend: { display: false } } },
  });
}

async function loadDashboard() {
  try {
    const stats = await apiGet("/api/stats");
    renderStatCards(stats);
    renderSeverityChart(stats);
    renderVendorsChart(stats);
    renderTrendChart(stats);
  } catch (err) {
    document.getElementById("stat-cards").innerHTML = `<div class="empty">Failed to load stats: ${err.message}</div>`;
  }
}

// --- Fetch trigger + status polling ---

const fetchBtn = document.getElementById("fetch-btn");
const fetchStatusEl = document.getElementById("fetch-status");
let pollTimer = null;

function formatFetchStatus(status) {
  if (status.status === "running") {
    return status.progress || "Fetching...";
  }
  if (status.status === "done" && status.result) {
    const { releases_processed, files_imported } = status.result;
    if (releases_processed === 0) {
      return "Up to date, no new releases.";
    }
    return `Done: ${files_imported} CVE(s) imported/updated from ${releases_processed} release(s).`;
  }
  if (status.status === "error") {
    return `Failed: ${status.error}`;
  }
  return "";
}

function applyStatus(status) {
  fetchStatusEl.textContent = formatFetchStatus(status);
  fetchStatusEl.classList.toggle("error", status.status === "error");
  fetchStatusEl.classList.toggle("done", status.status === "done");
  fetchBtn.disabled = status.status === "running";
}

async function pollStatus() {
  try {
    const status = await apiGet("/api/fetch/status");
    applyStatus(status);
    if (status.status === "running") {
      pollTimer = setTimeout(pollStatus, 3000);
    } else {
      pollTimer = null;
      if (status.status === "done") {
        loadDashboard();
      }
    }
  } catch {
    pollTimer = setTimeout(pollStatus, 5000);
  }
}

fetchBtn.addEventListener("click", async () => {
  fetchBtn.disabled = true;
  fetchStatusEl.classList.remove("error", "done");
  fetchStatusEl.textContent = "Starting fetch...";
  try {
    await apiPost("/api/fetch");
    clearTimeout(pollTimer);
    pollStatus();
  } catch (err) {
    fetchStatusEl.textContent = `Failed to start: ${err.message}`;
    fetchStatusEl.classList.add("error");
    fetchBtn.disabled = false;
  }
});

// In case a fetch was already triggered elsewhere (another tab, the
// compose `fetch` profile, ...), pick up its status on page load.
apiGet("/api/fetch/status").then((status) => {
  applyStatus(status);
  if (status.status === "running") pollStatus();
}).catch(() => {});

loadDashboard();
