// Copyright (c) 2026 Florian Fischer
// SPDX-License-Identifier: MIT

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];
const RANGE_MONTHS = { "3m": 3, "6m": 6, "1y": 12, "3y": 36, all: Infinity };

const rootStyle = getComputedStyle(document.documentElement);
const cssVar = (name) => rootStyle.getPropertyValue(name).trim();

const SEVERITY_COLORS = {
  CRITICAL: cssVar("--critical"),
  HIGH: cssVar("--high"),
  MEDIUM: cssVar("--medium"),
  LOW: cssVar("--low"),
  NONE: cssVar("--none"),
  UNKNOWN: cssVar("--none"),
};
const ACCENT = cssVar("--accent");
const SERIES_2 = cssVar("--series-2");
const MUTED = cssVar("--muted");
const BORDER = cssVar("--panel-border");

Chart.defaults.color = MUTED;
Chart.defaults.borderColor = BORDER;
Chart.defaults.font.family = "'IBM Plex Sans', sans-serif";

const charts = { severity: null, cvssHist: null, cumulative: null, trend: null, vendors: null, products: null };
let currentStats = null;
let currentRange = "1y";

function hexToRgba(hex, alpha) {
  const h = hex.replace("#", "");
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

// Buckets the monthly published-date trend into yearly totals, then turns
// those into a running total so the chart reads as catalog growth over time.
function cumulativeByYear(monthlyTrend) {
  const perYear = new Map();
  for (const { month, count } of monthlyTrend) {
    const year = month.slice(0, 4);
    perYear.set(year, (perYear.get(year) || 0) + count);
  }
  const years = [...perYear.keys()].sort();
  let running = 0;
  return years.map((year) => {
    running += perYear.get(year);
    return { year, total: running };
  });
}

function renderKpiStrip(stats) {
  const highRisk = (stats.by_severity.CRITICAL || 0) + (stats.by_severity.HIGH || 0);
  const items = [
    ["Total CVEs", stats.total.toLocaleString(), null],
    ["High-risk", highRisk.toLocaleString(), "Critical + high severity"],
    ["New this week", stats.new_last_7d.toLocaleString(), `${stats.new_last_30d.toLocaleString()} in the last 30 days`],
    ["Avg CVSS", stats.avg_cvss != null ? stats.avg_cvss.toFixed(1) : "—", "Scored CVEs only"],
    ["Vendors tracked", stats.distinct_vendor_count.toLocaleString(), null],
    ["Products tracked", stats.distinct_product_count.toLocaleString(), null],
  ];
  document.getElementById("kpi-strip").innerHTML = items
    .map(
      ([label, value, title]) => `
      <div class="kpi-item"${title ? ` title="${escapeHtml(title)}"` : ""}>
        <div class="value">${value}</div>
        <div class="label">${label}</div>
      </div>`
    )
    .join("");
}

function renderSeverityChart(stats) {
  const labels = SEVERITY_ORDER.filter((s) => stats.by_severity[s]);
  const data = labels.map((s) => stats.by_severity[s]);
  charts.severity?.destroy();
  charts.severity = new Chart(document.getElementById("severity-chart"), {
    type: "bar",
    data: { labels, datasets: [{ data, backgroundColor: labels.map((s) => SEVERITY_COLORS[s]) }] },
    options: {
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, grid: { color: BORDER } },
        y: { grid: { display: false } },
      },
    },
  });
}

function renderCvssHistogram(stats) {
  const labels = stats.cvss_distribution.map((b) => b.range);
  const data = stats.cvss_distribution.map((b) => b.count);
  charts.cvssHist?.destroy();
  charts.cvssHist = new Chart(document.getElementById("cvss-hist-chart"), {
    type: "bar",
    data: { labels, datasets: [{ data, backgroundColor: ACCENT, borderRadius: 3 }] },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, grid: { color: BORDER } },
        x: { grid: { display: false } },
      },
    },
  });
  const scored = stats.cvss_distribution.reduce((sum, b) => sum + b.count, 0);
  const unscored = Math.max(0, stats.total - scored);
  document.getElementById("cvss-hist-caption").textContent =
    `Distribution of ${scored.toLocaleString()} scored CVEs (${unscored.toLocaleString()} unscored, out of ${stats.total.toLocaleString()} total)`;
}

function renderCumulativeChart(stats) {
  const points = cumulativeByYear(stats.ingestion_trend);
  charts.cumulative?.destroy();
  charts.cumulative = new Chart(document.getElementById("cumulative-chart"), {
    type: "line",
    data: {
      labels: points.map((p) => p.year),
      datasets: [
        {
          label: "Total CVEs",
          data: points.map((p) => p.total),
          borderColor: ACCENT,
          backgroundColor: hexToRgba(ACCENT, 0.15),
          fill: true,
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.2,
        },
      ],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, grid: { color: BORDER } },
        x: { grid: { display: false } },
      },
    },
  });
}

function renderTrendChart(range) {
  const n = RANGE_MONTHS[range];
  const slice = (arr) => (n === Infinity ? arr : arr.slice(-n));
  const published = slice(currentStats.ingestion_trend);
  const modified = slice(currentStats.modified_trend);
  const longer = published.length >= modified.length ? published : modified;
  const labels = longer.map((p) => p.month);
  const publishedMap = new Map(published.map((p) => [p.month, p.count]));
  const modifiedMap = new Map(modified.map((p) => [p.month, p.count]));

  charts.trend?.destroy();
  charts.trend = new Chart(document.getElementById("trend-chart"), {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Published",
          data: labels.map((m) => publishedMap.get(m) ?? 0),
          borderColor: ACCENT,
          backgroundColor: ACCENT,
          pointRadius: 0,
          borderWidth: 2,
          tension: 0.2,
        },
        {
          label: "Modified",
          data: labels.map((m) => modifiedMap.get(m) ?? 0),
          borderColor: SERIES_2,
          backgroundColor: SERIES_2,
          pointRadius: 0,
          borderWidth: 2,
          tension: 0.2,
        },
      ],
    },
    options: {
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: true, position: "bottom" },
        tooltip: { bodyFont: { family: "'IBM Plex Mono', monospace" } },
      },
      scales: {
        y: { beginAtZero: true, grid: { color: BORDER } },
        x: { grid: { display: false } },
      },
    },
  });
}

function setRange(range) {
  currentRange = range;
  document.querySelectorAll("#trend-range button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.range === range);
  });
  if (currentStats) renderTrendChart(range);
}

function renderBarChart(key, canvasId, items) {
  const labels = items.map((v) => v.name);
  const data = items.map((v) => v.count);
  charts[key]?.destroy();
  charts[key] = new Chart(document.getElementById(canvasId), {
    type: "bar",
    data: { labels, datasets: [{ data, backgroundColor: ACCENT }] },
    options: {
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, grid: { color: BORDER } },
        y: { grid: { display: false } },
      },
    },
  });
}

function renderRecentFeed(stats) {
  const container = document.getElementById("recent-feed");
  if (!stats.recent_modified.length) {
    container.innerHTML = '<tr><td colspan="4" class="empty">No recent activity.</td></tr>';
    return;
  }
  container.innerHTML = stats.recent_modified
    .map((item) => {
      const severity = item.severity || "UNKNOWN";
      return `
        <tr>
          <td><a href="/index.html?cve=${encodeURIComponent(item.cve_id)}" class="mono">${escapeHtml(item.cve_id)}</a></td>
          <td><span class="chip ${escapeHtml(severity)}">${escapeHtml(severity)}</span></td>
          <td>${escapeHtml(item.title || "—")}</td>
          <td class="mono">${formatRelative(item.modified_date)}</td>
        </tr>`;
    })
    .join("");
}

async function loadDashboard() {
  try {
    const stats = await apiGet("/api/stats");
    currentStats = stats;
    renderKpiStrip(stats);
    renderSeverityChart(stats);
    renderCvssHistogram(stats);
    renderCumulativeChart(stats);
    renderTrendChart(currentRange);
    renderBarChart("vendors", "vendors-chart", stats.top_vendors);
    renderBarChart("products", "products-chart", stats.top_products);
    renderRecentFeed(stats);
    document.getElementById("last-synced").textContent = formatRelative(stats.last_fetch_at);
  } catch (err) {
    document.getElementById("kpi-strip").innerHTML = `<div class="empty">Failed to load stats: ${escapeHtml(err.message)}</div>`;
  }
}

document.querySelectorAll("#trend-range button").forEach((btn) => {
  btn.addEventListener("click", () => setRange(btn.dataset.range));
});

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
