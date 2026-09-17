// Copyright (c) 2026 Florian Fischer
// SPDX-License-Identifier: MIT

const state = {
  q: "",
  vendor: "",
  product: "",
  severity: "",
  page: 1,
  pageSize: 25,
};

const resultsBody = document.getElementById("results-body");
const pageInfo = document.getElementById("page-info");
const prevBtn = document.getElementById("prev-page");
const nextBtn = document.getElementById("next-page");
const detailOverlay = document.getElementById("detail-overlay");
const detailCard = document.getElementById("detail-card");

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

async function loadResults() {
  resultsBody.innerHTML = '<tr><td colspan="6" class="loading">Loading...</td></tr>';
  try {
    const data = await apiGet("/api/cves", {
      q: state.q,
      vendor: state.vendor,
      product: state.product,
      severity: state.severity,
      page: state.page,
      page_size: state.pageSize,
    });
    renderResults(data);
  } catch (err) {
    resultsBody.innerHTML = `<tr><td colspan="6" class="empty">Failed to load results: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function renderResults(data) {
  if (!data.items.length) {
    resultsBody.innerHTML = '<tr><td colspan="6" class="empty">No CVEs match your filters.</td></tr>';
  } else {
    resultsBody.innerHTML = data.items
      .map((item) => {
        const vendorsProducts = [...new Set([...item.vendors, ...item.products])].slice(0, 3).join(", ");
        return `
          <tr data-cve-id="${escapeHtml(item.cve_id)}">
            <td class="mono">${escapeHtml(item.cve_id)}</td>
            <td>${escapeHtml(item.title || "—")}</td>
            <td><span class="chip ${escapeHtml(item.severity || "UNKNOWN")}">${escapeHtml(item.severity || "UNKNOWN")}</span></td>
            <td class="mono">${item.cvss_score ? item.cvss_score.toFixed(1) : "—"}</td>
            <td class="mono">${formatDate(item.published_date)}</td>
            <td>${escapeHtml(vendorsProducts || "—")}</td>
          </tr>`;
      })
      .join("");
    resultsBody.querySelectorAll("tr[data-cve-id]").forEach((row) => {
      row.addEventListener("click", () => openDetail(row.dataset.cveId));
    });
  }

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  pageInfo.textContent = `Page ${data.page} of ${totalPages} (${data.total} results)`;
  prevBtn.disabled = data.page <= 1;
  nextBtn.disabled = data.page >= totalPages;
}

async function openDetail(cveId) {
  detailCard.innerHTML = '<div class="loading">Loading...</div>';
  detailOverlay.classList.remove("hidden");
  try {
    const cve = await apiGet(`/api/cves/${encodeURIComponent(cveId)}`);
    detailCard.innerHTML = `
      <button class="close-btn" id="close-detail">&times;</button>
      <h2 class="mono">${escapeHtml(cve.cve_id)}</h2>
      <div>${escapeHtml(cve.title || "")}</div>
      <dl>
        <dt>Severity</dt><dd><span class="chip ${escapeHtml(cve.severity || "UNKNOWN")}">${escapeHtml(cve.severity || "UNKNOWN")}</span></dd>
        <dt>CVSS</dt><dd class="mono">${cve.cvss_score ? cve.cvss_score.toFixed(1) : "—"} ${escapeHtml(cve.cvss_vector || "")}</dd>
        <dt>Published</dt><dd class="mono">${formatDate(cve.published_date)}</dd>
        <dt>Modified</dt><dd class="mono">${formatDate(cve.modified_date)}</dd>
        <dt>Vendors</dt><dd>${cve.vendors.map((v) => `<span class="tag">${escapeHtml(v)}</span>`).join("") || "—"}</dd>
        <dt>Products</dt><dd>${cve.products.map((p) => `<span class="tag">${escapeHtml(p)}</span>`).join("") || "—"}</dd>
        <dt>Advisory</dt><dd>${cve.advisory_url ? `<a href="${escapeHtml(cve.advisory_url)}" target="_blank" rel="noopener">${escapeHtml(cve.advisory_url)}</a>` : "—"}</dd>
      </dl>
      <p>${escapeHtml(cve.description || "No description available.")}</p>
      <div class="refs">
        <strong>References</strong>
        <ul>
          ${cve.references.map((r) => `<li><a href="${escapeHtml(r.url)}" target="_blank" rel="noopener">${escapeHtml(r.url)}</a></li>`).join("") || "<li>None</li>"}
        </ul>
      </div>
    `;
    document.getElementById("close-detail").addEventListener("click", closeDetail);
  } catch (err) {
    detailCard.innerHTML = `<button class="close-btn" id="close-detail">&times;</button><div class="empty">Failed to load ${escapeHtml(cveId)}: ${escapeHtml(err.message)}</div>`;
    document.getElementById("close-detail").addEventListener("click", closeDetail);
  }
}

function closeDetail() {
  detailOverlay.classList.add("hidden");
}

detailOverlay.addEventListener("click", (e) => {
  if (e.target === detailOverlay) closeDetail();
});

const triggerSearch = debounce(() => {
  state.page = 1;
  loadResults();
}, 300);

document.getElementById("q").addEventListener("input", (e) => {
  state.q = e.target.value;
  triggerSearch();
});
document.getElementById("vendor").addEventListener("input", (e) => {
  state.vendor = e.target.value;
  triggerSearch();
  refreshAutocomplete("vendor", "vendor-options", e.target.value);
});
document.getElementById("product").addEventListener("input", (e) => {
  state.product = e.target.value;
  triggerSearch();
  refreshAutocomplete("product", "product-options", e.target.value);
});
document.getElementById("severity").addEventListener("change", (e) => {
  state.severity = e.target.value;
  state.page = 1;
  loadResults();
});
prevBtn.addEventListener("click", () => {
  if (state.page > 1) {
    state.page -= 1;
    loadResults();
  }
});
nextBtn.addEventListener("click", () => {
  state.page += 1;
  loadResults();
});

const refreshAutocomplete = debounce(async (kind, datalistId, prefix) => {
  if (!prefix) return;
  try {
    const options = await apiGet(`/api/${kind === "vendor" ? "vendors" : "products"}`, { prefix, limit: 10 });
    const datalist = document.getElementById(datalistId);
    datalist.innerHTML = options.map((o) => `<option value="${escapeHtml(o)}"></option>`).join("");
  } catch {
    // autocomplete is a nicety; ignore failures
  }
}, 250);

const initialParams = new URLSearchParams(window.location.search);
const initialQ = initialParams.get("q");
const initialCve = initialParams.get("cve");
if (initialQ) {
  state.q = initialQ;
  document.getElementById("q").value = initialQ;
}

loadResults();

if (initialCve) {
  openDetail(initialCve);
}
