// Copyright (c) 2026 Florian Fischer
// SPDX-License-Identifier: MIT

function licenseLabel(component) {
  const license = component.licenses?.[0]?.license;
  if (!license) return "—";
  return license.id || license.name || "—";
}

function pypiUrl(name) {
  return `https://pypi.org/project/${encodeURIComponent(name)}/`;
}

async function loadSbom() {
  const summary = document.getElementById("sbom-summary");
  const body = document.getElementById("sbom-body");
  try {
    const sbom = await apiGet("/sbom.json");
    const root = sbom.metadata?.component;
    const components = [...(sbom.components || [])].sort((a, b) => a.name.localeCompare(b.name));

    summary.textContent = `${components.length} runtime dependencies of ${root?.name || "this app"} ${root?.version || ""} — CycloneDX ${sbom.specVersion || "?"}.`;

    if (!components.length) {
      body.innerHTML = '<tr><td colspan="4" class="empty">No components listed.</td></tr>';
      return;
    }

    body.innerHTML = components
      .map(
        (c) => `
        <tr>
          <td><a href="${pypiUrl(c.name)}" target="_blank" rel="noopener">${escapeHtml(c.name)}</a></td>
          <td class="mono">${escapeHtml(c.version || "—")}</td>
          <td>${escapeHtml(licenseLabel(c))}</td>
          <td class="mono">${escapeHtml(c.purl || "—")}</td>
        </tr>`
      )
      .join("");
  } catch (err) {
    summary.textContent = "";
    body.innerHTML = `<tr><td colspan="4" class="empty">Failed to load SBOM: ${escapeHtml(err.message)}</td></tr>`;
  }
}

loadSbom();
