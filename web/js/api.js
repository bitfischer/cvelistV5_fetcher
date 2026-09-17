// Copyright (c) 2026 Florian Fischer
// SPDX-License-Identifier: MIT

async function apiGet(path, params = {}) {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, value);
    }
  }
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`${resp.status} ${resp.statusText}`);
  }
  return resp.json();
}

async function apiPost(path) {
  const resp = await fetch(path, { method: "POST" });
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(body.detail || `${resp.status} ${resp.statusText}`);
  }
  return body;
}
