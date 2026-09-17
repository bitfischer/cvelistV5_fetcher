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

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function formatDate(iso) {
  if (!iso) return "—";
  return iso.slice(0, 10);
}

// The API returns naive UTC timestamps with no offset (e.g. "2026-09-10T21:00:00").
// `new Date(...)` treats an offset-less string as local time, so relative-time math
// would silently skew by the viewer's UTC offset unless we append "Z" first.
function parseUtc(iso) {
  if (!iso) return null;
  const hasOffset = /Z$|[+-]\d\d:?\d\d$/.test(iso);
  return new Date(hasOffset ? iso : `${iso}Z`);
}

function formatRelative(iso) {
  const d = parseUtc(iso);
  if (!d || Number.isNaN(d.getTime())) return "never";
  const minutes = Math.max(0, Math.round((Date.now() - d.getTime()) / 60000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return d.toISOString().slice(0, 10);
}
