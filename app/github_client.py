# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

"""GitHub Releases client for CVEProject/cvelistV5.

The cvelistV5 repo publishes periodic releases: most carry a "delta" zip of
changed CVE JSON files since the previous release, and some also carry a
full "all CVEs" archive. We never clone the repo or use the CVE Services
API - just the Releases API, which is enough to do a full-then-delta sync.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import httpx

from app.guard import MAX_RELEASES_RESPONSE_BYTES

REPO = "CVEProject/cvelistV5"
RELEASES_URL = f"https://api.github.com/repos/{REPO}/releases"


@dataclass
class Asset:
    name: str
    download_url: str
    size: int


@dataclass
class Release:
    tag_name: str
    assets: list[Asset] = field(default_factory=list)


def _client(timeout: float) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cvelistv5-fetcher",
        },
        follow_redirects=True,
    )


def list_releases(per_page: int = 100, max_pages: int = 10) -> list[Release]:
    """Fetch all releases (paginated), sorted oldest -> newest by tag name."""
    releases: list[Release] = []
    with _client(timeout=30.0) as client:
        for page in range(1, max_pages + 1):
            resp = client.get(RELEASES_URL, params={"per_page": per_page, "page": page})
            resp.raise_for_status()
            if len(resp.content) > MAX_RELEASES_RESPONSE_BYTES:
                raise ValueError("releases response exceeds size limit")
            batch = resp.json()
            if not batch:
                break
            for rel in batch:
                assets = [
                    Asset(name=a["name"], download_url=a["browser_download_url"], size=a["size"])
                    for a in rel.get("assets", [])
                ]
                releases.append(Release(tag_name=rel["tag_name"], assets=assets))
            if len(batch) < per_page:
                break
    releases.sort(key=lambda r: r.tag_name)
    return releases


def find_archive_asset(release: Release) -> Asset | None:
    """The full 'all CVEs' archive, published on some (not all) releases."""
    for asset in release.assets:
        name = asset.name.lower()
        if name.endswith(".zip") and "all" in name:
            return asset
    return None


def find_delta_asset(release: Release) -> Asset | None:
    """The incremental delta archive, published on most releases."""
    for asset in release.assets:
        name = asset.name.lower()
        if name.endswith(".zip") and "delta" in name:
            return asset
    return None


def download_asset(
    asset: Asset,
    max_bytes: int,
    on_progress: Callable[[int, int], None] | None = None,
    progress_every_bytes: int = 20 << 20,
) -> bytes:
    """Download an asset's bytes, optionally reporting progress.

    on_progress(downloaded_bytes, total_bytes) is called every
    progress_every_bytes of new data (total_bytes is asset.size, GitHub's
    advertised size - a hint, not authoritative).
    """
    with _client(timeout=1800.0) as client:
        with client.stream("GET", asset.download_url) as resp:
            resp.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            next_report_at = progress_every_bytes
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(
                        f"asset {asset.name!r} exceeds download size limit {max_bytes}"
                    )
                chunks.append(chunk)
                if on_progress and total >= next_report_at:
                    on_progress(total, asset.size)
                    next_report_at += progress_every_bytes
            if on_progress:
                on_progress(total, asset.size)
            return b"".join(chunks)
