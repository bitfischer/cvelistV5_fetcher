# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

"""CLI entrypoint: sync CVE records from CVEProject/cvelistV5 GitHub releases.

First run: downloads the newest release with a full archive asset and
imports everything. Subsequent runs: downloads only delta archives from
releases newer than the stored watermark, advancing it after each one.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from typing import Callable

from sqlmodel import Session

from app import github_client
from app.db import get_session, init_db
from app.guard import MAX_ARCHIVE_DOWNLOAD_BYTES, MAX_DELTA_DOWNLOAD_BYTES
from app.ingest import ImportSummary, import_archive
from app.models import FetchState

ProgressFn = Callable[[str], None]


def _default_progress(message: str) -> None:
    print(message, file=sys.stderr)


def _get_or_create_state(session: Session) -> FetchState:
    state = session.get(FetchState, 1)
    if state is None:
        state = FetchState(id=1, last_release="")
        session.add(state)
        session.commit()
        session.refresh(state)
    return state


def _format_size(num_bytes: int) -> str:
    if num_bytes < 1 << 20:
        return f"{num_bytes / 1024:.0f} KiB"
    return f"{num_bytes / (1 << 20):.0f} MiB"


def _download_progress(notify: ProgressFn, label: str) -> Callable[[int, int], None]:
    def _report(downloaded: int, total: int) -> None:
        if total:
            pct = downloaded / total * 100
            notify(f"  downloading {label}: {_format_size(downloaded)} / {_format_size(total)} ({pct:.0f}%)")
        else:
            notify(f"  downloading {label}: {_format_size(downloaded)}")

    return _report


def _import_progress(notify: ProgressFn, label: str) -> Callable[[ImportSummary], None]:
    def _report(summary: ImportSummary) -> None:
        notify(
            f"  importing {label}: {summary.imported} CVE(s) imported "
            f"({summary.skipped} skipped, {summary.files_seen} files processed so far)"
        )

    return _report


def run_fetch(session: Session, on_progress: ProgressFn | None = None) -> dict:
    notify = on_progress or _default_progress

    state = _get_or_create_state(session)
    notify("Listing releases from CVEProject/cvelistV5...")
    releases = github_client.list_releases()
    if not releases:
        raise RuntimeError("no releases found for CVEProject/cvelistV5")

    result = {"releases_processed": 0, "files_imported": 0, "watermark": state.last_release}

    if not state.last_release:
        release = next(
            (r for r in reversed(releases) if github_client.find_archive_asset(r)), None
        )
        if release is None:
            raise RuntimeError("no release with a full archive asset was found")
        asset = github_client.find_archive_asset(release)
        notify(
            f"First run: downloading full archive from release {release.tag_name} "
            f"({asset.name}, ~{_format_size(asset.size)})..."
        )
        archive_bytes = github_client.download_asset(
            asset, MAX_ARCHIVE_DOWNLOAD_BYTES, on_progress=_download_progress(notify, asset.name)
        )
        notify("  download complete, extracting and importing CVEs...")
        summary = import_archive(
            session, archive_bytes, on_progress=_import_progress(notify, release.tag_name)
        )
        notify(f"  imported {summary.imported} CVEs ({summary.skipped} skipped, "
               f"{summary.files_seen} files seen)")

        state.last_release = release.tag_name
        state.last_run_at = datetime.now(timezone.utc)
        session.add(state)
        session.commit()

        result["releases_processed"] = 1
        result["files_imported"] = summary.imported
        result["watermark"] = state.last_release
        notify(f"Done. Watermark now {state.last_release}.")
        return result

    newer = [r for r in releases if r.tag_name > state.last_release]
    if not newer:
        notify("No new releases since last fetch.")
        return result

    notify(f"Found {len(newer)} new release(s) to process.")
    for idx, release in enumerate(newer, start=1):
        asset = github_client.find_delta_asset(release)
        if asset is None:
            notify(f"Release {idx}/{len(newer)} ({release.tag_name}) has no delta asset, skipping.")
            state.last_release = release.tag_name
            session.add(state)
            session.commit()
            result["releases_processed"] += 1
            continue

        notify(f"Release {idx}/{len(newer)}: downloading delta from {release.tag_name} ({asset.name})...")
        archive_bytes = github_client.download_asset(
            asset, MAX_DELTA_DOWNLOAD_BYTES, on_progress=_download_progress(notify, asset.name)
        )
        summary = import_archive(
            session, archive_bytes, on_progress=_import_progress(notify, release.tag_name)
        )
        notify(f"  imported {summary.imported} CVEs ({summary.skipped} skipped, "
               f"{summary.files_seen} files seen)")

        # Persist the watermark after each release so a mid-run crash doesn't
        # reprocess releases already completed.
        state.last_release = release.tag_name
        state.last_run_at = datetime.now(timezone.utc)
        session.add(state)
        session.commit()

        result["releases_processed"] += 1
        result["files_imported"] += summary.imported

    result["watermark"] = state.last_release
    notify(f"Done. Watermark now {state.last_release}.")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()

    init_db()
    with get_session() as session:
        result = run_fetch(session)

    print(
        f"Done. {result['releases_processed']} release(s) processed, "
        f"{result['files_imported']} CVE(s) imported/updated, "
        f"watermark now {result['watermark'] or '(none)'}.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
