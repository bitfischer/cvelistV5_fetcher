# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

"""Size limits guarding the fetch/ingest path against oversized or malicious payloads.

We pull from a single trusted GitHub source, so this is a sanity net (truncated
downloads, unexpectedly large releases) rather than a defense against an
adversarial feed.

cvelistV5 release archives are a zip containing a single nested zip
(cves.zip) full of CVE-*.json files, so the budget below is charged across
both levels rather than per top-level entry.
"""

MAX_RELEASES_RESPONSE_BYTES = 8 << 20  # 8 MiB - GitHub releases listing JSON
MAX_ARCHIVE_DOWNLOAD_BYTES = 1 << 30  # 1 GiB - full cvelistV5 archive
MAX_DELTA_DOWNLOAD_BYTES = 256 << 20  # 256 MiB - incremental delta archive
MAX_ZIP_DEPTH = 2  # outer release zip -> nested cves.zip
MAX_ZIP_ENTRIES = 1_000_000
MAX_ZIP_ENTRY_BYTES = 8 << 20  # 8 MiB - a single CVE JSON file
MAX_NESTED_ZIP_BYTES = 1 << 30  # 1 GiB - the nested cves.zip container itself
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 8 << 30  # 8 GiB across all entries, all levels


class GuardError(Exception):
    """Raised when a download or archive exceeds a configured safety limit."""


class ZipBudget:
    """Tracks entry count and cumulative uncompressed bytes across nested zips."""

    def __init__(self) -> None:
        self.entries = 0
        self.total_bytes = 0

    def charge(self, size: int) -> None:
        self.entries += 1
        if self.entries > MAX_ZIP_ENTRIES:
            raise GuardError(f"zip has more than {MAX_ZIP_ENTRIES} entries")
        self.total_bytes += size
        if self.total_bytes > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
            raise GuardError(
                f"zip total uncompressed size exceeds limit {MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES}"
            )
