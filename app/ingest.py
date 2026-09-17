# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

"""Zip handling and DB upsert glue: downloaded archive bytes -> persisted CVEs."""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import delete
from sqlmodel import Session, select

from app.guard import (
    MAX_NESTED_ZIP_BYTES,
    MAX_ZIP_DEPTH,
    MAX_ZIP_ENTRY_BYTES,
    GuardError,
    ZipBudget,
)
from app.models import CVE, CVEProductLink, CVEVendorLink, Product, Vendor
from app.parser import ParsedCVE, parse_cve_record


@dataclass
class ImportSummary:
    files_seen: int = 0
    imported: int = 0
    skipped: int = 0


def _iter_cve_json_entries(archive_bytes: bytes, budget: ZipBudget | None = None, depth: int = 0):
    if budget is None:
        budget = ZipBudget()
    if depth >= MAX_ZIP_DEPTH:
        raise GuardError(f"zip nesting exceeds max depth {MAX_ZIP_DEPTH}")

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            basename = info.filename.rsplit("/", 1)[-1]

            if basename.lower().endswith(".zip"):
                if info.file_size > MAX_NESTED_ZIP_BYTES:
                    raise GuardError(
                        f"nested zip {basename!r} is {info.file_size} bytes, "
                        f"exceeds limit {MAX_NESTED_ZIP_BYTES}"
                    )
                budget.charge(info.file_size)
                yield from _iter_cve_json_entries(zf.read(info), budget, depth + 1)
                continue

            if basename.startswith("CVE-") and basename.endswith(".json"):
                if info.file_size > MAX_ZIP_ENTRY_BYTES:
                    raise GuardError(
                        f"zip entry {basename!r} is {info.file_size} bytes, "
                        f"exceeds limit {MAX_ZIP_ENTRY_BYTES}"
                    )
                budget.charge(info.file_size)
                yield basename, zf.read(info)


class _LookupCache:
    """Caches Vendor/Product name -> id for the duration of one import run.

    Avoids one SELECT per vendor/product per CVE, which matters a lot across
    a 200k+ record archive where the same vendor names recur constantly.
    """

    def __init__(self, session: Session):
        self.session = session
        self.vendor_ids: dict[str, int] = {
            v.name: v.id for v in session.exec(select(Vendor)).all()
        }
        self.product_ids: dict[str, int] = {
            p.name: p.id for p in session.exec(select(Product)).all()
        }

    def vendor_id(self, name: str) -> int:
        vid = self.vendor_ids.get(name)
        if vid is None:
            vendor = Vendor(name=name)
            self.session.add(vendor)
            self.session.flush()
            vid = vendor.id
            self.vendor_ids[name] = vid
        return vid

    def product_id(self, name: str) -> int:
        pid = self.product_ids.get(name)
        if pid is None:
            product = Product(name=name)
            self.session.add(product)
            self.session.flush()
            pid = product.id
            self.product_ids[name] = pid
        return pid


def upsert_parsed_cve(session: Session, parsed: ParsedCVE, cache: _LookupCache) -> None:
    cve = session.exec(select(CVE).where(CVE.cve_id == parsed.cve_id)).first()
    is_new = cve is None
    if cve is None:
        cve = CVE(cve_id=parsed.cve_id)

    cve.title = parsed.title
    cve.description = parsed.description
    cve.severity = parsed.severity
    cve.cvss_score = parsed.cvss_score
    cve.cvss_vector = parsed.cvss_vector
    cve.published_date = parsed.published_date
    cve.modified_date = parsed.modified_date
    cve.cpes = parsed.cpes
    cve.references = parsed.references
    cve.advisory_url = parsed.advisory_url
    cve.source = parsed.source
    cve.updated_at = datetime.now(timezone.utc)

    session.add(cve)
    session.flush()  # ensure cve.id is populated

    if not is_new:
        session.execute(delete(CVEVendorLink).where(CVEVendorLink.cve_id == cve.id))
        session.execute(delete(CVEProductLink).where(CVEProductLink.cve_id == cve.id))

    for vendor_name in parsed.vendors:
        vendor_id = cache.vendor_id(vendor_name)
        session.add(CVEVendorLink(cve_id=cve.id, vendor_id=vendor_id))
    for product_name in parsed.products:
        product_id = cache.product_id(product_name)
        session.add(CVEProductLink(cve_id=cve.id, product_id=product_id))


def import_archive(
    session: Session,
    archive_bytes: bytes,
    commit_every: int = 2000,
    on_progress: Callable[[ImportSummary], None] | None = None,
) -> ImportSummary:
    summary = ImportSummary()
    cache = _LookupCache(session)
    for _name, raw in _iter_cve_json_entries(archive_bytes):
        summary.files_seen += 1
        try:
            parsed = parse_cve_record(raw)
        except (ValueError, KeyError, TypeError):
            summary.skipped += 1
            continue
        if parsed is None:
            summary.skipped += 1
            continue
        upsert_parsed_cve(session, parsed, cache)
        summary.imported += 1
        if summary.imported % commit_every == 0:
            session.commit()
            if on_progress:
                on_progress(summary)
    session.commit()
    if on_progress:
        on_progress(summary)
    return summary
