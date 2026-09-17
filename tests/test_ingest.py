# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

import io
import zipfile
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine, select

from app.ingest import import_archive
from app.models import CVE, Vendor

FIXTURES = Path(__file__).parent / "fixtures"


def _make_archive(*fixture_names: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in fixture_names:
            data = (FIXTURES / name).read_bytes()
            cve_id = name  # arbitrary, parser reads the real id from the JSON body
            zf.writestr(f"CVE-placeholder-{cve_id}.json", data)
    return buf.getvalue()


def _make_nested_archive(*fixture_names: str) -> bytes:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        for name in fixture_names:
            data = (FIXTURES / name).read_bytes()
            zf.writestr(f"cves/CVE-inner-{name}.json", data)
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("cves.zip", inner.getvalue())
    return outer.getvalue()


def _fresh_session() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return Session(engine)


def test_import_archive_flat_layout():
    archive = _make_archive("published_basic.json", "rejected.json")
    with _fresh_session() as session:
        summary = import_archive(session, archive)
        assert summary.files_seen == 2
        assert summary.imported == 1
        assert summary.skipped == 1
        assert session.get(CVE, 1).cve_id == "CVE-2024-12345"


def test_import_archive_nested_zip_layout():
    archive = _make_nested_archive("published_basic.json", "cvss_version_preference.json")
    with _fresh_session() as session:
        summary = import_archive(session, archive)
        assert summary.imported == 2
        cve_ids = {c.cve_id for c in session.exec(select(CVE)).all()}
        assert cve_ids == {"CVE-2024-12345", "CVE-2024-55555"}


def test_reimport_updates_existing_row_and_replaces_links():
    archive = _make_archive("published_basic.json")
    with _fresh_session() as session:
        import_archive(session, archive)
        import_archive(session, archive)  # re-run, simulating a later delta
        cves = session.exec(select(CVE)).all()
        assert len(cves) == 1  # upsert, not duplicate
        vendors = session.exec(select(Vendor)).all()
        assert len(vendors) == 1  # no duplicate vendor rows either
