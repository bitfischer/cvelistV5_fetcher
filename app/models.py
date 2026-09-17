# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

from datetime import datetime, timezone

from sqlmodel import JSON, Column, Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CVEVendorLink(SQLModel, table=True):
    __tablename__ = "cve_vendor_links"

    cve_id: int = Field(foreign_key="cves.id", primary_key=True)
    vendor_id: int = Field(foreign_key="vendors.id", primary_key=True)


class CVEProductLink(SQLModel, table=True):
    __tablename__ = "cve_product_links"

    cve_id: int = Field(foreign_key="cves.id", primary_key=True)
    product_id: int = Field(foreign_key="products.id", primary_key=True)


class Vendor(SQLModel, table=True):
    __tablename__ = "vendors"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)


class Product(SQLModel, table=True):
    __tablename__ = "products"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)


class CVE(SQLModel, table=True):
    __tablename__ = "cves"

    id: int | None = Field(default=None, primary_key=True)
    cve_id: str = Field(index=True, unique=True, max_length=32)
    title: str = Field(default="", max_length=500)
    description: str = Field(default="")
    # CRITICAL, HIGH, MEDIUM, LOW, NONE
    severity: str = Field(default="", index=True, max_length=16)
    cvss_score: float = Field(default=0.0)
    cvss_vector: str = Field(default="", max_length=128)
    published_date: datetime | None = Field(default=None)
    modified_date: datetime | None = Field(default=None, index=True)
    cpes: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    references: list[dict] = Field(default_factory=list, sa_column=Column(JSON))
    advisory_url: str = Field(default="", max_length=2048)
    source: str = Field(default="cveorg", index=True, max_length=50)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class FetchState(SQLModel, table=True):
    __tablename__ = "fetch_state"

    id: int | None = Field(default=1, primary_key=True)
    last_release: str = Field(default="")
    last_run_at: datetime | None = Field(default=None)
