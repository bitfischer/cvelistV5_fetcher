# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

from datetime import datetime

from pydantic import BaseModel


class CVEListItem(BaseModel):
    cve_id: str
    title: str
    severity: str
    cvss_score: float
    published_date: datetime | None
    vendors: list[str]
    products: list[str]


class CVEListResponse(BaseModel):
    items: list[CVEListItem]
    total: int
    page: int
    page_size: int


class CVEDetail(BaseModel):
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    published_date: datetime | None
    modified_date: datetime | None
    vendors: list[str]
    products: list[str]
    cpes: list[str]
    references: list[dict]
    advisory_url: str
    source: str


class VendorCount(BaseModel):
    name: str
    count: int


class TrendPoint(BaseModel):
    month: str
    count: int


class StatsResponse(BaseModel):
    total: int
    by_severity: dict[str, int]
    top_vendors: list[VendorCount]
    top_products: list[VendorCount]
    ingestion_trend: list[TrendPoint]
