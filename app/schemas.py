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


class CVSSBucket(BaseModel):
    range: str
    count: int


class RecentActivityItem(BaseModel):
    cve_id: str
    title: str
    severity: str
    modified_date: datetime | None


class StatsResponse(BaseModel):
    total: int
    by_severity: dict[str, int]
    top_vendors: list[VendorCount]
    top_products: list[VendorCount]
    ingestion_trend: list[TrendPoint]
    avg_cvss: float | None
    cvss_distribution: list[CVSSBucket]
    new_last_7d: int
    new_last_30d: int
    distinct_vendor_count: int
    distinct_product_count: int
    modified_trend: list[TrendPoint]
    last_fetch_at: datetime | None
    recent_modified: list[RecentActivityItem]
