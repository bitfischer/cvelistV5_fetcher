# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

from fastapi import APIRouter, Depends
from sqlmodel import Session, func, select

from app.db import get_session_dep
from app.models import CVE, CVEProductLink, CVEVendorLink, Product, Vendor
from app.schemas import StatsResponse, TrendPoint, VendorCount

router = APIRouter(prefix="/api", tags=["stats"])

TOP_N = 10


@router.get("/stats", response_model=StatsResponse)
def get_stats(session: Session = Depends(get_session_dep)) -> StatsResponse:
    total = session.exec(select(func.count()).select_from(CVE)).one()

    severity_rows = session.exec(
        select(CVE.severity, func.count()).group_by(CVE.severity)
    ).all()
    by_severity = {severity or "UNKNOWN": count for severity, count in severity_rows}

    top_vendor_rows = session.exec(
        select(Vendor.name, func.count(CVEVendorLink.cve_id).label("n"))
        .join(CVEVendorLink, CVEVendorLink.vendor_id == Vendor.id)
        .group_by(Vendor.name)
        .order_by(func.count(CVEVendorLink.cve_id).desc())
        .limit(TOP_N)
    ).all()
    top_vendors = [VendorCount(name=name, count=count) for name, count in top_vendor_rows]

    top_product_rows = session.exec(
        select(Product.name, func.count(CVEProductLink.cve_id).label("n"))
        .join(CVEProductLink, CVEProductLink.product_id == Product.id)
        .group_by(Product.name)
        .order_by(func.count(CVEProductLink.cve_id).desc())
        .limit(TOP_N)
    ).all()
    top_products = [VendorCount(name=name, count=count) for name, count in top_product_rows]

    trend_rows = session.exec(
        select(
            func.strftime("%Y-%m", CVE.published_date).label("month"),
            func.count(),
        )
        .where(CVE.published_date.is_not(None))
        .group_by("month")
        .order_by("month")
    ).all()
    ingestion_trend = [TrendPoint(month=month, count=count) for month, count in trend_rows if month]

    return StatsResponse(
        total=total,
        by_severity=by_severity,
        top_vendors=top_vendors,
        top_products=top_products,
        ingestion_trend=ingestion_trend,
    )
