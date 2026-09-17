# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import Integer, case, cast
from sqlmodel import Session, func, select

from app.db import get_session_dep
from app.models import CVE, CVEProductLink, CVEVendorLink, FetchState, Product, Vendor
from app.schemas import (
    CVSSBucket,
    RecentActivityItem,
    StatsResponse,
    TrendPoint,
    VendorCount,
)

router = APIRouter(prefix="/api", tags=["stats"])

TOP_N = 10
RECENT_N = 8


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

    modified_trend_rows = session.exec(
        select(
            func.strftime("%Y-%m", CVE.modified_date).label("month"),
            func.count(),
        )
        .where(CVE.modified_date.is_not(None))
        .group_by("month")
        .order_by("month")
    ).all()
    modified_trend = [TrendPoint(month=month, count=count) for month, count in modified_trend_rows if month]

    # cvss_score defaults to 0.0 for records the parser couldn't score — that's a
    # "no data" sentinel, not a real CVSS score of zero, so it's excluded from
    # both the average and the distribution below.
    avg_cvss_raw = session.exec(
        select(func.avg(CVE.cvss_score)).where(CVE.cvss_score > 0)
    ).one()
    avg_cvss = float(avg_cvss_raw) if avg_cvss_raw is not None else None

    bucket_expr = case((CVE.cvss_score >= 10, 9), else_=cast(CVE.cvss_score, Integer))
    bucket_rows = dict(
        session.exec(
            select(bucket_expr.label("bucket"), func.count())
            .where(CVE.cvss_score > 0)
            .group_by("bucket")
        ).all()
    )
    cvss_distribution = [
        CVSSBucket(range=f"{i}-{i + 1}", count=bucket_rows.get(i, 0)) for i in range(10)
    ]

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    new_last_7d = session.exec(
        select(func.count()).select_from(CVE).where(CVE.published_date >= now - timedelta(days=7))
    ).one()
    new_last_30d = session.exec(
        select(func.count()).select_from(CVE).where(CVE.published_date >= now - timedelta(days=30))
    ).one()

    distinct_vendor_count = session.exec(select(func.count()).select_from(Vendor)).one()
    distinct_product_count = session.exec(select(func.count()).select_from(Product)).one()

    fetch_state = session.get(FetchState, 1)
    last_fetch_at = fetch_state.last_run_at if fetch_state else None

    recent_rows = session.exec(
        select(CVE.cve_id, CVE.title, CVE.severity, CVE.modified_date)
        .where(CVE.modified_date.is_not(None))
        .order_by(CVE.modified_date.desc())
        .limit(RECENT_N)
    ).all()
    recent_modified = [
        RecentActivityItem(cve_id=cve_id, title=title, severity=severity, modified_date=modified_date)
        for cve_id, title, severity, modified_date in recent_rows
    ]

    return StatsResponse(
        total=total,
        by_severity=by_severity,
        top_vendors=top_vendors,
        top_products=top_products,
        ingestion_trend=ingestion_trend,
        avg_cvss=avg_cvss,
        cvss_distribution=cvss_distribution,
        new_last_7d=new_last_7d,
        new_last_30d=new_last_30d,
        distinct_vendor_count=distinct_vendor_count,
        distinct_product_count=distinct_product_count,
        modified_trend=modified_trend,
        last_fetch_at=last_fetch_at,
        recent_modified=recent_modified,
    )
