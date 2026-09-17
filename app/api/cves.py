# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, func, or_, select

from app.db import get_session_dep
from app.models import CVE, CVEProductLink, CVEVendorLink, Product, Vendor
from app.schemas import CVEDetail, CVEListItem, CVEListResponse

router = APIRouter(prefix="/api", tags=["cves"])


def _base_filtered_id_query(
    q: str | None, vendor: str | None, product: str | None, severity: str | None
):
    query = select(CVE.id).distinct()
    if vendor:
        query = query.join(CVEVendorLink, CVEVendorLink.cve_id == CVE.id).join(
            Vendor, Vendor.id == CVEVendorLink.vendor_id
        )
        query = query.where(Vendor.name.ilike(f"%{vendor}%"))
    if product:
        query = query.join(CVEProductLink, CVEProductLink.cve_id == CVE.id).join(
            Product, Product.id == CVEProductLink.product_id
        )
        query = query.where(Product.name.ilike(f"%{product}%"))
    if q:
        like = f"%{q}%"
        query = query.where(or_(CVE.cve_id.ilike(like), CVE.title.ilike(like), CVE.description.ilike(like)))
    if severity:
        query = query.where(CVE.severity == severity.upper())
    return query


def _vendors_products_for(session: Session, cve_ids: list[int]) -> tuple[dict[int, list[str]], dict[int, list[str]]]:
    if not cve_ids:
        return {}, {}
    vendor_rows = session.exec(
        select(CVEVendorLink.cve_id, Vendor.name)
        .join(Vendor, Vendor.id == CVEVendorLink.vendor_id)
        .where(CVEVendorLink.cve_id.in_(cve_ids))
    ).all()
    product_rows = session.exec(
        select(CVEProductLink.cve_id, Product.name)
        .join(Product, Product.id == CVEProductLink.product_id)
        .where(CVEProductLink.cve_id.in_(cve_ids))
    ).all()
    vendors_by_cve: dict[int, list[str]] = {}
    for cve_id, name in vendor_rows:
        vendors_by_cve.setdefault(cve_id, []).append(name)
    products_by_cve: dict[int, list[str]] = {}
    for cve_id, name in product_rows:
        products_by_cve.setdefault(cve_id, []).append(name)
    return vendors_by_cve, products_by_cve


@router.get("/cves", response_model=CVEListResponse)
def list_cves(
    q: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    severity: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    session: Session = Depends(get_session_dep),
) -> CVEListResponse:
    id_query = _base_filtered_id_query(q, vendor, product, severity)
    total = session.exec(select(func.count()).select_from(id_query.subquery())).one()

    # Fetch the page of CVE rows directly, ordered by published_date desc.
    page_query = (
        select(CVE)
        .where(CVE.id.in_(id_query))
        .order_by(CVE.published_date.desc().nullslast(), CVE.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    cves = session.exec(page_query).all()

    vendors_by_cve, products_by_cve = _vendors_products_for(session, [c.id for c in cves])

    items = [
        CVEListItem(
            cve_id=c.cve_id,
            title=c.title,
            severity=c.severity,
            cvss_score=c.cvss_score,
            published_date=c.published_date,
            vendors=sorted(vendors_by_cve.get(c.id, [])),
            products=sorted(products_by_cve.get(c.id, [])),
        )
        for c in cves
    ]
    return CVEListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/cves/{cve_id}", response_model=CVEDetail)
def get_cve(cve_id: str, session: Session = Depends(get_session_dep)) -> CVEDetail:
    cve = session.exec(select(CVE).where(CVE.cve_id == cve_id.upper())).first()
    if cve is None:
        raise HTTPException(status_code=404, detail="CVE not found")

    vendors_by_cve, products_by_cve = _vendors_products_for(session, [cve.id])

    return CVEDetail(
        cve_id=cve.cve_id,
        title=cve.title,
        description=cve.description,
        severity=cve.severity,
        cvss_score=cve.cvss_score,
        cvss_vector=cve.cvss_vector,
        published_date=cve.published_date,
        modified_date=cve.modified_date,
        vendors=sorted(vendors_by_cve.get(cve.id, [])),
        products=sorted(products_by_cve.get(cve.id, [])),
        cpes=cve.cpes,
        references=cve.references,
        advisory_url=cve.advisory_url,
        source=cve.source,
    )
