# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from app.db import get_session_dep
from app.models import Product, Vendor

router = APIRouter(prefix="/api", tags=["lookups"])


@router.get("/vendors", response_model=list[str])
def list_vendors(
    prefix: str = "",
    limit: int = Query(default=10, ge=1, le=50),
    session: Session = Depends(get_session_dep),
) -> list[str]:
    query = select(Vendor.name)
    if prefix:
        query = query.where(Vendor.name.ilike(f"{prefix}%"))
    query = query.order_by(Vendor.name).limit(limit)
    return session.exec(query).all()


@router.get("/products", response_model=list[str])
def list_products(
    prefix: str = "",
    limit: int = Query(default=10, ge=1, le=50),
    session: Session = Depends(get_session_dep),
) -> list[str]:
    query = select(Product.name)
    if prefix:
        query = query.where(Product.name.ilike(f"{prefix}%"))
    query = query.order_by(Product.name).limit(limit)
    return session.exec(query).all()
