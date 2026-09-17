# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

from fastapi import APIRouter, HTTPException

from app import fetch_job

router = APIRouter(prefix="/api", tags=["fetch"])


@router.post("/fetch")
def trigger_fetch() -> dict:
    started = fetch_job.start_fetch()
    if not started:
        raise HTTPException(status_code=409, detail="A fetch is already running")
    return fetch_job.get_status()


@router.get("/fetch/status")
def fetch_status() -> dict:
    return fetch_job.get_status()
