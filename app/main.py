# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api import cves, fetch, lookups, stats
from app.db import init_db

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="cvelistV5_fetcher")


@app.on_event("startup")
def _on_startup() -> None:
    init_db()


app.include_router(cves.router)
app.include_router(stats.router)
app.include_router(lookups.router)
app.include_router(fetch.router)


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/index.html")


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="static")
