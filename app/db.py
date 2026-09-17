# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

import os
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

DB_PATH = Path(os.environ.get("CVELISTV5_DB_PATH", "cves.db"))
_engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


@event.listens_for(_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _connection_record):
    # WAL mode lets the fetch job write in a background thread without
    # blocking concurrent API reads (search/stats) in the request threads.
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


def get_engine():
    return _engine


def init_db() -> None:
    # Import models so their tables are registered on SQLModel.metadata before create_all.
    from app import models  # noqa: F401

    SQLModel.metadata.create_all(_engine)


@contextmanager
def get_session():
    """For use outside FastAPI (CLI, tests): `with get_session() as session: ...`"""
    with Session(_engine) as session:
        yield session


def get_session_dep():
    """FastAPI dependency: `session: Session = Depends(get_session_dep)`"""
    with Session(_engine) as session:
        yield session
