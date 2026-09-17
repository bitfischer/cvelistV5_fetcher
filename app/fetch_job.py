# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

"""Runs app.fetch.run_fetch in a background thread so the trigger-fetch API
endpoint can return immediately instead of blocking on a multi-minute sync.

State is process-local (in memory). That's fine for this single-process app:
a second worker process would just track its own fetch independently, and a
concurrent trigger is rejected while one is already running.
"""

from __future__ import annotations

import sys
import threading
from datetime import datetime, timezone
from typing import Any

from app.db import get_session, init_db
from app.fetch import run_fetch

_lock = threading.Lock()
_state: dict[str, Any] = {
    "status": "idle",  # idle | running | done | error
    "started_at": None,
    "finished_at": None,
    "progress": None,
    "result": None,
    "error": None,
}


def get_status() -> dict[str, Any]:
    with _lock:
        return dict(_state)


def start_fetch() -> bool:
    """Start a fetch in a background thread. Returns False if one is already running."""
    with _lock:
        if _state["status"] == "running":
            return False
        _state.update(
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
            progress="Starting...",
            result=None,
            error=None,
        )

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return True


def _on_progress(message: str) -> None:
    print(message, file=sys.stderr)  # also visible via `docker compose logs`
    with _lock:
        _state["progress"] = message


def _run() -> None:
    try:
        init_db()
        with get_session() as session:
            result = run_fetch(session, on_progress=_on_progress)
        with _lock:
            _state["status"] = "done"
            _state["result"] = result
    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        with _lock:
            _state["status"] = "error"
            _state["error"] = str(exc)
    finally:
        with _lock:
            _state["finished_at"] = datetime.now(timezone.utc).isoformat()
