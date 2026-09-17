# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

import time
from unittest.mock import patch

from app import fetch_job


def _reset_state():
    with fetch_job._lock:
        fetch_job._state.update(
            status="idle", started_at=None, finished_at=None, result=None, error=None
        )


def test_start_fetch_runs_in_background_and_reports_done():
    _reset_state()
    fake_result = {"releases_processed": 1, "files_imported": 5, "watermark": "tag-1"}
    with patch("app.fetch_job.init_db"), \
         patch("app.fetch_job.get_session"), \
         patch("app.fetch_job.run_fetch", return_value=fake_result):
        started = fetch_job.start_fetch()
        assert started is True

        for _ in range(50):
            if fetch_job.get_status()["status"] != "running":
                break
            time.sleep(0.02)

    status = fetch_job.get_status()
    assert status["status"] == "done"
    assert status["result"] == fake_result
    assert status["started_at"] is not None
    assert status["finished_at"] is not None


def test_start_fetch_rejects_concurrent_start():
    _reset_state()
    with fetch_job._lock:
        fetch_job._state["status"] = "running"
    try:
        assert fetch_job.start_fetch() is False
    finally:
        _reset_state()


def test_failed_fetch_reports_error():
    _reset_state()
    with patch("app.fetch_job.init_db"), \
         patch("app.fetch_job.get_session"), \
         patch("app.fetch_job.run_fetch", side_effect=RuntimeError("boom")):
        fetch_job.start_fetch()
        for _ in range(50):
            if fetch_job.get_status()["status"] != "running":
                break
            time.sleep(0.02)

    status = fetch_job.get_status()
    assert status["status"] == "error"
    assert status["error"] == "boom"
