# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

"""Standalone entrypoint used to build the packaged executable (PyInstaller).

Runs the same FastAPI app as `make run`, but as a single self-contained
binary with no Python install required.
"""

import os
import sys

import uvicorn

from app.main import app


def main() -> None:
    host = os.environ.get("CVELISTV5_HOST", "127.0.0.1")
    port = int(os.environ.get("CVELISTV5_PORT", "8420"))
    print(f"cvelistV5-fetcher: starting dashboard on http://{host}:{port}", file=sys.stderr)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
