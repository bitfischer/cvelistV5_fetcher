#!/bin/sh
# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT
#
# Runs as root just long enough to make sure the mounted data directory is
# writable by the unprivileged "appuser" (the named volume may already exist
# from a run under an older, root-only image), then drops privileges before
# exec'ing the real command. Works for both the "app" service (uvicorn) and
# the "fetch" one-off service (cvelistv5-fetch), since it execs whatever
# command was passed in rather than hardcoding one.
set -e

DB_DIR=$(dirname "${CVELISTV5_DB_PATH:-/data/cves.db}")
mkdir -p "$DB_DIR"
chown -R appuser:appuser "$DB_DIR"

exec python3 -c '
import os, pwd, sys
pw = pwd.getpwnam("appuser")
os.setgid(pw.pw_gid)
os.setgroups([])
os.setuid(pw.pw_uid)
os.execvp(sys.argv[1], sys.argv[1:])
' "$@"
