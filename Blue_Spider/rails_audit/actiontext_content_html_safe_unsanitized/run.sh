#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"                                   # exploits/<VULN-ID>/
PARENT="$(cd .. && pwd)"                               # exploits/
[ -d "$PARENT/.venv" ] || python3 -m venv "$PARENT/.venv"   # create the shared venv once
"$PARENT/.venv/bin/pip" install -q -r "$PARENT/requirements.txt"   # idempotent; path contains .venv -> hook-allowed
exec env PYTHONPATH="$PARENT" "$PARENT/.venv/bin/python" automation.py "$@"
