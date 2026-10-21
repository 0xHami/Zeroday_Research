#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"                                  # exploits/<VULN-ID>/
VENV="$(cd .. && pwd)/.venv"                          # absolute path → clean sys.prefix
[ -d "$VENV" ] || python3 -m venv "$VENV"             # shared venv (created once)
"$VENV/bin/pip" install -q -r ../requirements.txt     # idempotent; .venv/bin/pip → hook-allowed
exec "$VENV/bin/python" automation.py "$@"
