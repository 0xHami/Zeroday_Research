#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"                                  # exploits/VULN-<id>/
VENV="$(cd .. && pwd)/.venv"                          # shared venv (absolute)
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -r ../requirements.txt     # idempotent; inside .venv -> hook-allowed
exec "$VENV/bin/python" automation.py "$@"
