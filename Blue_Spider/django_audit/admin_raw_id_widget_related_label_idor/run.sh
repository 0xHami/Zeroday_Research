#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"                                   # exploits/VULN-007/
VENV="$(cd .. && pwd)/.venv"                           # absolute path to shared venv
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -r ../requirements.txt      # idempotent; ".venv" path = hook-allowed
exec "$VENV/bin/python" automation.py "$@"
