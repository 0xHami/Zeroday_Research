#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"                                   # exploits/VULN-002/
VENV="$(cd .. && pwd)/.venv"                           # absolute path to the shared venv
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -r ../requirements.txt
exec "$VENV/bin/python" automation.py "$@"
