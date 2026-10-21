#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
VENV="$(cd .. && pwd)/.venv"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -r ../requirements.txt
exec "$VENV/bin/python" automation.py "$@"
