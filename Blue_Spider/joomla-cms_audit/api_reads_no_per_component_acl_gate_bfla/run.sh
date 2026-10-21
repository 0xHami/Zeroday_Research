#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"                                  # exploits/VULN-008/
VENV="$(cd .. && pwd)/.venv"                          # absolute path -> no sys.prefix warning
[ -d "$VENV" ] || python3 -m venv "$VENV"             # create the shared venv once
"$VENV/bin/pip" install -q -r ../requirements.txt     # idempotent; .venv/bin/pip -> hook-allowed
exec "$VENV/bin/python" automation.py "$@"
