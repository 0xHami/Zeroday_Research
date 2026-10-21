#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[ -d ../.venv ] || python3 -m venv ../.venv
../.venv/bin/pip install -q -r ../requirements.txt
exec "$(cd .. && pwd)/.venv/bin/python" automation.py "$@"
