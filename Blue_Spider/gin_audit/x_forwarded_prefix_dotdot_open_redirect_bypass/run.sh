#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"                                  # exploits/VULN-001/
[ -d ../.venv ] || python3 -m venv ../.venv           # create the shared venv once
../.venv/bin/pip install -q -r ../requirements.txt    # idempotent; ../.venv/bin/pip -> hook-allowed
# exec with the venv's python by ABSOLUTE path so Python 3.14 doesn't warn about a
# relative sys.prefix (keeps run.log clean); still the same shared ../.venv interpreter.
exec "$(cd .. && pwd)/.venv/bin/python" automation.py "$@"
