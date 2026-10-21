"""Shared, report-grade console output for the Filament exploits.

Status tags are coloured for a terminal but plain when captured to a file
(gate on ``stdout.isatty()`` and honour ``NO_COLOR``) so ``run.log`` has no
escape codes. Every exploit routes its narration through :func:`log`, opens with
:func:`banner`, and ends with :func:`verdict`.
"""

from __future__ import annotations

import os
import sys

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag: str, msg: str) -> None:
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id: str, title: str, base_url: str, code_path: str) -> None:
    line = "=" * 72
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(line, flush=True)
    log("INFO", f"target: {base_url}")
    log("INFO", f"exercising: {code_path}")


def verdict(vuln_id: str, status: str, one_liner: str) -> None:
    """Print the final one-line verdict, coloured by status."""
    colour = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33",
              "INTENDED": "33"}.get(status, "0")
    text = f"==> {vuln_id}: {status} — {one_liner}"
    if _USE_COLOR:
        print(f"\033[1;{colour}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)
