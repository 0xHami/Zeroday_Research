"""Run a Playwright (Python) script inside the official Playwright container.

Host chromium can't launch here (missing libs, non-root), so real-browser checks
(stored/DOM XSS firing, click-to-execute) run INSIDE
``mcr.microsoft.com/playwright/python:latest`` with ``--network host`` so
``http://localhost:<port>`` reaches the running lab. The image bundles the v1.46.0
browsers but not the pip package, so we ``pip install playwright==1.46.0`` (pinned to
match the bundled browser revision) at runtime — inside the container, which the host
safety policy allows.

The caller's script lives under ``claude_audit/filament`` (mounted at ``/work``) and
is referenced by its path relative to that dir.
"""

from __future__ import annotations

import subprocess

WORK_HOST = "/opt/cvehunter/claude_audit/filament"
IMAGE = "mcr.microsoft.com/playwright/python:latest"
PW_PIN = "playwright==1.46.0"   # must match the browsers bundled in the image


def run_browser_script(script_rel_path: str, env: dict | None = None,
                       timeout: int = 300) -> subprocess.CompletedProcess:
    """Execute ``/work/<script_rel_path>`` in the Playwright container.

    ``env`` entries are passed through as ``-e KEY=VALUE`` so the script can read
    BASE_URL, credentials, a sentinel suffix, etc. Returns the CompletedProcess
    (stdout carries the script's markers / verdict).
    """
    cmd = ["docker", "run", "--rm", "--network", "host", "--ipc=host", "--memory=2g",
           "-v", f"{WORK_HOST}:/work", "-w", "/work", "-e", "HOME=/tmp"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [IMAGE, "sh", "-c",
            f"pip install -q '{PW_PIN}' >/dev/null 2>&1 && python /work/{script_rel_path}"]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
