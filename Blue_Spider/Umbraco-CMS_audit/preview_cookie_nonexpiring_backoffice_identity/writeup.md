# VULN-025 — Preview cookie mints a full, non-expiring, non-revocable backoffice identity

| | |
|---|---|
| **ID** | VULN-025 |
| **Software** | Umbraco CMS |
| **Repository** | https://github.com/umbraco/Umbraco-CMS |
| **Affected version** | 18.3.0-rc (commit-pinned; no tagged release) |
| **Commit** | `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e` |
| **Severity** | Medium — CVSS 3.1 `6.8` (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N`) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None to *replay*; the token is minted the first time any backoffice user enters preview. Exploitation is conditional on capturing the `HttpOnly`, DataProtection-encrypted `UMB_PREVIEW` cookie value (proxy/backup/shared-machine/cross-site leak). |
| **Attacker gains** | An indefinitely-valid, non-revocable bearer of the minting user's **full backoffice identity** on the front-end principal (draft/unpublished + member-protected content read; front-end authorization runs as that user), surviving the victim's logout, password change and 2FA reset. |

## Summary

Every other credential Umbraco issues to a backoffice user — the identity cookie and the OpenIddict reference tokens — is bound to that user's ASP.NET-Identity **security stamp** and is rotated whenever the user signs out or changes their password/2FA. The **preview** token is the exception. It is the DataProtection-encrypted *user GUID and nothing else* — no expiry claim, no security-stamp binding — and its verifier re-checks only whether the account is approved and not locked. When that cookie rides a front-end (non-backoffice) request, `PreviewAuthenticationMiddleware` attaches a **full backoffice `ClaimsIdentity`** to the request principal. A captured `UMB_PREVIEW` value is therefore an unrevocable, non-expiring bearer of a full backoffice identity.

Dynamically confirmed: replaying **only** a captured `UMB_PREVIEW` cookie in a brand-new session (no `UMB_UCONTEXT`, no bearer) makes the front end render the authenticated backoffice **preview toolbar**; an invalid cookie does not; and the cookie **still works after the minting account's password has been changed** — the credential rotation that invalidates every stamp-bound session leaves the preview token untouched.

## How it works (mechanism & code trace)

**The token is only the encrypted user GUID.** The registered generator embeds nothing else — no timestamp, no expiry, no stamp:

```csharp
// src/Umbraco.Web.Common/Preview/UserBasedPreviewTokenGenerator.cs:28-33
public Task<Attempt<string?>> GenerateTokenAsync(Guid userKey)
{
    var token = EncryptionHelper.Encrypt(userKey.ToString(), _dataProtectionProvider);  // :30 — GUID only
    return Task.FromResult(Attempt.Succeed(token));
}
```

**Verification checks account state only — never time or stamp:**

```csharp
// UserBasedPreviewTokenGenerator.cs:35-56
var decrypted = EncryptionHelper.Decrypt(token, _dataProtectionProvider);
if (Guid.TryParse(decrypted, out Guid key))
{
    IUser? user = await _userService.GetAsync(key);
    if (user is { IsApproved: true, IsLockedOut: false })   // :44 — no expiry, no security-stamp check
        return Attempt.Succeed<Guid?>(user.Key);            // :46
}
```

**A full backoffice identity is built from that bare GUID and injected onto the front-end principal:**

```csharp
// src/Umbraco.Core/Services/PreviewService.cs:131,141-142
Attempt<Guid?> userKeyAttempt = await _previewTokenGenerator.VerifyAsync(cookieValue);      // :131
...
ClaimsPrincipal? principal = await coreBackOfficeSignInManager.CreateUserPrincipalAsync(userKeyAttempt.Result!.Value); // :141
ClaimsIdentity? backOfficeIdentity = principal?.GetUmbracoIdentity();                        // :142  (FULL identity)
```

```csharp
// src/Umbraco.Web.Common/Middleware/PreviewAuthenticationMiddleware.cs:57-69
var isPreview = request.HasPreviewCookie() && !request.IsBackOfficeRequest();   // FE request with UMB_PREVIEW
if (isPreview) {
    Attempt<ClaimsIdentity> backOfficeIdentityAttempt = await _previewService.TryGetPreviewClaimsIdentityAsync();
    if (backOfficeIdentityAttempt.Success)
        context.User.AddIdentity(backOfficeIdentityAttempt.Result!);            // :69 — identity added to principal
}
```

**The vulnerable generator is the one that actually runs.** Core registers a no-op, but Web.Common overrides it, so any web host resolves the `UserBasedPreviewTokenGenerator`:

```csharp
// src/Umbraco.Core/DependencyInjection/UmbracoBuilder.cs:387
Services.AddUnique<IPreviewTokenGenerator, NoopPreviewTokenGenerator>();
// src/Umbraco.Web.Common/DependencyInjection/UmbracoBuilderExtensions.cs:223  (runs later in AddUmbracoCore -> wins)
builder.Services.AddUnique<IPreviewTokenGenerator, UserBasedPreviewTokenGenerator>();
```

The cookie (`Constants-Web.cs:13` → `UMB_PREVIEW`) is set `HttpOnly` and, on HTTPS, `SameSite=None; Secure` (`PreviewService.cs:97-103`); it carries **no `Expires`/`Max-Age`**. Both the generator and `PreviewService` are `[Obsolete]`-tagged for v19 removal but remain the live, DI-registered implementation.

**Contrast with a stamp-bound credential.** A backoffice identity/OpenIddict token is validated against `SecurityStamp`; `SignOutAsync` and `ChangePasswordAsync` rotate the stamp, invalidating outstanding tokens. `VerifyAsync` above performs no such check, so nothing about a logout or password change reaches the preview token — the defect is the *absence* of the expiry+stamp validation that every other credential has.

## Why it is a vulnerability (reasoning)

A backoffice identity is a privileged security principal. The invariant a session system must uphold is that such a credential (a) expires and (b) is revocable — logging out or changing a compromised account's password must terminate its access. The preview token violates both: it never expires and it is impervious to credential rotation. So a single leaked `UMB_PREVIEW` value gives an attacker persistent, unrevocable read access to the site's draft/unpublished and member-protected content as the victim user, and the front end evaluates authorization decisions as that backoffice identity. This is textbook insufficient session expiration / non-revocable bearer (CWE-613/384). The impact is rated Medium (not High) precisely because the cookie is DataProtection-encrypted + `HttpOnly` and therefore **not forgeable** — exploitation is conditional on capturing the value (AC:H), not mintable at will.

## Reproduction

From the running lab, the exploit does everything end-to-end (`cd exploits/VULN-025 && ./run.sh`):

1. **Provision (as admin):** create a throwaway *Administrators* user + password (keeps the shared admin account untouched).
2. **Mint:** as that victim, `GET /document/{id}/preview-url?providerAlias=umbDocumentUrlProvider` →
   `Set-Cookie: UMB_PREVIEW=…; path=/; samesite=lax; httponly` (no `Expires`/`Max-Age`).
3. **Decisive replay:** in a fresh session carrying **only** `UMB_PREVIEW`, `GET /` →
   ```
   2395 B — injects <script src="/umbraco/website/preview.js"> and
            <umb-website-preview path="/umbraco" url="http://localhost:29184/" unique="694a14f8-…">
   ```
   The backoffice preview toolbar renders only when the principal holds the backoffice preview identity → the standalone cookie **is** an authenticated identity.
4. **Controls:** invalid `UMB_PREVIEW` → 2154 B, no toolbar; no cookie → 2154 B, no toolbar (the effect is the verify path, not luck).
5. **Non-revocability:** admin changes the victim's password (rotates the security stamp); replay the **same** pre-change cookie → **2395 B, toolbar still injected**.

Output ends with `[OK]` / `==> VULN-025: CONFIRMED`. Full capture: `run.log`, `request.http`, `response.txt`.

## Impact

- **Confidentiality (C:H):** indefinite read of draft/unpublished and member-protected front-end content as the victim backoffice user, from a captured cookie, surviving the victim's logout/password/2FA change.
- **Integrity (I:L):** the front-end principal carries a backoffice identity; front-end authorization / protected-content decisions run as that user.
- **Persistence:** the credential cannot be revoked short of *disabling or locking* the account (the only two states `VerifyAsync` rejects) or rotating the Data-Protection key ring.
- **Attack cost:** one replayed cookie; no login, no bearer, no CSRF token.

## Suggested fix

Embed and verify an **expiry** and the user's **security stamp** in the preview token (invalidate on logout / password / 2FA change), and give the preview token its own Data-Protection purpose string. Concretely, `GenerateTokenAsync` should serialize `{userKey, securityStamp, issuedUtc}`, and `VerifyAsync` should reject the token when it is older than a bounded lifetime or when the stored stamp no longer matches `user.SecurityStamp` — the same contract every other backoffice credential already honours.

## References
- **CWE-613** Insufficient Session Expiration · **CWE-384** Session Fixation · **CWE-522** Insufficiently Protected Credentials.
- OWASP **Session Management Cheat Sheet** (expiration & invalidation on credential change): https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Related in this audit: **VULN-012** (indefinite draft read via preview) — VULN-025 is the stronger "full-identity, survives credential change" superset.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `gh api search/issues q='repo:umbraco/Umbraco-CMS UMB_PREVIEW'` — 15 results, all functional (preview badge, preview window reload, insecure-context support); none about token expiry, security stamp or revocation.
2. `gh api search/issues q='repo:umbraco/Umbraco-CMS "preview token" OR UserBasedPreviewTokenGenerator OR PreviewAuthenticationMiddleware'` — PR #23698, PR #23759, PR #23539; none security-motivated.
3. WebFetch `github.com/umbraco/Umbraco-CMS/pull/23698` ("Auth: Reuse the backoffice auth cookie to authorize preview", merged to v19/dev 2026-08-20, breaking, not backported) — removes `IPreviewTokenGenerator`/`UserBasedPreviewTokenGenerator` for architectural reasons; the description says nothing about non-expiring/non-revocable tokens.
4. WebFetch `github.com/umbraco/Umbraco-CMS/issues/23579` ("You can access /umbraco/preview?id=xyz without an active preview session") — UX gap, no security framing, no token-expiry discussion.
5. GitHub advisory DB full listing for NuGet `Umbraco.Cms` — nearest are CVE-2024-48929 (incomplete server termination on sign-out, 10.8.7) and CVE-2024-48926 (logout page before session expiration); neither concerns the preview cookie.
6. `gh api repos/umbraco/Umbraco-CMS/commits?path=src/Umbraco.Web.Common/Preview/UserBasedPreviewTokenGenerator.cs&since=2026-06-01` — only #23759 ([Obsolete] tagging); generator logic unchanged for 17.x/18.x.

**Related but distinct public references** (same class or component, not this bug):
- PR #23698 (v19 only) — replaces the mechanism but for auth-architecture reasons; 17.x/18.x LTS lines keep the vulnerable generator.
- CVE-2024-48929 / GHSA-wxw9-6pv9-c3xc — session termination on explicit sign-out (backoffice cookie), different component.
- CVE-2024-10761 / GHSA-69cg-w8vm-h229 — XSS in the preview badge, different root cause.

**Reasoning:** No advisory, issue or PR describes the `UMB_PREVIEW` token as a non-expiring, non-stamp-bound bearer of a full backoffice identity; the only upstream change (v19) is framed as refactoring and explicitly not backported, so supported 17.x/18.x remain affected. Confidence is held below 90 because the class (session expiration/revocation) is common and the vendor could consider the HttpOnly encrypted cookie an acceptable risk.
