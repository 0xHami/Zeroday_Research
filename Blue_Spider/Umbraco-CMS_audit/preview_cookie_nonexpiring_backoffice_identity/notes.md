# VULN-025 — Preview cookie mints a full, non-expiring, non-revocable backoffice identity

**Software**: Umbraco CMS
**Repository**: https://github.com/umbraco/Umbraco-CMS
**Affected version**: 18.3.0-rc (version.json; commit-pinned, no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium — CVSS 3.1 `6.8` (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N`)
**Target commit**: cee7d8981ab0fd18b4dc96449ae071edf1aaf21e
**Validated at**: 2026-09-29

## Preconditions
- Admin authenticated to the Management API (to provision the test subject).
- A throwaway **Administrators**-group user is created and given a password (so the credential-rotation test never touches the shared admin account). All names/emails/passwords carry a random suffix.
- Any existing document is reused to enter preview (`DefaultUrlProvider.GetPreviewUrlAsync` is unconditional); one is created if the tree is empty.

## Request
See `request.http`.
1. Mint (as the victim backoffice user): `GET /umbraco/management/api/v1/document/{id}/preview-url?providerAlias=umbDocumentUrlProvider` → response `Set-Cookie: UMB_PREVIEW=<token>; path=/; samesite=lax; httponly` (no `Expires`/`Max-Age`).
2. Decisive replay: `GET /` carrying **only** `UMB_PREVIEW` (brand-new session, no `UMB_UCONTEXT`, no bearer).
3. Same replay again, after the account's password was changed.

## Response
See `response.txt` / `run.log`:
- `GET /` with the **valid** `UMB_PREVIEW` (fresh session) → **2395 B**, backoffice preview toolbar injected: `<script src="/umbraco/website/preview.js">` + `<umb-website-preview … unique="694a14f8-…">`.
- `GET /` with an **invalid** `UMB_PREVIEW` → **2154 B**, no toolbar (control).
- `GET /` with **no** cookie → **2154 B**, no toolbar (control).
- `GET /` with the **same** cookie **after the victim's password was changed** → **2395 B**, toolbar **still** injected.

## Observation
Exactly matches the static finding. A standalone `UMB_PREVIEW` cookie — with no accompanying backoffice session — causes the front-end pipeline to attach the minting user's full backoffice identity (the preview toolbar renders only for that authenticated preview principal; the invalid-cookie control proves the effect is the token-verification path, not incidental). Rotating the account's password rotates its ASP.NET-Identity security stamp, which invalidates every stamp-bound token/session — yet the pre-change preview cookie keeps working, proving the preview token is bound to neither an expiry nor the security stamp. This is the non-revocable, non-expiring bearer described in the finding.

## Side effects
- Created 1 throwaway Administrators user per run (random-suffixed) and rotated its password to a random value (effectively disabling further login with a known secret). Harmless; left for inspection like the VULN-044 artifacts.
- Entered preview for the reused document (sets the server-side preview state for that node); no content mutated.

## Research & references
- **CWE-613** Insufficient Session Expiration; **CWE-522** Insufficiently Protected Credentials; **CWE-384** Session Fixation/Non-rotation.
- OWASP **Session Management Cheat Sheet** — session tokens must expire and must be invalidated on logout / credential change: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Umbraco source: `UserBasedPreviewTokenGenerator.cs:30,44-46`, `PreviewService.cs:131,141-142`, `PreviewAuthenticationMiddleware.cs:62-69`, DI override `Umbraco.Web.Common/DependencyInjection/UmbracoBuilderExtensions.cs:223`, cookie name `Constants-Web.cs:13`.

## If NEEDS_MANUAL
n/a — CONFIRMED. (Impact remains *conditional on cookie capture*: `UMB_PREVIEW` is DataProtection-encrypted + `HttpOnly`, so it is not forgeable and not JS-readable; the vulnerability is that once a value is captured it is an unrevocable, non-expiring full-identity bearer. On a real HTTPS install the cookie is additionally `SameSite=None; Secure` (`PreviewService.cs:97-103`), widening cross-site capture exposure vs. the `SameSite=Lax` fallback seen on this plain-HTTP lab.)
