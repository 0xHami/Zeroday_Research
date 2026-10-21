# VULN-001 — Bundled demo default-credential superuser via Host header + hardcoded ENCRYPT_KEY

**Target name:** PublicCMS
**Target URL:** https://github.com/sanluan/PublicCMS
**Software version:** V5.202608.a
**Status**: CONFIRMED
**Severity (static)**: Critical
**Target commit**: e85ab023a22b19bff5b5b0c944440ab614df467f
**Validated at**: 2026-09-19

## Preconditions
- Bundled demo data imported (`useSimple=true` — done for this target). Confirmed in DB:
  `sys_user` id=2, site_id=2, superuser=1, disabled=0, salt `0123456789`.
- `sys_domain` maps `site2.dev.publiccms.com` → site 2 (confirmed in DB).
- No credentials required from the attacker; only an attacker-chosen `Host` header.

## Request
See `request.http`. Two requests: (1) `POST /admin/login` with `Host: site2.dev.publiccms.com`
and `username=admin&password=admin`; (2) `GET /admin/index` with the returned cookie.

## Response
See `response.txt` (login headers) and `evidence/dashboard.html` (rendered superuser console).
- Step 1 → `HTTP 302`, `Set-Cookie: PUBLICCMS_ADMIN=2_<uuid>`, `Location: index.html`.
- Step 2 → `HTTP 200`, `<title>企业中英文站点 - Management system</title>`.

## Observation
Matches the static prediction exactly. The cookie's `2_` prefix proves the session belongs to
`sys_user` id=2, the demo superuser (not the installer-secured id=1). Offline derivation confirms
the credential: `sha512(sha512("admin") + "0123456789")` reproduces the shipped hash byte-for-byte
(the `[SETUP]` line in `run.log`). Negative control: `password=wrongpass123` with the same Host
returns HTTP 200 (stays on the login page, no 302, no cookie) — so the 302+cookie is a genuine
authentication success, not an unconditional redirect.

## Side effects
None. The script only authenticates and reads the dashboard; it performs no writes as the
superuser. `sys_user` id=2 remains unchanged. Each login mints a fresh `sys_user_token`/session
row (normal login side effect); no cleanup required.

## Research & references
- CWE-798 (Use of Hard-coded Credentials) / CWE-321 (Hard-coded Cryptographic Key).
- OWASP WSTG-ATHN-02 "Testing for Default Credentials" — method: identify shipped/sample accounts
  and attempt vendor defaults. Applied here to the demo `admin` account.
- The `Host`-header site-resolution angle mirrors OWASP WSTG-INPV Host-header testing: the app
  trusts `request.getServerName()` to pick the tenant, so the attacker selects site 2 at will.

## If FAILED
n/a — CONFIRMED.

## Notes on the secondary defect (ENCRYPT_KEY)
`CommonConstants.ENCRYPT_KEY = "publiccms"` is a compile-time constant shared by every install and
is used to encrypt `database.properties` at rest. Not independently exercised here (it needs a file
read to chain), but it is a static-confirmed hard-coded key (CWE-321). It converts any file-read
primitive into DB-credential disclosure.
