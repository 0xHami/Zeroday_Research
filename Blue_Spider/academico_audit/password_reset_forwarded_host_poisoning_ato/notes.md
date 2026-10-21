# VULN-002 — Password-reset Host-header poisoning → account takeover

**Target name:** academico
**Target URL:** https://github.com/academico-sis/academico
**Software version:** untagged, commit a6518355 (2026-05-31)
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 8.8)
**Target commit**: a6518355c3a30818044c46a9fc7fd53da34ab7f7
**Validated at**: 2026-09-25

## Preconditions
- None to launch (unauthenticated). A victim account must exist; the exploit creates a
  fresh victim **admin** account via tinker to demonstrate worst-case (admin ATO).
- Mail driver is `log` (verified) so the reset email renders into `storage/logs/laravel.log`;
  the notification is `ShouldQueue` (queue=database), so `queue:work --once` is run to render it.
- **Target functional bug aligned as a documented precondition:** `config/auth.php:96`
  defaults the broker table to `password_reset_tokens`, but the shipped migration chain
  (`create_password_resets` → `rename … _tokens` → `revert …`) leaves the table named
  `password_resets`, so the reset flow 500s as-shipped (`Base table … password_reset_tokens
  doesn't exist`). The exploit renames the table to match the shipped config default —
  a functional-bug fix a real operator must make to use reset at all. The host-poisoning
  bug under test is independent of this mismatch.

## Request
See `request.http` — three requests: (1) reset request with `X-Forwarded-Host: evil.attacker.tld`;
(2) GET the captured link against the real server with the host spoof; (3) submit the new password.

## Response
See `response.txt`. This run:
- Poisoned link from the mail log:
  `https://evil.attacker.tld/admin/password-reset/reset?email=victim_...%40example.invalid&token=cca399…&signature=25e678…`
  — host is the attacker's, with a valid token + signature.
- Replay to the real server **without** the host spoof: **HTTP 403** (`ValidateSignature`
  rejects — the signature was computed over `evil.attacker.tld`).
- Replay **with** `X-Forwarded-Host: evil.attacker.tld`: **HTTP 200** (signature recomputed
  over the spoofed host, matches → check bypassed).
- `resetPassword`: HTTP 200 + redirect. Login with the attacker's new password: **True**;
  login with the victim's old password: **False** (locked out).

## Observation
The finding is real, but the mechanism differs from the report's write-up:
- **Report said:** "the `admin/password-reset/reset` route carries no `signed` middleware …
  so the signature Filament appends is never enforced."
- **Actually:** `route:list -v` shows the route DOES carry
  `Illuminate\Routing\Middleware\ValidateSignature`, and it IS enforced (naive replay = 403).
  The real reason the check is defeated is `trustProxies(at:'*')`: it lets the attacker spoof
  the Host on **both** the signing side (the poisoned email) and the validation side (the
  replay), so `ValidateSignature` recomputes over the attacker's host and passes. The
  vulnerability and its fix (pin the root URL / restrict trusted proxies) are unchanged; the
  root cause is shared with VULN-008.

## Side effects
- Created victim admin `victim_<suffix>@example.invalid` (id assigned at runtime); its password
  is now the attacker's value. Harmless test account. Renamed `password_resets` →
  `password_reset_tokens` (persists; this is the config-aligned name).
- Original seeded admin (id=1) untouched — re-verified logging in as `academico@thomasdebay.com`
  still works after this run.

## Research & references
- OWASP WSTG-**INPV** / "Testing for Host Header Injection" and the Password-Reset-Poisoning
  technique (attacker sets X-Forwarded-Host so the reset link points at their host).
  https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy — *HTTP Host header attacks → Password reset poisoning*:
  the exact technique (poison the reset email host via forwarded headers, harvest the token).
  https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
- Laravel signed URLs / `ValidateSignature`: the signature covers the absolute URL incl. host;
  when the host is attacker-controlled on both ends (trustProxies '*'), the signature is inert.
- Applied technique: spoof `X-Forwarded-Host` on the reset request to poison the link, then
  spoof it again on replay so `URL::hasValidSignature()` recomputes over the same host.

## If FAILED
n/a — CONFIRMED.
