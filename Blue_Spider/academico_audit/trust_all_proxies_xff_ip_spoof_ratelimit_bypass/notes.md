# VULN-008 — trustProxies('*') → client-controlled request()->ip()

**Target name:** academico
**Target URL:** https://github.com/academico-sis/academico
**Software version:** untagged, commit a6518355 (2026-05-31)
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 5.3)
**Target commit**: a6518355c3a30818044c46a9fc7fd53da34ab7f7
**Validated at**: 2026-09-25

## Preconditions
- None (unauthenticated). Uses failed logins against a random nonexistent account, so
  nothing is created and no real account is locked (the throttle is per-IP, not per-account).

## Request
See `request.http` — repeated `POST /livewire-5f244c96/update` calling `authenticate`
with wrong credentials, varying only the `X-Forwarded-For` header.

## Response
See `response.txt`. Decisive observation (this run):
- Phase A, FIXED `X-Forwarded-For: 203.0.113.165`: attempts 1–5 → `CREDS`
  ("These credentials do not match"); attempts 6–8 → `THROTTLED` (only a rate-limit
  notification effect, credential check no longer runs). The limiter is real and engages
  after 5.
- Phase B, ROTATING `X-Forwarded-For` (fresh 10.x.x.x per request): 0/8 throttled — every
  attempt gets a fresh bucket, identical failed-login volume, never blocked.
- Corroboration: `Illuminate\Http\Request` with `X-Forwarded-For: 203.0.113.77, 10.0.0.5`
  and trusted proxies `*` resolves `->ip() = 203.0.113.77` (the left-most, attacker-set
  entry) — the same value written to logs/activitylog/Sentry.

## Observation
Exactly the static prediction. The 5-attempt Filament login throttle
(`Login.php:20 $this->rateLimit(5)`) keys on `request()->ip()`, and with
`trustProxies(at:'*')` (`bootstrap/app.php:16`) that value is the client's own
`X-Forwarded-For`. Rotating the header defeats the throttle entirely; the same header is
the forged source IP for audit records.

## Side effects
None persisted. Failed-login throttle buckets for the random IPs used will expire on
their own (short decay window). Admin account untouched (wrong email used).

## Research & references
- OWASP WSTG — **WSTG-ATHN-04** / anti-automation & rate limiting; and IP-spoofing via
  `X-Forwarded-For` when the app trusts all proxies. https://owasp.org/www-project-web-security-testing-guide/
- Laravel docs — "Configuring Trusted Proxies": trust only known proxy IPs/CIDRs, never
  `*`, when the app is not behind a proxy that overwrites XFF. Technique applied: rotate
  the left-most XFF entry to rotate the derived `request()->ip()` and thus the limiter key.
- Shared root cause with VULN-002 (the same setting makes `X-Forwarded-Host` attacker-controlled).

## If FAILED
n/a — CONFIRMED.
