# VULN-025 — Open redirect in login/signup and auth-handoff (`//evil.com`)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
**Validated at**: 2026-09-27

## Preconditions
- For the decisive **server-side** proof: one valid login-link token (self-minted via the
  authenticated "view as student" endpoint). No special privilege — any account can mint one.
- The client-side login/signup sinks need no precondition (a victim clicking a crafted URL).

## Request
See `request.http`. Decisive server request (no browser needed):
```
GET /api/auth/login-link?token=<VALID>&redirect=//evil.example/phish   (no Origin header)
```
Client sinks accept the same payload: `GET /login?redirect=//evil.example/phish`,
`GET /signup?redirect=//evil.example/phish`.

## Response
See `response.txt`. Guard behaviour across payloads (all HTTP 302):
```
redirect='//evil.example/phish'   → Location: '//evil.example/phish'   (ACCEPTED — open redirect)
redirect='/\evil.example/phish'   → Location: '/\evil.example/phish'   (ACCEPTED — browsers treat /\ as //)
redirect='/lms'                   → Location: '/lms'                   (safe control, accepted)
redirect='https://evil.example/x' → Location: '/'                      (absolute URL rejected → fallback)
```
The decisive response also carries `Set-Cookie: classroomio.session_token=…` (the redirect fires
**after** the session is established).

## Observation
`redirect.startsWith('/')` is not an origin check. A protocol-relative `//evil.example`
(and the backslash variant `/\evil.example`) begins with `/`, so it passes the guard, yet a
browser resolves it to a different origin. Confirmed live: the server emits
`Location: //evil.example/phish` from a user-supplied `redirect` param — a working open redirect.
Because the login-link handler sets the session cookie and then redirects, this is specifically
the **post-Set-Cookie auth-handoff** variant: a freshly-authenticated victim is bounced to the
attacker origin. The absolute-URL control (`https://evil.example`) correctly falls back to `/`,
isolating the `//`/`/\` bypass. The identical `startsWith('/')` guard is present client-side in
`login/+page.svelte:110` and `signup/+page.svelte:194` (a `window.location.href` sink) and
server-side in `token-exchange.ts:41`.

## Side effects
- One throwaway account created (to mint the token). The login-link GETs create short-lived
  sessions for that same account. No persistent damage.

## Research & references
- CWE-601 URL Redirection to Untrusted Site ("Open Redirect").
- OWASP Cheat Sheet — Unvalidated Redirects and Forwards: protocol-relative `//host` and
  backslash `/\host` are the canonical `startsWith('/')` bypasses; the repo already ships the
  correct fix (`resolveOrgJoinRedirect`, a full `URL` origin comparison) but does not use it here.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
The browser *navigation* on the client login/signup sinks is a client-side `window.location.href`
assignment; its effect is confirmed by code + the accepted param, and the same class is proven
server-side (a raw 302 to `//evil.example`), so no browser was required.
