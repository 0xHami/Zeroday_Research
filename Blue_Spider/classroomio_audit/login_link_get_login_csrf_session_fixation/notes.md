# VULN-026 — Login CSRF / session fixation via reusable self-mintable login-link GET

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.1 — `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N`)
**Validated at**: 2026-09-27

## Preconditions
- One authenticated attacker account (to self-mint a login-link token for *its own* account).
  Created at runtime via signup. No admin privilege.
- Victims modelled as **fresh cookie jars** (independent browsers with no session).

## Request
See `request.http`. Decisive sequence:
```
POST /account/view-as-student-token   {}                      (attacker)  → token for attacker's own account
GET  /api/auth/login-link?token=<attacker token>              (victim jar, no Origin, no CSRF token)
GET  /api/auth/get-session                                    (victim jar) → user == attacker
```

## Response
See `response.txt`.
- Self-mint → `200 {"success":true,"data":{"token":"<jwt>"}}`.
- Victim #1 login-link GET → `302` with `Set-Cookie: classroomio.session_token=…`; subsequent
  `get-session` returns the **attacker's** `user.id` and `email`.
- Victim #2 (separate jar, `Origin: https://attacker.example`) replaying the SAME token → also
  authenticated as the attacker (token reusable within its TTL; no Origin/CSRF rejection).

## Observation
`GET /api/auth/login-link?token=` creates and sets a full session with **no Origin/Referer/CSRF
check**. Under `SameSite=Lax` cookies a top-level cross-site GET navigation still sets cookies,
so an attacker can drive a victim's browser here. The token is only signature/expiry-verified —
there is no `jti`/nonce and it is not consumed — so it is **replayable**. Because any user can
self-mint a login-link token for their own account (`/account/view-as-student-token`), the
attacker mints for the **attacker** account, and the victim's browser is signed in **as the
attacker** (login CSRF / session fixation). Confirmed live: two independent fresh jars both
resolved to the attacker's `user.id` using the same token, including one that sent an attacker
`Origin` header (proving no Origin check). Anything the victim then enters (profile data,
uploads, a linked OAuth identity) accrues to the attacker's account.

## Side effects
- One throwaway attacker account created. The login-link GETs created two short-lived sessions
  bound to that account. No persistent damage.

## Research & references
- CWE-352 Cross-Site Request Forgery (login CSRF) and CWE-384 Session Fixation.
- OWASP — "Login CSRF" and the Session Management Cheat Sheet: session-establishing operations
  must require a POST with a CSRF token / Origin validation and must use one-time tokens.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. The whole chain is confirmable with plain HTTP (no browser needed): the Set-Cookie plus the
subsequent `get-session` identity is decisive proof of the fixed session.
