# VULN-028 — `disableEmailPassword`/`disableGoogleAuth` enforced UI-only (dead-code guards)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 5.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`; → High where SSO is force-required)
**Validated at**: 2026-09-27

## Preconditions
- Org admin session to set the flag. The `disableEmailPassword` column is set on the org row
  (id `48bbdff8-…`) and **restored to its original value** at the end of the run.
- A set of valid email/password credentials whose account is a member of the org (admin creds
  used) — i.e. exactly the account a wired guard would block.

## Request
See `request.http`.
```
PUT  /organization                     {"disableEmailPassword":true}   (admin)
POST /api/auth/sign-in/email           {admin creds}                   (fresh jar)  → still 200 + Set-Cookie
```

## Response
See `response.txt`.
- `PUT /organization {"disableEmailPassword":true}` → **HTTP 403** `UPGRADE_REQUIRED`
  ("Public/auth settings require an Enterprise plan"). This is the *entitlement-to-change* gate
  (`assertAuthSettingsEntitlement`), which trips because the **API container runs with
  `PUBLIC_IS_SELFHOSTED` empty (cloud mode)** and the org is on the default `BASIC` plan. It is
  unrelated to the login bypass. The flag was therefore set directly on the DB row (a legitimate
  admin/operator action; the task permits the psql route).
- With `organization.disable_email_password = 't'` (verified via psql), `POST /api/auth/sign-in/email`
  returned **HTTP 200** with `Set-Cookie: classroomio.session_token=…`.

## Observation
The org's decision to disable email/password login has **no effect on authentication**. Better
Auth registers `emailAndPassword` unconditionally (`packages/db/src/auth.ts:52`), and the guards
that would enforce the flags — `checkEmailPasswordAllowed` / `checkGoogleAuthAllowed`
(`auth/hooks/auth-settings.ts:63,112`) — have **zero callers** repo-wide (grep-confirmed: only
their definitions exist; they are never wired into a better-auth `before` hook). So with the flag
set true and persisted, the "disabled" method still authenticates (200 + session). Only the
dashboard UI honours the flag (by hiding the form). This defeats a "force SSO" / method-lockdown
control and lets a compromised email/password remain usable after being "disabled". The Google
path shares the identical dead-guard defect; it is dormant here only because the instance uses
placeholder Google OAuth credentials.

Deployment note: the manifest records the intended mode as self-hosted, but the **API** process
has `PUBLIC_IS_SELFHOSTED` unset, so the API behaves as cloud (the documented split-mode gotcha in
the target's own `CLAUDE.md`). This affects only the PUT entitlement gate; the dead-guard bypass
is mode-independent (the guards are uncalled in both modes).

## Side effects
- `organization.disable_email_password` toggled true then **restored** to its original value
  (`f`) in a `finally` block (verified: end state `f`). No other state changed.

## Research & references
- CWE-284 Improper Access Control / CWE-1188 (insecure default) — a security policy toggle whose
  server-side enforcement is dead code.
- OWASP ASVS V2 (Authentication) — the server must enforce which authentication mechanisms are
  permitted; client-only enforcement is not a control.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
The Google-auth half (`disableGoogleAuth`) is dormant here (placeholder OAuth creds, no live
Google flow). It shares the same uncalled guard; to see it live, configure real Google OAuth,
set `disableGoogleAuth=true`, and confirm `GET /api/auth/sign-in/social?provider=google` still
initiates the flow.
