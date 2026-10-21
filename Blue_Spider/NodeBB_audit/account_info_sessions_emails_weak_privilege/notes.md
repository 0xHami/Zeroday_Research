# VULN-021 — /info over-exposes session IP/UA + email/username history

**Software**: NodeBB
**Repository**: https://github.com/NodeBB/NodeBB
**Affected version**: 4.16.0 (install/package.json:5; commit-pinned, untagged master)
**Status**: CONFIRMED (config-gated)
**Severity (static)**: Medium (conditional)
**Target commit**: 20623201cbf2cc8a37612726cdf10ee82083c9c3
**Validated at**: 2026-09-28

## Preconditions
- Admin delegated `groups:view:users:info` to a lower-privileged group (here `registered-users`), a
  supported ACP privilege choice. Default grants it only to global-mods/admins (who are already
  isPrivileged). The exploit grants it, tests, then rescinds it.

## Request / Response
See `request.http` / `response.txt` / `run.log`. Captured:
```
viewer uid=5 isAdmin=False isGlobalMod=False
GET /api/user/admin/info    -> 200; sessions=10 (first ip=172.18.0.1), emails=[admin@example.com], usernames=[admin]
GET /api/user/admin/sessions -> 403   (same data, canEdit-gated, denied)
```

## Observation
Confirmed exactly. A member holding only `view:users:info` read the admin's 10 session records
(each with `ip`, `uuid`, `platform`, `browser`, `version`, `datetime`), full email history and username
history via `GET /api/user/admin/info`, while the dedicated `GET /api/user/admin/sessions` (same session
data, canEdit-gated) returned 403 for the same caller. This is the authorization divergence the static
finding describes: `info.js:29-39` assigns `sessions/emails/usernames/invitedBy` unconditionally, and the
`/info$` path exception (`src/middleware/user.js:192-193`) admits `view:users:info` — a weaker bar than
`canEdit` (/sessions) or showemail/self (listEmails) for the identical data.

## Side effects
Config change (grant) then restored. One throwaway viewer user created. Read-only on the victim.

## Research & references
- OWASP API1:2023 (Broken Object Level Authorization) / API3 (excessive data exposure);
  WSTG-ATHZ-02.
- NodeBB treats IP addresses as GDPR-sensitive; session IP/UA + email history over-exposure is the
  concrete impact.
- CWE-200, CWE-284.

## If FAILED
n/a — CONFIRMED (config-gated; conditional risk in the report).
