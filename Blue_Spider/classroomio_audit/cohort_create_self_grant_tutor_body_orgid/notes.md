# VULN-010 — Cohort creation self-grants cohort TUTOR (+ body organizationId)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: High — CVSS 3.1 8.1 `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N`
**Validated at**: 2026-09-27

## Preconditions
- Any authenticated session. Demonstrated with a plain STUDENT (roleId 3) provisioned
  via the app's own course share-link flow, and additionally with a fully anonymous
  better-auth session (VULN-018) — i.e. no account at all.
- No org-membership, role, or tutor/admin privilege is required by the route
  (`authMiddleware` only). In single-org, the body `organizationId` must be the real
  org uuid (a foreign/bogus id fails the FK); the privesc uses the real org id.

## Request
See `request.http`. Decisive request (STUDENT session):
```
POST http://localhost:21527/cohort
cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
Content-Type: application/json

{"organizationId":"48bbdff8-2ad5-46a3-a259-2ca3d52677dd","name":"pwn-cohort-<rand>"}
```

## Response
`HTTP 201 {"success":true,"data":{"id":"5008dd46-…","organizationId":"48bbdff8-…","name":…}}`.
See `response.txt` / `run.log`.

## Observation
The static finding predicted the creator is unconditionally inserted as a cohort TUTOR.
Confirmed against Postgres: after the STUDENT's single request,
`cohort_member(cohort=5008dd46-…, profile=<student>).role_id = 2` (TUTOR), and
`cohort.organization_id` equals the body-supplied org. The same request from an
**anonymous** session also produced a `cohort_member.role_id = 2` row. The caller
began as roleId 3 (STUDENT) / no org role (anon) and ended as a cohort TUTOR — a
vertical privilege escalation in one unprivileged request. That TUTOR role is exactly
what `cohortTeamMemberMiddleware` gates, so it unlocks the cohort add-course /
invite / newsfeed endpoints (the VULN-009 precondition, validated in that directory).

## Side effects
- Creates one `cohort` row and one `cohort_member` row (roleId 2) per run. Names carry a
  random suffix. Rows are left in place as evidence; they are inert (no email sent, no
  enrollment) and scoped to the test org.

## Research & references
- OWASP API Security Top 10 2023 — API1:2023 Broken Object Level Authorization and
  API5:2023 Broken Function Level Authorization (privileged create with no role gate).
- CWE-269 Improper Privilege Management; CWE-915 Improperly Controlled Modification of
  Object Attributes (mass-assignment of `organizationId`).
- Contrast within the same codebase: every other cohort route
  (`PUT/DELETE /cohort/:cohortId`, add-course, invite) uses `cohortTeamMemberMiddleware`,
  and course/quiz creation force the org server-side — only the create path skips both.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a for the within-org privesc (fully automated). The *cross-tenant* consequence
(creating a cohort inside an arbitrary foreign org via the body `organizationId`)
requires a second organization and is only reachable in cloud/multi-tenant mode.
