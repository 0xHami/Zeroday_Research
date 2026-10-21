# VULN-030 — Public-API `/v1/courses/*` stale privilege (demoted key creator)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 5.4 — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`)
**Validated at**: 2026-09-27

## Preconditions
- A course with a student roster (PII target). An **existing** org course with ≥1 student is
  reused (found via psql); the recorded run used `b64ad4e2-…` with 2 students. (Creating new
  students via the invite/accept path is capped by the Free-plan student quota — see Side effects
  — so no new students are created.)
- An org automation key of type `api` (scope `public_api:*`) whose creator is user **S**.
  - The real create endpoint `POST /organization/automation/keys {type:"api"}` is **plan-gated**
    — it returned `403 "Public API keys require an Early Adopter or Enterprise plan"` (this org is
    on the default `BASIC` plan). So the key row was **seeded directly in the DB**, attributed to
    S, mirroring a key minted while S's org was on an eligible plan. The security control under
    test — the missing actor-role re-check in the v1 course services — is exercised live and is
    independent of how the key was minted.
- Actor **S**: a fresh account added as an org member **directly** (a psql `organizationmember`
  insert as ADMIN, because the invite/accept path is student-quota-capped). S is ADMIN at the
  baseline read, then **demoted to STUDENT** (`organizationmember.role_id` 1 → 3). Verified in the
  DB each phase. S's membership row is deleted at cleanup.

## Request
See `request.http`. Base path is `/public-api/v1` (mounted at `app.ts:254`). Same Bearer key
across both phases:
```
GET /public-api/v1/courses                         Authorization: Bearer <S's api key>
GET /public-api/v1/courses/<C>/students            Authorization: Bearer <same key>   (roster PII)
GET /public-api/v1/courses/<C>/members             Authorization: Bearer <same key>   (guarded sibling)
```

## Response
See `response.txt`.
```
Phase S=ADMIN   : courses=200  students=200  members=200
Phase S=STUDENT : courses=200  students=200  members=403      ← same key, creator demoted
```

## Observation
`c.set('actorId', automationKey.createdByProfileId)` fixes the actor to the key's **static**
creator (`middlewares/automation-key.ts:28`). The v1 course services
(`services/v1/courses/course.ts` — `listCoursesService`, `getCourseService`,
`listCourseStudentsService`) authorize with **only** `assertCourseBelongsToOrganization(orgId,
courseId)` — they never re-check the actor's current role. Confirmed live: after S was demoted
from ADMIN to STUDENT (DB `role_id` 1 → 3), the **same** key still returned `200` for
`/courses` and for `/courses/:id/students` (full student roster + PII). The sibling
`/courses/:id/members` route calls `assertCourseTeamMemberOrOrgAdmin(courseId, actorId)` (which
re-derives the live role via `isCourseTeamMemberOrOrgAdmin`) and flipped from `200` to `403` on
the same demotion — proving the role check exists and works elsewhere, and that the vulnerable
services simply omit it. `removeTeamMember`/role change does not revoke the key, so access
outlives the role (privilege persistence after off-boarding/demotion).

## Side effects
- One throwaway account (key-owner **S**) created via signup; its `organizationmember` row and the
  seeded api key row are both **deleted** at the end of the run (idempotent; frees the quota). No
  new student members are created; the reused roster course is only read, never modified.
- No production data destroyed.
- Quota note: the org shows 56 student rows, yet the invite/accept path rejects new students with
  "reached its 20-student limit on the Free plan" — an unrelated Free-plan cap that motivated the
  direct-membership setup above (not a limitation of the finding).

## Research & references
- CWE-284 Improper Access Control; specifically stale/lingering authorization (CWE-613
  Insufficient Session/credential Expiration flavour applied to API keys after a role change).
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization / API5:2023 Broken
  Function Level Authorization: authorization must reflect the actor's *current* privileges.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
The full "real API key minted by an admin then demoted" chain additionally requires an org on an
Early-Adopter/Enterprise plan so `POST /organization/automation/keys {type:"api"}` succeeds
(here it 403s on BASIC). Steps if reproducing with a real-minted key:
1. Put the org on an eligible plan (Enterprise/Early-Adopter, or self-hosted-Enterprise).
2. As an admin, `POST /organization/automation/keys {"type":"api"}` → capture `secret`.
3. Demote/remove that admin (`DELETE /organization/team/:memberId` or role change).
4. Repeat the two-phase read above; observe `/courses` + `/students` still 200, `/members` 403.
