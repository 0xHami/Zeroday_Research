# VULN-030 — Public-API `/v1/courses/*` ignores the key actor's current role (stale privilege)

| | |
|---|---|
| **ID** | VULN-030 (raw F-06) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.4** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Possession of an org automation key whose creator was later demoted/removed |
| **What an attacker gains** | Continued full read of course rosters/PII and course create/update/delete after losing the role that justified it |

## Summary

The public (v1) API authorizes the acting identity as the key's **static** creator profile id.
The `/v1/courses/*` services authorize on **course-belongs-to-org only** — they never re-check the
actor's *current* role. A key whose creator has since been demoted to student (or removed) still
grants full read of course rosters/PII and course mutation. Every **sibling** domain
(members, cohorts) re-derives the current role, proving the pattern the course services skipped.

Confirmed live with a decisive side-by-side contrast on the **same key**: after the key's creator
was demoted from ADMIN to STUDENT, `GET /public-api/v1/courses` and
`/public-api/v1/courses/:id/students` still returned `200` (course list + full student roster),
while the guarded sibling `/public-api/v1/courses/:id/members` flipped from `200` to `403`.

## How it works (mechanism & code trace)

**Actor is the key's static creator — `apps/api/src/middlewares/automation-key.ts:28`:**

```ts
c.set('actorId', automationKey.createdByProfileId);      // fixed at key-creation time
```

**Vulnerable services check only course↔org — `apps/api/src/services/v1/courses/course.ts:26-41`:**

```ts
export async function listCoursesService(orgId, query) {
  return getOrganizationCourses(orgId, '', ROLE.ADMIN, query);       // no actor check at all
}
export async function getCourseService(orgId, params) {
  await assertCourseBelongsToOrganization(orgId, params.courseId);   // course↔org only
  return getCourse(params.courseId);
}
export async function listCourseStudentsService(orgId, params) {
  await assertCourseBelongsToOrganization(orgId, params.courseId);   // …then returns roster + PII
  const members = await listCourseMembers(params.courseId);
  return members.filter((m) => m.roleId === ROLE.STUDENT);
}
```

`assertCourseBelongsToOrganization` (`apps/api/src/services/v1/shared.ts:49-54`) inspects the
**course's** org, never the **actor**:

```ts
export async function assertCourseBelongsToOrganization(orgId, courseId) {
  const courseOrganizationId = await getCourseOrganizationId(courseId);
  if (!courseOrganizationId || courseOrganizationId !== orgId) { throw new AppError('Course not found', …, 404); }
}
```

**The pattern they skipped — `apps/api/src/services/v1/shared.ts:83-96`** re-reads the live role;
`apps/api/src/services/v1/courses/members.ts:30-33` uses it:

```ts
export async function assertOrgTeamMember(orgId, actorId) {
  assertAutomationActor(actorId);
  const roleId = await getOrganizationMemberRoleId(orgId, actorId);   // LIVE db read (organizationmember)
  if (roleId === ROLE.ADMIN || roleId === ROLE.TUTOR) return;
  throw new AppError('Automation actor must be an organization admin or tutor', …, 403);
}
// members.ts:  await assertCourseTeamMemberOrOrgAdmin(courseId, actorId)  → isCourseTeamMemberOrOrgAdmin (live)
```

**Why the framework doesn't save it.** `removeTeamMember`/role change does not revoke the person's
automation keys, and the actor id captured on the key is static; because the course services never
call `assertOrgTeamMember`/`assertCourseTeamMemberOrOrgAdmin`, there is nothing to notice the
demotion. (Route-level scope middleware gates `public_api:*` but is orthogonal — it does not check
the actor's org role.)

## Why it is a vulnerability

Authorization is bound to the course's org membership, not to the acting key-owner's **current**
role. This is classic stale/lingering authorization: privilege persists after off-boarding or
demotion. The same key that a demoted student holds continues to expose course rosters (student
PII) and course CRUD for the whole org.

## Reproduction

Base path `/public-api/v1` (mounted at `app.ts:254`). Setup: an **existing** org course with a
student roster is reused (the invite/accept path is capped by the Free-plan student quota, so no
new students are created); a fresh key-owner **S** is added as an org member directly (psql), ADMIN
at baseline then demoted to STUDENT (`organizationmember.role_id` 1 → 3); an `api` (`public_api:*`)
key is attributed to S. S's membership and the key are removed at cleanup.

> Note: `POST /organization/automation/keys {"type":"api"}` is plan-gated — it returned
> `403 "Public API keys require an Early Adopter or Enterprise plan"` on this `BASIC` org — so the
> key row was seeded directly in the DB, attributed to S. The defect under test (the missing
> actor-role re-check in the course services) is exercised live regardless of how the key was minted.

1. While S is ADMIN, read with S's key: `/courses` → 200, `/courses/<C>/students` → 200 (roster),
   `/courses/<C>/members` → 200.
2. Demote S to STUDENT (`organizationmember.role_id` 1 → 3). The key is **not** revoked.
3. Re-read with the **same** key:
   ```
   GET /public-api/v1/courses                    → 200        (stale privilege)
   GET /public-api/v1/courses/<C>/students        → 200        (roster + PII — stale privilege)
   GET /public-api/v1/courses/<C>/members         → 403        (guarded sibling honours the demotion)
   ```
4. `./run.sh` → `[OK]`, exit 0:
   ```
   (real POST /organization/automation/keys {type:api} → HTTP 403: "Public API keys require an Early Adopter or Enterprise plan")
   Phase S=ADMIN   : courses=200  students=200  members=200
   Phase S=STUDENT : courses=200  students=200  members=403
   ==> VULN-030: CONFIRMED — demoted key still reads /v1/courses + student roster; guarded /members returns 403
   ```

## Impact

- **Privilege persistence after off-boarding/demotion** — a demoted/removed team member's key
  keeps full read of course rosters (student PII) and course create/update/delete.
- **Data at risk:** course rosters/PII and content for the key's org.
- **Chains:** roster/PII feeds data-harvest findings; course mutation overlaps the course
  create/update findings.

## Suggested fix

Add the actor-role re-check at the start of each `apps/api/src/services/v1/courses/course.ts`
service, mirroring `members.ts`:

```ts
export async function getCourseService(orgId, actorId, params) {
  await assertOrgTeamMember(orgId, actorId);              // NEW — reject a demoted actor
  await assertCourseBelongsToOrganization(orgId, params.courseId);
  return getCourse(params.courseId);
}
// same for listCoursesService / listCourseStudentsService / export / update / delete
```

Also revoke a member's automation keys when they are demoted/removed (`removeTeamMember` and the
role-change path).

## References

- CWE-284 Improper Access Control; stale authorization after role change (CWE-613 flavour applied
  to long-lived API keys).
- OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization / API1:2023 BOLA:
  authorization must reflect the actor's current privileges.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; none concerns the public `/v1` API or automation keys.
2. `classroomio github security advisory GHSA` — 9 GHSAs; none on `public-api/v1/courses` or stale key privilege.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no match.
5. Issue tracker `demoted OR "removed member" OR stale OR assertOrgTeamMember OR "automation actor" OR revoke automation key` — 184 hits; #1310 (closed: API keys update member role), #1280 (admins change teammate role); none report a key retaining course/roster access after its creator's demotion.
6. Issue tracker `"custom domain" OR "automation key" OR ...` — #1003 (OAuth 2.1 proposal; notes automation keys lack expiry/revocation), #804 (rate-limit keying), #1204 (video routes); none on actor-role re-check.
7. Commit search `CORS OR redirect OR "login link" OR newsfeed OR attendance` — c5c984f (#987) flagged and fetched: session-based course access now requires live org membership so removed/demoted admins lose instructor privileges; the body never mentions API keys, automation keys, or `/v1/courses`.
8. Commit search `"custom domain" OR "automation key" OR sanitize OR certificate OR PUBLIC_IS_SELFHOSTED` — 1dad967 (#1211) removes automation keys from in-app presign/lesson routes; e913a4a1 scopes MCP keys; neither adds `assertOrgTeamMember` to `apps/api/src/services/v1/courses/course.ts`.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- PR #987 (merged 2026-09-04) — same concept (a demoted/removed admin keeping privileges) but for session users on dashboard/course routes; the automation-key actor path in the v1 course services is a distinct code path that still checks course↔org only.
- Issue #1003 (open) — automation-key lifecycle/revocation gaps raised as a feature request, not as a missing role re-check.
- PR #1211 / issue #1204 — automation-key route hygiene (rate limiting, scope middleware), not role staleness.

**Reasoning:** No public record states that `listCoursesService` / `getCourseService` / `listCourseStudentsService` skip the live actor-role check that the sibling `members`/`cohorts` services perform, or that a key outlives its creator's demotion. Upstream has publicly fixed the analogous session-based stale-privilege problem (#987), which shows awareness of the concept and lowers confidence to 70, but that fix neither names nor touches the public-API services.
