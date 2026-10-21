# VULN-015 — Arbitrary-user PII oracle via analytics endpoints

| | |
|---|---|
| **ID** | VULN-015 (raw AC-5) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 7.7** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Low — a team member of **one** org or course (ADMIN/TUTOR, or a course team member) |
| **What an attacker gains** | The full name + email (+ avatar, last-seen) of **any** account on the instance, by userId — a global de-anonymization / PII-harvest oracle (cross-tenant in cloud) |

## Summary

Two analytics endpoints take a path `:userId` and return that user's profile without ever checking that the user belongs to the caller's org/course. Being a team member of one scope is treated as license to resolve any `userId` on the platform to its name and email. Confirmed live: an authorized caller resolved a freshly-created account — one with empty `orgRoles`, i.e. a member of no org and not enrolled in the caller's course — to its exact email on **both** endpoints.

## How it works (mechanism & code trace)

**Entry A — `apps/api/src/routes/organization/organization.ts:471-493`.** Gated by team membership of the *org*, then the raw `:userId` is passed through:

```ts
.get('/audience/:userId/analytics', authMiddleware, orgTeamMemberMiddleware,
     zValidator('param', ZGetUserAnalytics), async (c) => {
  const orgId = c.req.header('cio-org-id')!;
  const { userId } = c.req.valid('param');
  const analytics = await getUserAnalytics(userId, orgId);   // userId is arbitrary
```

`orgTeamMemberMiddleware` admits any ADMIN or TUTOR (`apps/api/src/middlewares/org-team-member.ts:44`): `if (roleId !== ROLE.ADMIN && roleId !== ROLE.TUTOR) return 403`.

**Entry B — `apps/api/src/routes/course/people.ts:172-194`.** Same shape, gated by `courseTeamMemberMiddleware` (course team member or org admin):

```ts
.get('/:userId/analytics', courseTeamMemberMiddleware, zValidator('param', ZCourseUserAnalyticsParam),
     ..., async (c) => {
  const { courseId, userId } = c.req.valid('param');
  const analytics = await getUserCourseAnalytics(courseId, userId, { includeProgressImpact });
```

**Sink / defect — the services resolve the profile globally.** `apps/api/src/services/organization.ts:998-1090`:

```ts
export async function getUserAnalytics(userId: string, orgId: string) {
  const profile = await getProfileById(userId);            // global lookup — no org membership filter
  if (!profile) throw new AppError('User profile not found', ..., 404);
  ...
  return { user: { id: userId, fullName: profile.fullname || '', email: profile.email || '',
                   avatarUrl: profile.avatarUrl || '', lastSeen: lastSeen || undefined }, ... };
```

and identically `packages/core/src/services/course/course.ts:724-803` (`getUserCourseAnalytics` → `getProfileById(userId)` → returns `user.email`). The `orgId`/`courseId` are used only to compute *course stats*, never to constrain which `userId` may be resolved.

**Why the framework doesn't save it.** The middleware authorizes the caller against the *authorization object* (the org/course in the header/path) but the *mutation/read object* is the path `:userId`, and nothing reconciles them. Zod validates that `:userId` is a string — not that it is a member. This is the canonical BOLA gap.

## Why it is a vulnerability

The endpoint is meant to return analytics for a user **within** the caller's org/course audience. Returning the profile of a user who is a member of neither is an object-level authorization failure: it converts "team member of one course" into "read any account's email on the instance." Confirmed against a fresh account with `orgRoles == {}` — provably outside every org — so this is not "leaks a co-member," it is a global oracle. A STUDENT session (not a team member) is correctly rejected with 403, which proves the route is access-controlled and isolates the defect to the unconstrained `:userId`; the lowest role that passes — a TUTOR — already has the full capability.

## Reproduction

Preconditions: the target is up; a caller that is a team member of one org/course (the manifest admin qualifies; a TUTOR is equivalent).

1. Create a fresh account (the "victim") and note its `userId`; it has empty `orgRoles`.
2. Decisive requests (caller's cookie + `cio-org-id`):
   ```
   GET /organization/audience/<victim userId>/analytics
   GET /course/<caller courseId>/members/<victim userId>/analytics
   ```
   → both `HTTP 200`, `data.user.email == <victim email>` although the victim is not a member.
3. `./run.sh` prints both 200s with the leaked `{fullName,email,avatarUrl,lastSeen}`, the STUDENT negative control (`403`), and `[OK]`. See `run.log` / `response.txt`.

## Impact

- **Targeted de-anonymization + email harvesting** across the whole instance (cross-tenant in cloud, where `getProfileById` spans tenants).
- **Chaining:** userIds leak liberally (course rosters via VULN-016, community authors, etc.); harvested emails feed the unauthenticated phishing relay VULN-024/032.
- Data at risk: every user's name + email.

## Suggested fix

Before returning the profile, verify `:userId` is a member of the authorized scope, else 404. For the org endpoint (`apps/api/src/services/organization.ts:998`):

```diff
 export async function getUserAnalytics(userId: string, orgId: string) {
+  const isMember = await isProfileInOrg(userId, orgId);   // packages/db/src/queries/organization
+  if (!isMember) throw new AppError('User profile not found', ErrorCodes.PROFILE_NOT_FOUND, 404);
   const profile = await getProfileById(userId);
```

and for the course endpoint (`packages/core/src/services/course/course.ts:724`) require `userId` to be a `groupmember` of `courseId` before `getProfileById`. Additionally, avoid emitting `email` for co-members unless strictly required.

## References

- OWASP API Security Top 10 2023 — API1:2023 Broken Object Level Authorization.
- CWE-639 (authorization bypass through user-controlled key), CWE-200.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 40 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — 9 known ClassroomIO CVEs; none concern user analytics endpoints.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; no analytics advisory; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio audience analytics userId email disclosure vulnerability "analytics"` — no results naming these routes; only CVE-2025-65670/67259.
5. Direct read of the repo issue list filtered for security — found issues #640 and #643 (see below) and #685.
6. Read github.com/classroomio/classroomio/issues/640 and /643 — report the **legacy SvelteKit route** `POST /api/analytics/user` (`apps/dashboard/src/routes/api/analytics/user/+server.ts`) returning another user's analytics for a body-supplied `userId` with no caller permission check; closed with no linked fix.
7. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — no analytics coverage.

**Related but distinct public references** (same class or component, not this bug):
- GitHub issues classroomio/classroomio#640 and #643 — PARTIAL MATCH: the same concept (a user-analytics endpoint resolves an arbitrary `userId` without scoping) in the predecessor SvelteKit implementation. Different files/routes (Hono `GET /organization/audience/:userId/analytics` and `GET /course/:courseId/members/:userId/analytics` → `getUserAnalytics`/`getUserCourseAnalytics` → global `getProfileById`), and a different defect shape (legacy route had no authorization at all; the new routes are gated by team-member middleware but never scope `:userId` to the org/course).
- CVE-2025-67259 (GHSA-rx88-8j23-4qxx) — authenticated student reads other students'/tutors' details via PostgREST `/rest/v1/course` in 0.1.13; different stack and endpoint.

**Reasoning:** No public reference names the Hono audience/member analytics routes or the unscoped `getProfileById` lookup in `getUserAnalytics`/`getUserCourseAnalytics`. The closest items (#640/#643) describe the equivalent flaw in the legacy dashboard route that these handlers replaced, and were closed without a fix, so the vendor has been told of the concept but not of this code path. Kept as a distinct component per the brief, with a low score reflecting the strong conceptual overlap. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
