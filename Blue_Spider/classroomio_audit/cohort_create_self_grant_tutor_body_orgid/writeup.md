# VULN-010 — Cohort creation self-grants cohort TUTOR (+ mass-assigned organizationId)

| | |
|---|---|
| **ID** | VULN-010 (raw F-41) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned, no tagged release |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 8.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N` (PR:N via the anonymous-session path) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any session — a self-registered STUDENT, or an anonymous better-auth session (no account) |
| **What an attacker gains** | A self-granted **cohort TUTOR** role in the org, which satisfies `cohortTeamMemberMiddleware` and unlocks cohort invite / add-course / newsfeed — the precondition for VULN-009 (force-enroll / payment-gate bypass) |

## Summary

`POST /cohort` creates a cohort and makes the caller a cohort **TUTOR** of it. The route
is gated by `authMiddleware` alone — there is no org-membership check, no role check, and
the owning `organizationId` is taken from the request body rather than the authorized
context. Any authenticated principal, down to an anonymous session, therefore mints a
cohort and self-grants the privileged cohort-team role. Confirmed live: a STUDENT
(roleId 3) — and separately an anonymous session — each ended up with a
`cohort_member.role_id = 2` (TUTOR) row after a single request.

## How it works (mechanism & code trace)

**Entry — `apps/api/src/routes/cohort/cohort.ts:121-135`.** The only middleware is
`authMiddleware`; the body simply extends the create schema with `organizationId`:

```ts
.post(
  '/',
  authMiddleware,                                                    // ← only gate: "is there a session?"
  zValidator('json', ZCreateCohort.extend({ organizationId: z.string().uuid() })),
  async (c) => {
    const user = c.get('user')!;
    const { organizationId, ...data } = c.req.valid('json');         // org comes from the BODY
    const cohort = await createCohort(organizationId, user.id, data);
    return c.json({ success: true, data: cohort }, 201);
  }
)
```

Every *other* cohort route in the same file uses `cohortTeamMemberMiddleware` or
`cohortMemberMiddleware`; the create path uses neither. `ZCreateCohort`
(`packages/utils/src/validation/cohort/cohort.ts:4-8`) only validates `name`/`description`/
`coverImage`, so nothing ties the caller to the org.

**Service — `apps/api/src/services/cohort/cohort.ts:127-140`.** The body org and the
caller id flow straight into the creator-membership helper:

```ts
export async function createCohort(organizationId: string, profileId: string, data: TCreateCohort) {
  const description = data.description?.trim() || `A cohort for ${data.name}`;
  return createCohortWithCreatorMembership(
    { organizationId, createdByProfileId: profileId, name: data.name, description, coverImage: data.coverImage },
    profileId
  );
}
```

**Sink — `packages/db/src/queries/cohort/cohort.ts:37-60`.** In one transaction the cohort
row is inserted with the body-supplied org, then the creator is unconditionally written as
a **TUTOR** member:

```ts
export async function createCohortWithCreatorMembership(cohortData, creatorProfileId) {
  return await db.transaction(async (tx) => {
    const [cohort] = await tx.insert(schema.cohort).values(cohortData).returning();
    if (!cohort) throw new Error('Failed to create cohort');

    await tx.insert(schema.cohortMember).values({
      cohortId: cohort.id,
      profileId: creatorProfileId,
      roleId: ROLE.TUTOR                       // ← self-granted privileged role, no authorization decision
    });

    return cohort;
  });
}
```

**Why the framework doesn't save it.** `authMiddleware` only proves a valid session
exists; it does not assert org membership or role. There is no `c.get('orgId')` binding
and no `orgTeamMemberMiddleware`/`orgAdminMiddleware` on the route, so the privileged
`ROLE.TUTOR` insert happens for whoever calls it. (In self-hosted single-org, the FK on
`cohort.organization_id` is the only constraint, so the attacker supplies the real org id —
which they can read from the unauthenticated catalog endpoints.)

## Why it is a vulnerability

Two invariants break:

1. **Privileged role for free (CWE-269).** A cohort TUTOR can invite students, add courses,
   and post to a cohort newsfeed — all gated by `cohortTeamMemberMiddleware`, which trusts
   `cohort_member.role_id`. Handing that role to any caller with no authorization decision
   is a textbook vertical privilege escalation. The attacker begins with STUDENT (roleId 3)
   or *no* org role at all (anonymous) and ends as a cohort-team member.
2. **Owning scope taken from the body (CWE-915).** The org that owns the cohort is chosen by
   the client, never reconciled with the caller's membership. Single-org, this is masked by
   the FK; multi-tenant (cloud), it is a cross-tenant write.

The self-granted role is not cosmetic: it is the precise gate that VULN-009 needs, turning
"anyone with a session" into "can force-enroll students into arbitrary courses."

## Reproduction

Preconditions: target up; a STUDENT session (the shared helper provisions one via a course
share link). Org id `48bbdff8-2ad5-46a3-a259-2ca3d52677dd`.

1. As the STUDENT, create a cohort:
   ```
   POST http://localhost:21527/cohort
   cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
   Content-Type: application/json

   {"organizationId":"48bbdff8-2ad5-46a3-a259-2ca3d52677dd","name":"pwn-cohort-x"}
   ```
   → `HTTP 201`, `data.id` = the new cohort.
2. Confirm the self-granted role in Postgres:
   ```
   docker exec cio-postgres psql -U postgres -d classroomio -t -A -c \
     "select role_id from cohort_member where cohort_id='<id>' and profile_id='<student>';"
   ```
   → `2` (TUTOR).
3. Automated: `./run.sh` → prints `[OK]` and exits 0. `run.log` shows
   `cohort_member(...).role_id = '2'` for both the STUDENT and an anonymous session.

## Impact

- **Vertical privilege escalation** from STUDENT (or anonymous) to cohort TUTOR, live in
  the single-org deployment.
- **Chain into VULN-009 (F-13):** as the self-granted cohort tutor, add any org course to
  the cohort and force-enroll its students — bypassing that course's invite / enrollment /
  payment gate. The two findings compose into "any session → force-enroll into any course."
- **Cross-tenant (cloud):** the body `organizationId` lets an attacker create cohorts inside
  an arbitrary organization.

## Suggested fix

`apps/api/src/routes/cohort/cohort.ts:121-135`:

```ts
// before
.post('/', authMiddleware, zValidator('json', ZCreateCohort.extend({ organizationId: z.string().uuid() })), …)

// after
.post('/', authMiddleware, orgTeamMemberMiddleware,           // require tutor/admin of the header org
  zValidator('json', ZCreateCohort), async (c) => {
    const user = c.get('user')!;
    const organizationId = c.get('orgId')!;                    // bind to the authorized org, drop it from the body
    const cohort = await createCohort(organizationId, user.id, c.req.valid('json'));
    …
```

Additionally, reconsider the unconditional `roleId: ROLE.TUTOR` self-insert in
`createCohortWithCreatorMembership` — assign the creator's cohort role from an
authorization decision rather than granting TUTOR to whoever calls create.

## References

- OWASP API Security Top 10 2023 — API5:2023 Broken Function Level Authorization;
  API3:2023 Broken Object Property Level Authorization (mass assignment).
- CWE-269 Improper Privilege Management; CWE-915 Improperly Controlled Modification of
  Object Attributes.
- In-repo positive control: `cohortTeamMemberMiddleware`
  (`apps/api/src/middlewares/cohort-team-member.ts`) and the org-forcing create paths for
  courses/quizzes show the pattern this route omits.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 78 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — only the 9 known ClassroomIO CVEs; none mention cohorts.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; none cohort related; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio cohort create "cohort" tutor privilege escalation vulnerability organizationId` — nothing on cohort creation; surfaced only CVE-2026-111368/111369 and the HackMD report.
5. Read github.com/classroomio/classroomio/pull/1134 "fix(api): scope cohort member mutations" (merged 2026-09-17) — scopes cohort member update/delete, newsfeed, goals and course-member mutations to the cohort/course; does not touch `POST /cohort` or the creator TUTOR grant in `createCohortWithCreatorMembership`.
6. Read commit 1844ad9 (#1277 "let cohort tutors grade submissions without org admin") — grading access for cohort tutors; not cohort creation.
7. Direct read of the repo issue list filtered for security — only #1266 (cohort submissions UX); nothing on cohort creation / self-granted roles. HackMD report: cohorts mentioned only as the already-fixed sibling (PR #1134).

**Related but distinct public references** (same class or component, not this bug):
- classroomio/classroomio PR #1134 — cohort *member mutation* scoping (memberId not bound to cohortId); same `apps/api/src/routes/cohort/cohort.ts` file, different routes and different defect.
- CVE-2026-111368 / CVE-2026-111369 — resource-id-scoping IDORs in submission/lesson routes; different component.

**Reasoning:** The only public cohort-related security change is PR #1134, which addresses member-row scoping and leaves the `authMiddleware`-only `POST /cohort` route, the body-supplied `organizationId`, and the unconditional `ROLE.TUTOR` self-insert untouched; no advisory, issue or write-up describes them. Confidence is reduced because the vendor has recently been auditing the cohort module and could have fixed or been told about this privately. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
