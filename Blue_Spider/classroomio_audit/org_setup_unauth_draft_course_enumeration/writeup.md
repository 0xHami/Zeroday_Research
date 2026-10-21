# VULN-034 — Unauthenticated draft-catalog enumeration via `GET /organization/setup`

| | |
|---|---|
| **ID** | VULN-034 (raw F-47) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.3** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | **None** (fully unauthenticated) |
| **What an attacker gains** | The full course catalog for any org by its public `siteName`, **including unpublished / in-development drafts** |

## Summary

The `organization/setup` endpoint is validated but not authenticated, and the query it uses filters courses only by the org's `siteName` — with no `isPublished`, `type`, or `status` gate. So an anonymous caller who knows the org's public catalog slug receives every course for that org, drafts included. Confirmed live: an anonymous request returned 43 courses, among them an unpublished (`isPublished:false`) course created moments earlier.

## How it works (mechanism & code trace)

**Entry — `apps/api/src/routes/organization/organization.ts:713-728`.** No auth middleware, only query validation:

```ts
.get('/setup', zValidator('query', ZGetOrgSetup), async (c) => {
  const { siteName } = c.req.valid('query');
  const setupData = await getOrgSetupData(siteName);
  return c.json({ success: true, data: setupData }, 200);
})
```

**Sink / defect — `packages/db/src/queries/course/course.ts:355-373`.** The doc comment itself admits it includes unpublished courses, and the only predicate is `siteName`:

```ts
/** Gets courses by organization siteName (for setup - includes unpublished courses) */
export const getCoursesBySiteNameForSetup = async (siteName: string) => {
  const result = await db.select({ course: schema.course })
    .from(schema.course)
    .innerJoin(schema.group, eq(schema.course.groupId, schema.group.id))
    .innerJoin(schema.organization, eq(schema.group.organizationId, schema.organization.id))
    .where(eq(schema.organization.siteName, siteName));       // siteName only — no visibility gate
```

**Why the framework doesn't save it.** As with VULN-016, the hardened public path (`/org-site/*`, and `GET /organization/courses/public` right above this route at `:494-499`, "returns only published courses") demonstrates the intended gate — but `/setup` was written for the first-run wizard and reuses a filter that deliberately includes drafts, while exposing it on an unauthenticated route.

## Why it is a vulnerability

`siteName` is public (it is the catalog slug used in URLs). The endpoint therefore lets anyone enumerate an org's unpublished/in-development course titles and metadata — competitive/roadmap information the org has chosen not to publish. It reads org-scoped data with no relationship (`S:C`) and no PII (unlike VULN-016), hence `C:L`.

## Reproduction

1. (Setup) As admin, create a `SELF_PACED` course and leave it unpublished.
2. Decisive request — **no cookie**:
   ```
   GET http://localhost:21527/organization/setup?siteName=cve-hunt-academy
   Origin: http://localhost:21526
   ```
   → `HTTP 200`, `data.courseData` contains the draft with `isPublished:false`.
3. `./run.sh` prints `data.courseData returned 43 courses ...` and the confirmed presence of the unpublished draft, then `[OK]`. See `run.log` / `response.txt`.

## Impact

- **Draft/roadmap leakage** and course enumeration for any org by public `siteName`.
- **Chaining:** the returned `id`/`slug` values feed VULN-016 (member emails + full content) and complement VULN-033 (org config).

## Suggested fix

Route public catalog reads through the published-only path, or add the visibility gate to the query (`packages/db/src/queries/course/course.ts:360`):

```diff
   .innerJoin(schema.organization, eq(schema.group.organizationId, schema.organization.id))
-  .where(eq(schema.organization.siteName, siteName));
+  .where(and(
+    eq(schema.organization.siteName, siteName),
+    eq(schema.course.isPublished, true),
+    eq(schema.course.type, 'PUBLIC'),
+    eq(schema.course.status, 'ACTIVE')
+  ));
```

If a genuine unauthenticated setup fetch is required, gate `/setup` with auth + org membership instead.

## References

- OWASP API3:2023 (excessive data exposure). CWE-200.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; none concerns `/organization/setup` or draft-course enumeration.
2. `classroomio github security advisory GHSA` — 9 GHSAs; none on unauthenticated catalog/draft exposure.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no match.
5. Issue tracker `unpublished OR "draft courses" OR "organization/setup" OR getCoursesBySiteNameForSetup OR "all organizations" OR "every organization" OR "org config"` — 53 hits; #1210 "prevent students from accessing unpublished courses" was the only candidate (inspected below); nothing on an unauthenticated setup endpoint.
6. Issue tracker `security in:title` — #1093 "protect public organization landing data" fetched: dashboard-only DTO narrowing for org-site pages; it does not touch `GET /organization/setup` or the course query.
7. Fetched PR #1210 (merged 2026-09-27T04:11Z, two hours after the audited commit) — adds a 404 for *logged-in students* opening unpublished course content via `assertEnrolledStudentContentAccess` (`apps/api/src/services/course/access.ts`) and core `getCourse`; it does not mention `/organization/setup`, `getCoursesBySiteNameForSetup`, `siteName`, or anonymous callers. An automated reviewer comment on that PR notes a "publication check skipped" on a public slug flow, but that is a bot remark about a different path, not a report of this endpoint.
8. Fetched PR #978 "restrict organization roster access" — team/audience endpoints only.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- PR #1210 (merged 2026-09-27) — same topic (unpublished courses) but a different actor (enrolled student, authenticated) and a different code path (course content access), leaving the unauthenticated `/setup` listing untouched.
- PR #1093 (merged 2026-09-10) — narrows public org-site data in the dashboard layer; not the API setup endpoint.
- CVE-2025-65670 / GHSA-mh75-3225-9wcj — students reaching admin/teacher data by altering course IDs in the old Supabase dashboard; different stack and requires a student session.

**Reasoning:** No public record describes the unauthenticated `GET /organization/setup?siteName=` route returning every course for an org, drafts included, via the `getCoursesBySiteNameForSetup` query that has no `isPublished`/`status` predicate. Upstream's same-day fix #1210 shows the vendor was actively closing unpublished-course exposure for students, which makes a wider private sweep plausible and keeps confidence at 75, but that fix neither names nor covers the anonymous setup endpoint.
