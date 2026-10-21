# VULN-023 — Course create writes body `organizationId` (cross-tenant course injection)

| | |
|---|---|
| **ID** | VULN-023 (raw F-43) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium (High in cloud) — **CVSS 3.1 6.5** `AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** — live cross-tenant injection into a foreign org |
| **Auth required** | Org ADMIN (of one org) |
| **What an attacker gains** | Inject courses/groups into another tenant's catalog (spam, defacement, foothold group) |

## Summary
`POST /course` authorizes ADMIN against the `cio-org-id` **header** org, but the service builds the course's group from the **body** `organizationId`, and the two are never reconciled. On this instance a second org existed, so an admin of org A (header = A) with body `organizationId = B` injected a real course + group into org B — a live cross-tenant write by a non-member.

## How it works (mechanism & code trace)
**Route — `apps/api/src/routes/course/course.ts:138`:**
```ts
.post('/', authMiddleware, orgAdminMiddleware, zValidator('json', ZCourseCreate), async (c) => {
    const user = c.get('user')!;
    const validatedData = c.req.valid('json');
    const result = await createCourse(user.id, validatedData);   // validatedData.organizationId is from the BODY
```
**Authz — `apps/api/src/middlewares/org-admin.ts:28-43`** checks ADMIN against `c.req.header('cio-org-id')` only.

**Sink — `packages/core/src/services/course/course.ts:294-300`:**
```ts
const [newGroup] = await createGroup(
  { name: data.title, description, organizationId: data.organizationId }, tx  // BODY value, not c.get('orgId')
);
```
**Schema — `packages/utils/src/validation/course/course.ts:308`** `organizationId: z.string().min(1)` — any non-empty string, never compared to the authorized org.

**Why the framework doesn't save it:** the only backstop is the DB foreign key `group.organization_id → organization.id`. A *bogus* uuid is rejected there (HTTP 500), but a *real* other-tenant org id satisfies the FK and the write lands cross-tenant.

## Why it's a vulnerability
The destination scope is a client-controlled body field while authorization is proven only for the header org. Proving admin of A authorizes writes into B — cross-tenant integrity violation (**S:C**, **I:H**).

## Reproduction (numbered)
1. **Test A (validation/authz accept the mismatch):** `POST /course` with header `cio-org-id: A`, body `organizationId: <random uuid>`, `{title,description,type:"SELF_PACED"}` → **HTTP 500** (FK abort) — **not** 400/403. The mismatched body org passed zod + `orgAdminMiddleware` and reached the DB.
2. **Contrast:** same but header `cio-org-id: <random uuid>` → **HTTP 403** `ORG_TEAM_NOT_AUTHORIZED` — authorization is anchored to the header.
3. **Test B (CONFIRMED cross-tenant):** header `cio-org-id: A`, body `organizationId: <real foreign org B>` → **HTTP 201**; verified the created `group.organization_id == B` while the admin has 0 membership rows in B. Injected course/group deleted afterward.

## Impact (and chaining)
- Cross-tenant catalog pollution / defacement / foothold groups in cloud.
- Destination-org root shared with VULN-005 (course clone). Victim `organizationId`s are enumerable (VULN-033).

## Suggested fix
`packages/core/src/services/course/course.ts:294-300` — bind the destination to the authorized org and drop it from the schema:
```diff
- const [newGroup] = await createGroup({ name: data.title, description, organizationId: data.organizationId }, tx);
+ const [newGroup] = await createGroup({ name: data.title, description, organizationId: authorizedOrgId }, tx);
```
Pass `c.get('orgId')` from the route into `createCourse` as `authorizedOrgId`, and remove `organizationId` from `ZCourseCreate` (`course.ts:308`) so the client cannot supply it.

## References
- CWE-639 IDOR; CWE-915 mass-assignment (destination scope from body).
- Evidence: `run.log`, `response.txt`, `request.http` in this directory.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — CVE-2025-65669/65670/65672/65675/65676/67259 and CVE-2026-111368; none concerns `POST /course` or a body `organizationId`.
2. `classroomio github security advisory GHSA` — 9 unreviewed GHSAs; the two Hono-API scoping CVEs (CVE-2026-111368 submission, CVE-2026-111369 lesson) do not cover course creation.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no match.
5. Issue tracker `isCustomDomainVerified OR "trusted origin" OR ... OR cross-tenant OR cross-org` — 49 hits; none report a cross-org course/group write via body `organizationId`.
6. Issue tracker `"custom domain" OR "automation key" OR organizationId OR disableEmailPassword OR cio-org-id` — 92 hits, feature PRs (#1217, #1384, #1341, #1008, #804); nothing on `createCourse` org binding.
7. Issue tracker `newsfeed IDOR OR ... OR "another course" OR "other courses" OR "cross-course"` — scoping fixes #1134 (cohort member mutations), #1122 (presign scope, unmerged); none on course creation.
8. Fetched the hackmd writeup behind CVE-2026-111368/111369 — it names the routers reviewed (submission, lesson, payment-request, content, section, mark, members); `POST /course` / `createGroup` is not among them.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-111368 / CVE-2026-111369 — same "authorization object ≠ mutation object" family under `/course/:courseId`, but on submission/lesson ids; different route and sink.
- PR #1134 "fix(api): scope cohort member mutations" (merged 2026-09-17) — a scoping fix in cohort members, not course creation.
- Issue #682 / PR #965 — foreign-org auto-join on tenant login; an org-membership flaw, not a cross-tenant write.

**Reasoning:** No public record describes `POST /course` trusting the body `organizationId` over the `cio-org-id` header org, nor the `createGroup(... organizationId: data.organizationId)` sink. The nearest public items are the Oct-2026 Hono scoping CVEs, whose author enumerated the routers examined and did not include course creation. The cross-tenant class is active in this project, so a private report could exist.
