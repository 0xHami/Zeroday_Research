# VULN-014 — Dashboard analytics cross-org PII IDOR (authz on header, data on query `orgId`)

| | |
|---|---|
| **ID** | VULN-014 (raw F-09) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 8.1** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** — query-controlled org scope + learner-email exposure; non-member org served |
| **Auth required** | Any org member (`/stats`) / org admin (`/compliance-overview`) of one org |
| **What an attacker gains** | Read another tenant's analytics and compliance learners **with email addresses** (cross-tenant PII) |

## Summary
The `/dash/*` handlers authorize the caller's role against the `cio-org-id` **header** org, but query the org taken from the client-supplied **query** `orgId`/`siteName`, never reconciling the two. Confirmed here: an admin who is a member of only org A gets **HTTP 200** for `/dash/compliance-overview?orgId=B` scoped to B (a non-member org), and the endpoint returns learner **emails**.

## How it works (mechanism & code trace)
**Handler — `apps/api/src/routes/dash/stats.ts:138-146`:**
```ts
.get('/compliance-overview', authMiddleware, orgAdminMiddleware, zValidator('query', ZDashComplianceOverview), async (c) => {
    const { orgId } = c.req.valid('query');            // attacker-chosen org
    const result = await getOrgComplianceOverview(orgId);
```
(`/stats` at `:43-49` reads query `orgId`/`siteName` the same way.)

**Authz — `apps/api/src/middlewares/org-member.ts:26-53`** (and `org-admin.ts`) validate `orgRoles[header]` and `c.set('orgId', header)` — the query `orgId` is never compared.

**PII sink — `getOrgComplianceOverview` (`apps/api/src/services/course/compliance.ts`)** returns a `learners[]` array including `email` and `fullname`, from rows filtered by the passed `orgId` (`packages/db/src/queries/course/compliance.ts`).

**Safe contrast — `stats.ts:125-137` `/top-courses`:**
```ts
const orgId = c.get('orgId')!;                         // authorized header org, query ignored
const result = await getTopCoursesByViews(orgId, days, bust);
```
This is the pattern the vulnerable handlers omit.

## Why it's a vulnerability
Authorization is anchored to one channel (header) while the data query is driven by an independent client-controlled channel (query `orgId`). Proving membership in one org authorizes reads of any org — a cross-tenant confidentiality break (BOLA) that exposes learner email addresses.

## Reproduction (numbered)
1. Seed our org with a COMPLIANCE course + one enrolled student (known email).
2. `GET /dash/compliance-overview?orgId=<OUR ORG>` (header = OUR ORG) → **200**, `data.learners[].email` contains the seeded student's email — the endpoint exposes learner PII.
3. `GET /dash/compliance-overview?orgId=<OTHER ORG we're not a member of>` (header still OUR ORG) → **200** (not 403), scoped to that org (our student absent) — the query `orgId` selects the org; a non-member org is served.
4. Contrast `GET /dash/top-courses?orgId=<OTHER ORG>` → **200** scoped to OUR org (query ignored).

**Scale note (NEEDS_MANUAL delta):** against a victim org that actually contains compliance learners, step 3 returns that org's learner emails/names. The access-control break and email-exposure mechanism are confirmed here; the harvest volume scales with the victim's data.

## Impact (and chaining)
- Cross-tenant business analytics + a roster of another tenant's compliance learners with emails (PII) → feeds phishing (VULN-024/032). Victim `orgId`s enumerable (VULN-033); `siteName` is the public catalog slug.
- **PR:L**, **S:C**, **C:H**.

## Suggested fix
In every `/dash/*` handler use the authorized org, not the client's:
```diff
- const { orgId } = c.req.valid('query');
- const result = await getOrgComplianceOverview(orgId);
+ const orgId = c.get('orgId')!;
+ const result = await getOrgComplianceOverview(orgId);
```
(`apps/api/src/routes/dash/stats.ts:145` and `:45`.) Drop `orgId`/`siteName` from `ZDashComplianceOverview`/`ZDashStats` so they cannot be supplied.

## References
- CWE-639 IDOR; OWASP API1:2023 Broken Object Level Authorization.
- Evidence: `run.log`, `response.txt`, `request.http` in this directory.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 35 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — 9 known ClassroomIO CVEs; none concern the `/dash/*` analytics routes.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; no analytics advisory; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio dash stats compliance-overview orgId cross-organization analytics IDOR` — no results naming these routes; only the known IDOR CVEs.
5. Direct read of the repo issue list filtered for security — found issues #640 and #643 (see below) and #685.
6. Read github.com/classroomio/classroomio/issues/640 and /643 — both report a cross-org analytics IDOR in the **legacy SvelteKit dashboard route** `POST /api/analytics/dash` (`apps/dashboard/src/routes/api/analytics/dash/+server.ts`, `orgId` from the request body, no membership check, `getOrganisationAnalytics`); closed 2026-03-13 / 2026-05-28 with no linked fix (maintainer: "a lot of this will be going away anyways").
7. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — no analytics coverage.

**Related but distinct public references** (same class or component, not this bug):
- GitHub issues classroomio/classroomio#640 and #643 (reporter lighthousekeeper1212, Feb 2026) — PARTIAL MATCH: the same functional bug (org analytics returned for a client-supplied `orgId` without reconciling it with the caller's org) in the predecessor implementation. Different file/route (`apps/dashboard/src/routes/api/analytics/dash/+server.ts` vs. Hono `apps/api/src/routes/dash/stats.ts`), different parameter channel (body vs. query), and a different defect shape (no authz at all vs. authz bound to the `cio-org-id` header while data is scoped by query `orgId`). `/dash/compliance-overview` and its learner-email payload are not in the issues.
- GitHub issue #685 — students seeing analytics for courses they do not own on the cloud dashboard UI (no endpoint named, no fix linked).

**Reasoning:** No public reference names the Hono `/dash/stats` or `/dash/compliance-overview` handlers or the header-vs-query `orgId` mismatch; the closest public items (#640/#643) describe the same vulnerability concept in the legacy SvelteKit route that the Hono API replaced, and they were closed without a fix. Because the maintainers were publicly told about a cross-org analytics IDOR by `orgId` eight months earlier, this finding is best characterised as "the reported defect survived the rewrite into new code, plus a new PII-bearing endpoint" — kept per the brief's rule that a different component is not the same disclosure, but with a low score so the owner can judge novelty. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
