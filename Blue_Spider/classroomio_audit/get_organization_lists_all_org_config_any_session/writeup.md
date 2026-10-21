# VULN-033 — `GET /organization` discloses full org config to any/anon session

| | |
|---|---|
| **ID** | VULN-033 (raw F-20) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.3** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any session — including an **anonymous** session minted for free (VULN-018) |
| **What an attacker gains** | Every organization's full config row — auth-posture flags, settings, AI-tutor escalation email, custom-domain config (cross-org enumeration); real billing IDs in cloud |

## Summary

`GET /organization` is gated by `authOrApiKeyMiddleware`, which accepts any logged-in session — so the free anonymous session from the ungated better-auth `anonymous()` plugin (VULN-018) passes. With no query filters the query returns **every** organization's full row. Confirmed live via the 401→200 differential: no cookie → 401, anonymous session → 200 returning two orgs' full config to an actor that is a member of neither.

## How it works (mechanism & code trace)

**Entry — `apps/api/src/routes/organization/organization.ts:103-119`.**

```ts
.get('/', authOrApiKeyMiddleware, zValidator('query', ZGetOrganizations), async (c) => {
  const filters = c.req.valid('query');
  const organizations = await getOrganizationsWithFilters(filters);   // no membership scoping
  return c.json({ success: true, data: organizations }, 200);
})
```

`authOrApiKeyMiddleware`'s first branch passes for any session (`apps/api/src/middlewares/auth-or-api-key.ts`), and VULN-018's anonymous sign-in yields exactly such a session.

**Sink / defect — `packages/db/src/queries/organization/organization.ts:820-856`.** With no filters, `conditions` is empty, so `whereClause` is `undefined` — an unfiltered select over all orgs, projecting the full organization row plus plan data:

```ts
const whereClause = conditions.length > 0 ? and(...conditions) : undefined;   // ← undefined ⇒ no filter
const result = await db.select({
    organization: schema.organization,
    plan: { planName, isActive, provider, subscriptionId,
            customerId: sql`organization_plan.payload->>'customerId'` }
  })
  .from(schema.organization)
  .leftJoin(schema.organizationPlan, eq(schema.organization.id, schema.organizationPlan.orgId))
  .where(whereClause);
```

**Why the framework doesn't save it.** The gate answers "is there *a* session?" not "may this session read *this* org." No membership predicate is applied and no column projection narrows the row, so auth-posture flags (`disableEmailPassword`/`disableGoogleAuth`/`disableSignup`), `settings`, `customCode`, `aiTutorSettings` (incl. escalation email), `landingpage`, and custom-domain fields all ship to the caller.

## Why it is a vulnerability

Org configuration should be scoped to a member (or server-to-server only). Handing the full row of every org to an anonymous session is a broken-access-control information disclosure and a cross-org enumeration primitive (`S:C`). It is prime recon: auth posture reveals which auth methods to attack; the AI-tutor `escalation.email` and org contacts feed targeted phishing.

**Scope precision (local vs cloud).** On this self-hosted-style build the plan `subscriptionId` is a synthetic `selfhosted-*` and `customerId` is null, so the local confidentiality impact is **config / auth-posture disclosure + cross-org enumeration** — not real billing data. The product-level score keeps `C:H` because in cloud the identical query returns the full tenant roster with real billing IDs.

## Reproduction

1. Baseline: `GET /organization` with no cookie → `HTTP 401`.
2. Mint an anonymous session: `POST /api/auth/sign-in/anonymous` `{}` → `Set-Cookie: classroomio.session_token=…` (`user.isAnonymous=true`, `orgRoles={}`).
3. Decisive request: `GET /organization` with that cookie → `HTTP 200`, `data` is a list of full org config rows (observed: `probe3f8bad`, `cve-hunt-academy`).
4. `./run.sh` prints `no-cookie → 401`, `anon → 200`, the exposed config keys, and `[OK]`. See `run.log` / `response.txt`.

## Impact

- **Recon / enumeration** across all orgs on the instance (auth posture, settings, escalation email, custom-domain config).
- **Chaining:** VULN-018 (anon session) unlocks it with no account; leaked `orgId`/`siteName` feed VULN-034 (draft catalog) and other org-scoped attacks. In cloud: cross-tenant roster + billing-ID leak.

## Suggested fix

Restrict the endpoint to server-to-server use, or scope to the caller's membership and project only needed columns (`apps/api/src/routes/organization/organization.ts:103`):

```diff
- .get('/', authOrApiKeyMiddleware, zValidator('query', ZGetOrganizations), async (c) => {
-   const filters = c.req.valid('query');
-   const organizations = await getOrganizationsWithFilters(filters);
+ .get('/', apiKeyMiddleware, zValidator('query', ZGetOrganizations), async (c) => {   // server-to-server only
+   const filters = c.req.valid('query');
+   const organizations = await getOrganizationsWithFilters(filters);
```

For user sessions, return only the caller's own org(s) and never billing IDs or cross-tenant rows. Separately, remove the `anonymous()` plugin (VULN-018) so "any session" cannot be minted for free.

## References

- OWASP API5:2023 (Broken Function Level Authorization), API2:2023 (Broken Authentication).
- CWE-284 (improper access control), CWE-200 (information exposure).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; CVE-2025-67259 (PostgREST `/rest/v1/course` leak on the old Supabase stack) is the only info-disclosure CVE and targets a different endpoint.
2. `classroomio github security advisory GHSA` — 9 GHSAs; none on `GET /organization` or org-config exposure.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no match.
5. Issue tracker `unpublished OR "draft courses" OR "organization/setup" OR getCoursesBySiteNameForSetup OR "all organizations" OR "every organization" OR "org config"` — 53 hits; none report `GET /organization` returning every org's row to any session.
6. Issue tracker `security in:title` — #1093 "protect public organization landing data" flagged; fetched PR + files: dashboard-only (`apps/dashboard/.../public-org.ts` `toPublicOrg` DTO for org-site SSR, removes a debug log); no change to `apps/api/src/routes/organization/organization.ts` `GET /` or `getOrganizationsWithFilters`.
7. Fetched PR #978 "restrict organization roster access" (merged 2026-09-21) — restricts `GET /organization/team` and `/audience` to admins; the org listing is not touched.
8. Fetched issues #685, #640, #643 — dashboard analytics/admin-info leaks via SvelteKit `+server.ts` routes; not the Hono org list.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- PR #1093 (merged 2026-09-10) — narrows the org payload sent to public org-site pages (dashboard layer); a near-miss on "full org row exposure" but a different component, and the API endpoint still returns full rows at the audited commit.
- PR #978 — team/audience roster restriction (different endpoints).
- CVE-2025-67259 / GHSA-rx88-8j23-4qxx — student reads course relational data via PostgREST; different stack and endpoint.
- Issues #640 / #643 / #685 — dashboard analytics IDORs.

**Reasoning:** No public record describes `GET /organization` under `authOrApiKeyMiddleware` returning every organization's full configuration (auth flags, settings, AI-tutor escalation email, plan/customer ids) to any session, nor the `whereClause = undefined` unfiltered select. Upstream has fixed adjacent over-exposure in the dashboard (#1093) and rosters (#978), showing awareness of the class, which keeps confidence at 75. The anonymous-session enabler (VULN-018) is tracked separately.
