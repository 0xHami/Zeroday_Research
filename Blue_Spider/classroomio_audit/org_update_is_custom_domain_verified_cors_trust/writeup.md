# VULN-021 — `isCustomDomainVerified` mass-assignment → instance-wide credentialed-CORS trust

| | |
|---|---|
| **ID** | VULN-021 (raw F-14) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium (High in cloud) — **CVSS 3.1 6.5** `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Org ADMIN (of one org) |
| **What an attacker gains** | Inject an arbitrary hostname into the instance-wide credentialed-CORS allowlist → cross-origin read of authenticated API responses from an attacker-controlled origin |

## Summary
`PUT /organization` accepts a client-settable `isCustomDomainVerified` boolean. Setting `{customDomain:"evil.example", isCustomDomainVerified:true}` makes the API add `evil.example` to a process-wide trusted-origin set with **no DNS/ownership check**, and `sessionCors` then reflects that origin with `Access-Control-Allow-Credentials: true`. Confirmed end-to-end here: an untrusted origin flips from not-reflected to reflected purely as a result of the admin's self-assertion.

## How it works (mechanism & code trace)
**Entry / schema — `packages/utils/src/validation/organization/organization.ts:147-148`:**
```ts
customDomain: z.string().nullable().optional(),
isCustomDomainVerified: z.boolean().optional(),   // client-settable "verified" flag
```
**Route — `apps/api/src/routes/organization/organization.ts:842`** `.put('/', authMiddleware, orgAdminMiddleware, zValidator('json', ZUpdateOrganization), …)` → `updateOrg(orgId, data)`.

**Sink — `apps/api/src/services/organization.ts:816-829`.** The body values are persisted and, if the (self-asserted) flag is true, the hostname is trusted with no verification:
```ts
const organization = await updateOrganization(orgId, data); // writes customDomain + isCustomDomainVerified from body
...
const newCustomDomainHostname = organization.customDomain?.trim().toLowerCase();
if (newCustomDomainHostname && organization.isCustomDomainVerified) {
  trustCustomDomainHostname(newCustomDomainHostname);        // no DNS/ownership check
}
```
`updateOrganization` sets the columns straight from `data` (`packages/db/src/queries/organization/organization.ts:1204` `.set(setData)`).

**Trust store — `packages/db/src/utils/custom-domain/trusted-origin.ts:8`** is a **process-wide** Set shared across every request/tenant:
```ts
const verifiedCustomDomainHostnames = new Set<string>();
```
consulted by CORS at `:95` (`verifiedCustomDomainHostnames.has(hostname)`), reached from `sessionCors` (`apps/api/src/middlewares/cors.ts:25-29`, `credentials:true`) → `apps/api/src/utils/origins.ts:16`.

**Why the framework doesn't save it:** `NODE_ENV=production` here, so the dev-only local-host allowance (`trusted-origin.ts:87`) is inactive; the untrusted `evil.example` origin is reflected **only** because the mass-assignment inserted it. The legitimate flow (`apps/api/src/routes/domain/domain.ts:31-36`) proves the flag is meant to come from the Approximated provider's real verification, never the client.

## Why it's a vulnerability
A security-critical boolean that must be derived from an out-of-band DNS/ownership check is accepted as a request field and fed into a global credentialed-CORS allowlist. Any org admin injects an arbitrary origin instance-wide; combined with credentialed CORS reflection (F-02), a page on that origin can read other users'/tenants' authenticated API responses cross-origin.

## Reproduction (numbered)
1. Baseline: `GET /` with `Origin: http://evil-<rand>.example` → **no** `Access-Control-Allow-Origin`.
2. As org admin: `PUT /organization` `{"customDomain":"evil-<rand>.example","isCustomDomainVerified":true}` → **200**; DB persists both fields (`isCustomDomainVerified=t`).
3. Re-probe: `GET /` with `Origin: http://evil-<rand>.example` → `Access-Control-Allow-Origin: http://evil-<rand>.example` **and** `Access-Control-Allow-Credentials: true`.
4. (Weaponization) From a page on the now-trusted origin, issue credentialed `fetch` to the API and read the response cross-origin.
5. Cleanup (automated): `PUT /organization` `{"customDomain":null,"isCustomDomainVerified":false}` → origin no longer reflected; org restored.

## Impact (and chaining)
- Instance-wide credentialed-CORS trust pollution → cross-tenant confidentiality via CORS credential theft in cloud.
- Directly weaponizes F-02 (CORS reflection), turning an otherwise-latent config into an exploitable cross-origin read. **PR:H**, **S:C** (affects other orgs), **C:H**.

## Suggested fix
`packages/utils/src/validation/organization/organization.ts:147-148` — strip client control of the verified flag (and ideally `customDomain`):
```diff
 customDomain: z.string().nullable().optional(),
-isCustomDomainVerified: z.boolean().optional(),
```
Only the DNS-verified `/domain` flow (`domain.ts:31-36`) may set `isCustomDomainVerified`. Additionally namespace the trusted-origin store per org or re-derive it at request time from persisted, provider-verified domains (`trusted-origin.ts:8`).

## References
- CWE-915 Improperly Controlled Modification of Object Attributes (mass-assignment); CWE-346 Origin Validation Error; OWASP CORS misconfiguration.
- Evidence: `run.log`, `response.txt`, `request.http` in this directory.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — CVE-2025-65669/65670/65672/65675/65676/67259 and CVE-2026-111368; none concerns custom-domain verification or CORS trust.
2. `classroomio github security advisory GHSA` — 9 unreviewed GHSAs (incl. CVE-2025-67298, CVE-2026-111369); none on `PUT /organization`, `isCustomDomainVerified`, or `trustCustomDomainHostname`.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports exist for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8 entries), `security.snyk.io ?search=classroomio` (no results), repo `security/advisories` (none published) — no match.
5. Issue tracker `isCustomDomainVerified OR "trusted origin" OR trustCustomDomainHostname OR "Allow-Credentials" OR CORS OR cross-tenant OR cross-org` — 49 hits, all feature/PR noise (#1124 first-party domain allowlist, #1204 rate limiting); none report a verification-flag mass-assignment or CORS allowlist pollution.
6. Issue tracker `"custom domain" OR "automation key" OR organizationId OR disableEmailPassword OR cio-org-id` — #1360 (public API lacks domain endpoints; free-plan gate UI-only), #1332 (PostHog proxy on custom domains); no match.
7. Commit search `"custom domain" OR "automation key" OR sanitize OR certificate OR PUBLIC_IS_SELFHOSTED` — 338cfef (academy host allowlist), 5320f1e (verified domain for view-as-student handoff); no verification-bypass fix.
8. Fetched issue #643 — its "unauthenticated domain management" item is the SvelteKit dashboard route `apps/dashboard/src/routes/api/domain/+server.ts` (Vercel add/remove/verify with no org-admin check), not the Hono `PUT /organization` verified flag.
(Note: the WebSearch quota was exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- Issue #643 (closed 2026-05-28) — dashboard `/api/domain` route lacked authorization; different component and different root cause (missing authz vs. a client-settable "verified" boolean feeding the credentialed-CORS allowlist).
- Issue #1360 (open, 2026-10-18) — free-plan custom-domain restriction enforced only in the UI; plan gating, not ownership verification or CORS.
- CVE-2025-65672 / GHSA-px6j-wc84-gwhf — IDOR on course share/invite settings; unrelated component.

**Reasoning:** No advisory, issue, or commit names `isCustomDomainVerified`, the process-wide `verifiedCustomDomainHostnames` set, or credentialed-CORS trust pollution via `PUT /organization`. The only public domain-management report (#643) targets a different layer and sink. The custom-domain code is under active change (#1124, #1360), so an in-flight or private report cannot be excluded, hence 80 rather than 90+.
