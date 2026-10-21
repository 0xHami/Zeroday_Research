# VULN-014 — Dashboard analytics cross-org PII IDOR (authz on header, data on query `orgId`)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED (query-controlled org scope + learner-email exposure observed; non-member org served 200)
**Severity (static)**: High — CVSS 3.1 8.1 `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
**Validated at**: 2026-09-27

## Preconditions
- Any org member (for `/dash/stats`) / org admin (for `/dash/compliance-overview`) of one org. Admin here is a member of only org `48bbdff8…`.

## Request
See `request.http`. `GET /dash/compliance-overview?orgId=<X>` with header `cio-org-id: 48bbdff8…`, for X = our org, and X = a foreign org / random uuid. Plus the safe contrast `/dash/top-courses`.

## Response
- `?orgId=<our org>` → **200**, `data.learners[].email` includes the seeded student `u_…@cvehunt.local` (`totalLearners:1`).
- `?orgId=f0259e1a…` (admin **not** a member) → **200** (not 403), scoped to that org (0 learners; our student absent).
- `/dash/top-courses?orgId=f0259e1a…` → **200** scoped to OUR org (ignores the query).

## Observation
`GET /dash/compliance-overview` authorizes with `orgAdminMiddleware` against the **header** org and sets `c.set('orgId', header)`, but reads the queried org from `c.req.valid('query').orgId` (`apps/api/src/routes/dash/stats.ts:145`) and passes it to `getOrgComplianceOverview`, whose row query filters by that query-supplied `orgId` and returns `learners[].email` (PII). Dynamically: the same admin (member of only our org) gets a 200 for a **different** org's scope — proving authorization is anchored to the header while the data is driven by the client's query param, with no reconciliation. The sibling `/dash/top-courses` (`stats.ts:128` uses `c.get('orgId')`) ignores the query, confirming the intended pattern the vulnerable handlers omit. Against a populated victim org, the identical request returns that org's learner emails/names.

## Side effects
Seeded a COMPLIANCE course + one enrolled student in OUR org, then **deleted** them (course_newsfeed, groupmember, course, group); the random student account remains (harmless orphan).

## Research & references
- CWE-639 IDOR / authorization-channel divergence; OWASP API1:2023 BOLA.
- PII sink: `getOrgComplianceOverview` `learners[].email` (`apps/api/src/services/course/compliance.ts`), rows filtered by the query `orgId` in `packages/db/src/queries/course/compliance.ts`.

## If FAILED
n/a — CONFIRMED (query-controlled scope + email exposure).

## If NEEDS_MANUAL
A full cross-tenant email harvest at scale needs a victim org that actually contains compliance learners; the access-control break (a non-member org served on the query param) and the learner-email exposure are both confirmed here. `/dash/stats?orgId=&siteName=` (member-level) exhibits the same query-controlled behavior.
