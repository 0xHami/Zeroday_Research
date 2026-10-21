# VULN-034 — Unauthenticated GET /organization/setup leaks unpublished draft courses

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Medium — CVSS 3.1 5.3 `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N`
**Validated at**: 2026-09-27

## Preconditions
- The org's public `siteName` (here `cve-hunt-academy` — it is the catalog slug, effectively public).
- No authentication.

## Request
See `request.http`: `GET /organization/setup?siteName=cve-hunt-academy` with **no Cookie header**.

## Response
`HTTP 200` with `data.courseData` = an array of **43** courses (all courses for the org), including a course we had just created and left **unpublished** (`isPublished:false`, `type:"SELF_PACED"`). See `response.txt`.

## Observation
The route (`apps/api/src/routes/organization/organization.ts:713`) has no auth middleware, and `getCoursesBySiteNameForSetup` (`packages/db/src/queries/course/course.ts:360-373`) filters only on `organization.siteName` — its own doc comment (`:355-356`) admits it "includes unpublished courses". So an anonymous caller enumerates every course for an org by its public siteName, including in-development drafts the hardened `/org-site/*` channel would hide. No member rows are joined, so (unlike VULN-016) no PII leaks here — the exposure is draft course metadata (titles/roadmap).

## Side effects
- Read-only. One unpublished draft course created per run (random suffix); harmless orphan.

## Research & references
- OWASP API3:2023 (excessive data exposure) / CWE-200. Same unauthenticated-read class as VULN-016 and VULN-033: each omits the PUBLIC/published/ACTIVE visibility gate.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.
