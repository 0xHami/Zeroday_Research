# VULN-016 — Unauthenticated GET /course/slug/:slug leaks any ACTIVE course + member emails

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: High — CVSS 3.1 7.5 `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
**Validated at**: 2026-09-27

## Preconditions
- A course slug (guessable/enumerable; slugs are `slugify(title)-Date.now()`, and 404-vs-200 is an existence oracle).
- No authentication of any kind. The exploit first uses an admin only to *create* the private course + member (the state a real deployment already has); the decisive read is fully anonymous.

## Request
See `request.http`: `GET /course/slug/<slug>` with **no Cookie header**.

## Response
`HTTP 200` with the full course object: `isPublished:false`, `type:"SELF_PACED"`, `status:"ACTIVE"`, plus `data.group.members[].profile.email` and the complete content tree. See `response.txt`.

## Observation
The anonymous GET returned an UNPUBLISHED, non-PUBLIC course and its member roster with email addresses (`admin@cvehunt.local`, `u_ce6534a6@cvehunt.local`). This matches the static finding exactly: the route (`apps/api/src/routes/course/course.ts:117`) has no auth middleware, and `getCourseWithRelations` (`packages/db/src/queries/course/course.ts:428-436`) filters only `status='ACTIVE'` — never `type='PUBLIC'` or `isPublished` — while selecting `profile.email` per group member (`:468-474`). The hardened public channel `/org-site/course/:slug` (`public-course.ts:129-131`) returns null unless `type='PUBLIC' && isPublished && status='ACTIVE'`; this legacy route enforces none of it.

## Side effects
- Read-only against the target. The exploit creates one draft course + one student per run (random suffixes); harmless orphans. No cleanup required.

## Research & references
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization; API3:2023 excessive data exposure.
- CWE-639 (authorization bypass through user-controlled key) + CWE-200 (exposure of sensitive information).

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.
