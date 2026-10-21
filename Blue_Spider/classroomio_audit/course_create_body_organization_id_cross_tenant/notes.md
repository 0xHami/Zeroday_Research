# VULN-023 — Course create writes body `organizationId` (cross-tenant course injection)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED (live cross-tenant injection into a foreign org observed here)
**Severity (static)**: Medium (High in cloud) — CVSS 3.1 6.5 `AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:N`
**Validated at**: 2026-09-27

## Preconditions
- Org ADMIN of the header org (manifest admin). A second org must exist to land a cross-tenant write; this instance had a foreign org (`f0259e1a…`) the admin is **not** a member of.

## Request
See `request.http`. Test A: `POST /course` header org = mine, body `organizationId` = random uuid. Contrast: header org = random uuid. Test B: header org = mine, body `organizationId` = foreign org.

## Response
- Test A → **500** `{"error":"Failed to create course","code":"INTERNAL_ERROR"}` (FK on `group.organization_id`; **not** 400/403).
- Contrast (bogus header) → **403** `ORG_TEAM_NOT_AUTHORIZED`.
- Test B → **201**; the created `group.organization_id` == `f0259e1a…` (the foreign org). Admin membership rows in that org = 0.

## Observation
`POST /course` is authorized by `orgAdminMiddleware` against the **header** org (`apps/api/src/middlewares/org-admin.ts:28-43`) but `createCourse` builds the group from the **body** `organizationId` (`packages/core/src/services/course/course.ts:294-300`), and `ZCourseCreate.organizationId = z.string().min(1)` (`packages/utils/src/validation/course/course.ts:308`) is never compared to the authorized org. Test A shows a mismatched body org passes validation + authz and reaches the DB (only the FK stops a bogus id). Test B shows that when the body org is a **real** other tenant, the course + group are injected there (HTTP 201, `group.organization_id` = the foreign org) — a live cross-tenant write by a non-member. The contrast confirms authorization is anchored to the header, not the write target.

## Side effects
Test A created no row (FK abort). Test B injected one course + group into the foreign org; the exploit **deletes** them (course_newsfeed, groupmember, course, group) after verifying; post-run the foreign org has 0 groups.

## Research & references
- CWE-639 IDOR / CWE-915 mass-assignment (destination scope from client body).
- Correct fix pattern: bind `organizationId = c.get('orgId')` and drop it from the schema. Shares the destination-org root with VULN-005 (course clone).

## If FAILED
n/a — CONFIRMED here.

## If NEEDS_MANUAL
On a single-org install with no second org, only Test A (validation/authz accept the mismatch; FK blocks a bogus id) is demonstrable; the cross-tenant landing needs a co-tenant org id (any real second `organization.id`), as shown here with `f0259e1a…`.
