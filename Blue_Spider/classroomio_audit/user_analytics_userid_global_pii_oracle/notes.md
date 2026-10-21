# VULN-015 — Arbitrary-user PII oracle via analytics endpoints

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: High — CVSS 3.1 7.7 `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
**Validated at**: 2026-09-27

## Preconditions
- A session that is a **team member of one org or course**: `orgTeamMemberMiddleware` admits ADMIN or TUTOR (`apps/api/src/middlewares/org-team-member.ts:44`); `courseTeamMemberMiddleware` admits any course team member or org admin. The exploit uses the manifest admin as the caller; a TUTOR (roleId 2) passes the identical gate. A plain STUDENT does **not** (verified: 403).
- A target `userId` (UUID). These leak liberally (course rosters via VULN-016, community authors, etc.).

## Request
See `request.http`: `GET /organization/audience/:userId/analytics` and `GET /course/:courseId/members/:userId/analytics`, with `:userId` = a victim that is NOT a member of the caller's org/course.

## Response
Both → `HTTP 200` with `data.user = { id, fullName, email, avatarUrl, lastSeen }`. See `response.txt`.

## Observation
Caller = admin (a legitimate team member of exactly one org/course). Target = a freshly-created account with `orgRoles == {}` (provably **not** a member of the org) and not enrolled in the caller's course. Both endpoints returned that account's exact email (`u_fb6cb3ef@cvehunt.local`). Root cause: both services call `getProfileById(userId)` — a global, unscoped lookup — and return the profile with no check that `:userId` belongs to the caller's org/course (`apps/api/src/services/organization.ts:1001,1083-1090`; `packages/core/src/services/course/course.ts:731,796-803`). The routes gate on team membership of the *authorization* scope but pass the raw path `:userId` (the *object*) straight through — a textbook BOLA.

**Negative control:** the same org request from a STUDENT session → `HTTP 403`, confirming the route *is* access-controlled; the defect is the unconstrained `:userId`, reachable by the lowest team role (TUTOR), not an open route. This is why using the admin as the caller still demonstrates the bug: the endpoint returns the PII of a user outside the scope it authorized against, which it must not, for any caller.

## Side effects
- Read-only. One course + one fresh victim account + one student (control) created per run (random suffixes); harmless orphans.

## Research & references
- OWASP API1:2023 Broken Object Level Authorization; CWE-639. Cross-tenant in cloud (global `getProfileById`).
- Chains: harvested emails feed VULN-024/032 (phishing); `userId`s sourced from VULN-016 rosters.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
- The **cross-tenant** dimension (resolving a userId belonging to a *different org* in a multi-org cloud deployment) needs cloud; the "arbitrary userId, no membership" defect is fully confirmed here against a non-member.
