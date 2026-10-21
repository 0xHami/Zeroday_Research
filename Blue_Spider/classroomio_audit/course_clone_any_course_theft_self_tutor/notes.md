# VULN-005 — Course clone: steal any course (incl. answer keys) + self-grant TUTOR

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: High — CVSS 3.1 8.5 `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
**Validated at**: 2026-09-27

## Preconditions
- Any org member of any role — demonstrated with a plain STUDENT (roleId 3) who has **no**
  membership of the source course. `orgMemberMiddleware` does not gate by role.
- Knowledge of a target `courseId` (uuid; obtainable from the unauthenticated
  course/catalog reads, e.g. VULN-016/VULN-034).

## Request
See `request.http`. Decisive request (STUDENT session):
```
POST http://localhost:21527/course/<victim_course_uuid>/clone
cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
Content-Type: application/json

{"title":"Stolen","slug":"stolen-<rand>","organizationId":"48bbdff8-2ad5-46a3-a259-2ca3d52677dd"}
```

## Response
`HTTP 200 {"success":true,"course":{"id":"ca5ec8f2-…","title":"Stolen …", …}}`.
See `response.txt` / `run.log`.

## Observation
Setup: admin created a victim course X with a uniquely-named lesson
(`SECRET-LESSON-<rand>`) and a graded RADIO exercise whose correct option carried a unique
label (`CORRECT-ANSWER-<rand>`, `isCorrect=true`). A STUDENT with `groupmember` count `0` in
X's group cloned X. Confirmed against Postgres on the resulting clone:
- the attacker holds `groupmember.role_id = 2` (**TUTOR**) in the clone's group;
- the clone contains a lesson whose title equals X's `SECRET-LESSON-<rand>` (content theft);
- the clone contains an `option` with X's unique correct-answer label and `is_correct = t`
  (**answer-key theft** — `cloneExercises` copies `isCorrect` verbatim).

All three predicted effects — no source-ownership check, body-supplied destination org,
self-granted TUTOR, and answer-key copy — reproduced exactly.

## Side effects
- Creates one cloned course (group + sections/lessons/exercises/questions/options) per run
  and one `groupmember` TUTOR row for the attacker. Titles/labels carry random suffixes;
  rows are inert evidence in the test org.

## Research & references
- OWASP API Security Top 10 2023 — API1:2023 Broken Object Level Authorization (source
  `courseId` used with no ownership check); API3:2023 (mass-assigned destination `organizationId`).
- CWE-639 Authorization Bypass Through User-Controlled Key; CWE-269 Improper Privilege
  Management (self-granted TUTOR).
- **In-repo contrast:** the sibling `/:courseId/download/content` route two lines above the
  clone route uses `courseMemberMiddleware`; the clone route omits that existing pattern.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a for the within-org theft + self-TUTOR (fully automated and confirmed). The
**cross-tenant** consequence (cloning another tenant's paid course into the attacker's org
via the body `organizationId`) requires a second organization and is only reachable in
cloud/multi-tenant mode; the missing **source-ownership** check proven here is the same
root defect.
