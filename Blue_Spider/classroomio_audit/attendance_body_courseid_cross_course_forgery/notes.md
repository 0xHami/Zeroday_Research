# VULN-020 — Attendance forgery via trusted body courseId/lessonId/studentId

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Medium — CVSS 3.1 6.5 `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N`
**Validated at**: 2026-09-27

## Preconditions
- A session that is a member of **one** course A (any STUDENT qualifies — `courseMemberMiddleware` checks membership of the PATH course).
- Target identifiers for a different course B: `courseId` (B), a victim's `studentId` (a `groupmember.id`), and a `lessonId`. These leak via rosters/analytics (VULN-016/015). `student_id` is a FK to `groupmember(id)`; `lesson_id` has NO FK (any uuid is accepted).

## Request
See `request.http`: `POST /course/<A>/attendance` (path course A, which the caller belongs to) with a JSON body whose `courseId`/`lessonId`/`studentId` all belong to course B + the victim.

## Response
`HTTP 201` `{ success:true, data:{ id, courseId:"<B>", studentId:"<victim groupmember>", isPresent:false, ... } }`. See `response.txt`.

## Observation
Ground truth via psql: before the request there were **0** rows for `(course_id=B, student_id=<victim gm>, lesson_id=L)`; after, exactly one row exists with `is_present=f`. The attacker is a member of course A only and has no role in course B, yet forged the victim's attendance there. Root cause: `courseMemberMiddleware` authorizes on the PATH `:courseId` (`apps/api/src/routes/course/attendance.ts:9-13`), but the handler forwards the whole body (`:16-17`) to `upsertAttendanceService`, which copies `courseId`/`lessonId`/`studentId` verbatim (`apps/api/src/services/attendance/attendance.ts:31-38`). Nothing reconciles the body with the path — a decoupled authorization-object vs mutation-object IDOR / mass-assignment.

## Side effects
- **Writes one `group_attendance` row per run** (a fresh random `lesson_id`, so no collisions). To clean up: `docker exec cio-postgres psql -U postgres -d classroomio -c "delete from group_attendance where student_id in (select id from groupmember gm join \"group\" g on gm.group_id=g.id join course c on c.group_id=g.id where c.title like 'Victim Course %');"` (optional; harmless test rows).
- Also creates 2 courses + 2 students per run (random suffixes).

## Research & references
- OWASP API1:2023 BOLA / API6-style mass assignment; CWE-639 + CWE-915.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
- Cross-tenant forgery (course B in a different org) needs a multi-org cloud deployment; the cross-course forgery within reach of a single course membership is fully confirmed here.
