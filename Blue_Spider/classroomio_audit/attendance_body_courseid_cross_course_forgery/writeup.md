# VULN-020 — Attendance forgery via trusted body params

| | |
|---|---|
| **ID** | VULN-020 (raw AC-2) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 6.5** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Low — any member (STUDENT) of **one** course |
| **What an attacker gains** | Create/overwrite attendance records for arbitrary students in arbitrary courses (cross-course; cross-tenant in cloud) |

## Summary

`POST /course/:courseId/attendance` authorizes the caller against the **path** `:courseId`, but the handler ignores the path and writes the **body** `courseId`/`lessonId`/`studentId` verbatim. A member of one course can therefore forge or overwrite any student's attendance in any other course. Confirmed live: a STUDENT of course A posted a body naming course B and a victim's `groupmember` id, and a `group_attendance` row was written for course B (verified in Postgres) though the attacker has no role there.

## How it works (mechanism & code trace)

**Entry — `apps/api/src/routes/course/attendance.ts:9-24`.** The gate is on the path; the body is forwarded whole:

```ts
export const attendanceRouter = new Hono().post(
  '/', authMiddleware, courseMemberMiddleware, zValidator('json', ZAttendanceUpsert),
  async (c) => {
    const data = c.req.valid('json');                  // { courseId, lessonId, studentId, isPresent }
    const attendance = await upsertAttendanceService(data);   // path :courseId never consulted
    return c.json({ success: true, data: attendance }, 201);
```

`courseMemberMiddleware` (`apps/api/src/middlewares/course-member.ts:26,38`) reads `courseId` from `c.req.param('courseId')` and checks `isUserCourseMemberOrOrgAdmin(courseId, user.id)` — i.e. it validates only the **path** course.

**Hop — `apps/api/src/services/attendance/attendance.ts:29-38`.** The service copies the body identifiers directly:

```ts
const attendanceData: TNewGroupAttendance = {
  courseId: data.courseId, lessonId: data.lessonId,
  studentId: data.studentId, isPresent: data.isPresent
};
return await upsertAttendance(attendanceData);
```

**Sink — `packages/db/src/queries/attendance/attendance.ts:65-91`** looks up `(data.courseId, data.lessonId, data.studentId)` and inserts/updates `group_attendance` with those values. Schema (live): `group_attendance.student_id` is a FK to `groupmember(id)`, `course_id` a FK to `course(id)`, and `lesson_id` is `uuid NOT NULL` with **no** FK.

**Why the framework doesn't save it.** `ZAttendanceUpsert` (`packages/utils/src/validation/attendance/*.ts`) validates types only. Nothing checks `data.courseId === c.req.param('courseId')`, that the lesson belongs to that course, or that the actor may mark that student. The *authorization object* (path course) and the *mutation object* (body identifiers) are fully decoupled.

## Why it is a vulnerability

Attendance may legitimately be set only by course staff, only for their course's lessons and students. Here any course member writes attendance for a student in a course they have no role in — an integrity violation (`I:H`, `C:N`). It can falsify compliance/participation evidence, damage a target's record, or inflate the attacker's own.

## Reproduction

1. (Setup) Provision the attacker as a STUDENT of course A; provision a separate course B with a victim student. Resolve the victim's `groupmember.id` (FK target for `studentId`).
2. Decisive request (attacker's cookie; path = course A):
   ```
   POST /course/<A>/attendance
   { "courseId":"<B>", "lessonId":"<uuid>", "studentId":"<victim groupmember id>", "isPresent": false }
   ```
   → `HTTP 201`; `data.courseId == <B>`.
3. Ground truth (psql): before = 0 rows for `(B, victim, lesson)`; after = one row `is_present=f`.
4. `./run.sh` prints `before = 0`, the 201, `after = '1|f'`, and `[OK]`. See `run.log` / `response.txt`.

## Impact

- **Attendance integrity** across courses (and tenants in cloud): forge/overwrite any student's presence.
- **Chaining:** target `courseId`/`studentId`/roster identifiers come from VULN-016 (roster) and VULN-015 (analytics).

## Suggested fix

Derive the course from the path and validate the lesson/student against it (`apps/api/src/routes/course/attendance.ts`):

```diff
  async (c) => {
-   const data = c.req.valid('json');
-   const attendance = await upsertAttendanceService(data);
+   const courseId = c.req.param('courseId')!;                 // authorization object == mutation object
+   const { lessonId, studentId, isPresent } = c.req.valid('json');
+   // reject if lessonId does not belong to courseId, or studentId is not a groupmember of courseId,
+   // or the caller is not course staff authorized to mark that student.
+   const attendance = await upsertAttendanceService({ courseId, lessonId, studentId, isPresent });
    return c.json({ success: true, data: attendance }, 201);
```

Additionally require the actor to be course **staff** (team member), not merely a member, to set attendance.

## References

- OWASP API1:2023 (BOLA) and mass-assignment guidance. CWE-639 (authorization bypass through user-controlled key), CWE-915 (mass assignment).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — returned CVE-2025-65669/65670/65672/65675/65676/67259 and CVE-2026-111368; none concerns the attendance route.
2. `classroomio github security advisory GHSA` — 9 unreviewed GHSAs in the GitHub Advisory Database (submission IDOR, lesson IDOR, verification bypass, share/invite IDOR, SVG XSS, course deletion, URL-courseId leak); none mentions attendance.
3. `classroomio attendance IDOR courseId body authorization bypass` — closest hit is CVE-2026-111368 (submission PUT/DELETE routes); nothing on attendance or a body `courseId`.
4. `classroomio huntr vulnerability report` — no huntr/HackerOne reports; only the CVE mirrors above.
5. `classroomio "attendance" vulnerability OR IDOR OR forgery group_attendance` — no relevant results.
6. NVD keyword listing (`services.nvd.nist.gov ... keywordSearch=classroomio`) — 8 CVEs total (adds CVE-2026-111369 lesson routes); none on `group_attendance` / `POST /course/:courseId/attendance`.
7. Fetched hackmd writeup behind CVE-2026-111368/111369 (`@hieuPenguinnn/classroomio-course-resource-id-scoping-idor`) — enumerates the routers it reviewed (submission, lesson, plus payment-request/content/section/mark/members as not affected); attendance is not named.
8. Repo issue tracker search (`security OR vulnerability OR IDOR ...`) — issues #640/#643/#682/#685/#1204/#1068 cover dashboard analytics IDORs, domain mgmt authz, auto-join, rate limiting, javascript: URLs; none covers attendance.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-111368 / GHSA-j6jm-jc5p-v7pp — same "courseMemberMiddleware authorizes path course, handler acts on unscoped id" pattern, but on `apps/api/src/routes/course/submission.ts` (PUT/DELETE by submissionId), not attendance.
- CVE-2026-111369 / GHSA-qg24-w69h-hf3v — same pattern on `apps/api/src/routes/course/lesson.ts` (PUT/DELETE by lessonId); different route and sink.
- CVE-2025-65670 / GHSA-mh75-3225-9wcj — courseId manipulation in the old SvelteKit/Supabase dashboard URLs (read-only leak); different code path and no attendance write.

**Reasoning:** No public CVE, GHSA, advisory, or repo issue names the attendance route, the `upsertAttendance` sink, or the body-`courseId`/`studentId` decoupling. The two Oct-2026 Hono-API scoping CVEs are the nearest neighbours and the same root-cause family, but their own source writeup lists the routers reviewed and does not include attendance. Confidence is tempered because this authorization-scoping class is systemic in the project and the same researcher may hold further unpublished variants.
