# VULN-013 — Lesson-comment edit/delete IDOR via a sequential integer id

| | |
|---|---|
| **ID** | VULN-013 (raw AC-3) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned, no tagged release |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 8.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:L` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any course member — a self-enrolled STUDENT of *one* course |
| **What an attacker gains** | Edit (put words in a victim's mouth) or delete **any** lesson comment platform-wide by iterating a small integer id — cross-course, and cross-tenant in cloud |

## Summary

Lesson comments are edited and deleted by a numeric id through
`PUT`/`DELETE /course/:courseId/lesson/comment/:commentId`. The routes are authorized only against
the path `:courseId` (via `courseMemberMiddleware`), while the operation targets a `commentId` that
is never reconciled with that course and never checked for authorship. Because `lesson_comment.id`
is a sequential bigint starting at 1, any member of *any single* course can enumerate ids and edit
or delete every lesson comment on the platform. Confirmed live: student B, enrolled only in course
Y, edited then deleted student A's comment (`id=1`) that belongs to course X, which B is not a
member of.

## How it works (mechanism & code trace)

**Entry point — `apps/api/src/routes/course/lesson.ts:222-255`.** Both routes carry only
`authMiddleware` + `courseMemberMiddleware` and validate `commentId` as a string:

```ts
.put('/comment/:commentId', authMiddleware, courseMemberMiddleware,
     zValidator('param', ZLessonCommentGetParam), zValidator('json', ZLessonCommentUpdate),
  async (c) => {
    const { commentId } = c.req.valid('param');
    const { comment } = c.req.valid('json');
    const updated = await updateLessonCommentService(Number(commentId), comment);   // :232
    ...
.delete('/comment/:commentId', authMiddleware, courseMemberMiddleware,
        zValidator('param', ZLessonCommentGetParam),
  async (c) => {
    const { commentId } = c.req.valid('param');
    const comment = await deleteLessonCommentService(Number(commentId));            // :248
```

`courseMemberMiddleware` (`apps/api/src/middlewares/course-member.ts:38`) checks
`isUserCourseMemberOrOrgAdmin(courseId, user.id)` — membership of the **path** course, nothing about
the comment.

**Service — `packages/core/src/services/lesson/lesson.ts:334-383`.** No author check, no course
scoping. The only precondition is a feature-flag check:

```ts
export async function updateLessonCommentService(commentId: number, comment: string) {
  await assertLessonCommentsEnabledForComment(commentId);                 // flags only
  const updated = await updateLessonComment(commentId, sanitizeHtml(comment));   // by bare id
  ...
export async function deleteLessonCommentService(commentId: number) {
  await assertLessonCommentsEnabledForComment(commentId);                 // flags only
  const deleted = await deleteLessonComment(commentId);                   // by bare id
```

**The guard checks flags, not identity — `lesson.ts:235-248`:**

```ts
async function assertLessonCommentsEnabledForComment(commentId: number) {
  const availability = await getLessonCommentsAvailabilityByCommentId(commentId);
  if (!availability) { throw new AppError('Comment not found', ..., 404); }
  if (!availability.organizationCommentsEnabled || !availability.courseCommentsEnabled ||
      !availability.lessonCommentsEnabled) { throw new AppError('Comments are disabled…', ..., 403); }
}
```

It resolves the comment's org/course purely to read three booleans — never to compare against the
URL course or the caller.

**Enumerable key — `packages/db/src/schema.ts:543-553`:**

```ts
export const lessonComment = pgTable('lesson_comment', {
  id: bigint({ mode: 'number' }).primaryKey().generatedByDefaultAsIdentity({
    name: 'lesson_comment_id_seq', startWith: 1, increment: 1, minValue: 1, cache: 1 }),
  ...
```

We observed the first comment created received `id=1`, so `commentId = 1, 2, 3, …` sweeps the table.

**Why the framework doesn't save it.** The update/delete queries (`updateLessonComment` /
`deleteLessonComment`) filter on `id` alone — no org or course predicate — so even a correct
`:courseId` in the URL is decorative. The route trusts that membership of *some* course implies the
right to touch *this* comment.

## Why it is a vulnerability (reasoning)

The authorization object (the path course, checked for membership) is decoupled from the target
object (the comment), and no ownership relation is ever established between them. A plain student of
one course can mutate comments that belong to courses — and, in cloud, tenants — they have no
relationship with. The guessable integer key removes the only friction (needing a leaked id) that
UUID-keyed IDORs have, turning this into an unattended platform-wide sweep. Integrity (edit/forge)
and availability (bulk delete of discussion) are both affected; confidentiality is N because
comments are already visible to members.

## Reproduction

Preconditions: target up; org "comments" app enabled (already true here). `./run.sh` provisions
course X + lesson, student A in X, and student B in a separate course Y.

1. Student A posts a comment in course X: `POST /course/<X>/lesson/<lesson>/comment {"lessonId":"<lesson>","comment":"..."}` → `201`, a low sequential id `<N>` (1 on a fresh DB).
2. Student B (member of course Y only) edits it via B's own course path:
   `PUT /course/<Y>/lesson/comment/<N> {"comment":"HACKED by student B ..."}` → `200`.
3. Student B deletes it: `DELETE /course/<Y>/lesson/comment/<N>` → `200`.
4. `./run.sh` → `[OK] exploit confirmed …`, exit 0. Transcript in `run.log`; `request.http` records the exact `<N>`.

Observable proof: DB `lesson_comment[<N>].comment` becomes B's text after the edit, and the row is
gone after the delete, while B has zero membership rows in course X.

## Impact

- **Mass vandalism:** iterate `commentId` to delete every lesson comment across all courses/tenants,
  destroying course discussion history unattended.
- **Targeted forgery:** rewrite a specific victim's comment to put words in their mouth (the text is
  sanitized against XSS by `sanitizeHtml`, but the authorship/integrity abuse stands).
- **Cross-tenant in cloud:** the queries have no org predicate, so a member of one tenant reaches
  comments in every tenant (S:C).
- **Lowest-effort IDOR in the set:** no leaked identifiers, no UUID guessing — a single free student
  account plus a counter.

## Suggested fix

In `updateLessonCommentService` / `deleteLessonCommentService`
(`packages/core/src/services/lesson/lesson.ts:334-383`), resolve the comment's own lesson→course and
enforce scope + authorship:

```ts
const meta = await getLessonCommentAuthorAndCourse(commentId);   // {authorGroupMemberId, courseId}
if (!meta) throw new AppError('Comment not found', ..., 404);
if (meta.courseId !== urlCourseId) throw new AppError('Not found', ..., 404);       // course scope
const isAuthor = meta.authorGroupMemberId === callerGroupMemberId;
if (!isAuthor && !(await isCourseTeamMemberOrOrgAdmin(meta.courseId, user.id)))     // author or team
  throw new AppError('Forbidden', ..., 403);
```
(Thread `courseId` + the caller from the route into the service.) Defence in depth: give
`lesson_comment` a non-sequential id to remove the enumeration primitive.

## References
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization.
- CWE-639 Authorization Bypass Through User-Controlled Key; CWE-284 Improper Access Control.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — 9 known ClassroomIO CVEs; CVE-2026-111369 (lesson routes) is the closest.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; none mention lesson comments; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio lesson comment edit delete IDOR commentId vulnerability` — no comment-related results; only CVE-2025-65670/65672.
5. Read VulnCheck + OSV records for CVE-2026-111369 — scope is PUT/DELETE `/:lessonId` (`apps/api/src/routes/course/lesson.ts` L107-152 at v1.0.0) and `course-member.ts`; the comment routes are not referenced.
6. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — explicitly covers submissions and lessons only; lesson comments are not mentioned.
7. Direct read of the repo issue list filtered for security — no issue mentions lesson comments.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-111369 (GHSA-qg24-w69h-hf3v) — same router file and same `courseMemberMiddleware` gate, but the target is the lesson row via `/:lessonId`; this finding targets `lesson_comment` rows via `/comment/:commentId` through `updateLessonCommentService`/`deleteLessonCommentService` in `packages/core`, with the additional author-check omission and sequential-integer enumeration.
- CVE-2026-111368 — submission-route IDOR, same pattern, different component.

**Reasoning:** No public reference names the lesson-comment edit/delete routes, the comment services, or the `lesson_comment` sequential id. However, the disclosed CVE-2026-111369 lives in the same router with the same middleware and the same "authorize on path course, mutate by bare id" pattern, so a vendor fix for that CVE could plausibly sweep in the comment routes, and the reporter may have additional unpublished findings. Treated as a near-miss, hence the reduced score. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
