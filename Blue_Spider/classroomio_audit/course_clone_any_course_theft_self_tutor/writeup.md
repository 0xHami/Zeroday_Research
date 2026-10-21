# VULN-005 — Course clone: cross-course theft (content + answer keys) + self-granted TUTOR

| | |
|---|---|
| **ID** | VULN-005 (raw F-12) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned, no tagged release |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 8.5** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any org member — a plain STUDENT with no relationship to the source course |
| **What an attacker gains** | A full copy of any course's content **and exercise answer keys**, plus a self-granted TUTOR role on the copy; cross-tenant content theft in cloud |

## Summary

`POST /course/:courseId/clone` deep-copies a course. It is gated by `orgMemberMiddleware`,
which admits **any role** (including STUDENT) and only proves the caller is *some* member of
the header org. `cloneCourse` then loads the **source** course by id with **no**
ownership/membership check, copies its sections/lessons/exercises/questions/options —
answer keys (`isCorrect`) included — into the **body-supplied** `organizationId`, and inserts
the caller as **TUTOR** of the new group. A STUDENT can therefore steal any course they can
name. Confirmed live: a STUDENT with zero membership of a victim course cloned it and ended
up TUTOR of a copy that contained the victim's lesson and its correct-answer option.

## How it works (mechanism & code trace)

**Entry — `apps/api/src/routes/course/course.ts:593-621`.** The gate is `orgMemberMiddleware`
(any role), and all four content-shaping values come from the request:

```ts
.post(
  '/:courseId/clone',
  authMiddleware,
  orgMemberMiddleware,                                  // admits STUDENT; only proves membership of the header org
  zValidator('param', ZCourseCloneParam),
  zValidator('json', ZCourseClone),
  async (c) => {
    const { courseId } = c.req.valid('param');          // SOURCE course — attacker-chosen
    const { title, description, slug, organizationId } = c.req.valid('json');  // DEST org — attacker-chosen
    const user = c.get('user')!;
    const newCourse = await cloneCourse(courseId, title, user.id, description, slug, organizationId);
    return c.json({ success: true, course: newCourse }, 200);
  }
)
```

`ZCourseClone` (`packages/utils/src/validation/course/course.ts:14-19`) requires only
`title`/`slug`/`organizationId` strings — nothing tying the source or destination to the caller.

**Sink — `apps/api/src/services/course/clone.ts:204-250`.** The source is loaded with no
authorization, the destination group is created in the body org, and the caller is made TUTOR:

```ts
export async function cloneCourse(courseId, newTitle, userId, newDescription?, newSlug?, organizationId?) {
  const [course] = await getCourseById(courseId);                       // :213  ← NO ownership/membership check
  const [newGroup] = await createGroup({
    name: newTitle, description: newDescription ?? course.description,
    organizationId: organizationId                                      // :219  ← destination org from the BODY
  });
  const [newCourse] = await createCourse({ /* copies title, overview, cost, certificate, … */ });
  await addGroupMember({ profileId: userId, email: '', groupId: newGroup.id, roleId: ROLE.TUTOR });  // :245-250 self-TUTOR
  const oldSections = await getCourseSectionsByCourseId(courseId);      // copies structure…
  const oldLessons  = await getLessonsByCourseId(courseId);
  await createLessons(oldLessons.map(…));
  await cloneLessonLanguages(newLessons, oldLessons);
  await cloneExercises(newLessons, oldLessons);                         // :298  ← copies exercises…
  return newCourse;
}
```

**Answer-key copy — `apps/api/src/services/course/clone.ts:185-201`.** `cloneExercises`
re-inserts every option, carrying `isCorrect` verbatim:

```ts
await createOptions(
  oldOptions.map((option) => {
    const newQuestionId = questionIdMap.get(option.questionId);
    if (newQuestionId === undefined) return null;
    return { value: option.value, label: option.label,
             isCorrect: option.isCorrect,                               // ← correct answer copied into the clone
             settings: option.settings, questionId: newQuestionId };
  }).filter((opt) => opt !== null)
);
```

**Why the framework doesn't save it.** Two decoupled identifiers are each left
unauthorized: the **source** `:courseId` is read with no `courseMemberMiddleware` /
`getCourseOrganizationId` check, and the **destination** `organizationId` is taken from the
body instead of the authorized `c.get('orgId')`. `orgMemberMiddleware` proves neither — only
that the caller is *some* member of the header org. The sibling
`/:courseId/download/content` route (two lines above) uses `courseMemberMiddleware`, so the
correct pattern was available and simply not applied here.

## Why it is a vulnerability

- **Confidentiality (C:H):** the clone is a full, readable copy of the source's content
  *and* its exercise answer keys (`isCorrect`). A student obtains the correct answers to
  graded exercises — defeating assessment integrity — and the entire course material,
  regardless of any relationship to the source.
- **Integrity / privilege (I:L, S:C):** the caller self-grants a TUTOR role on the new
  group, and writes a resource into an org scope on the basis of a body value rather than
  their authorization. Cross-tenant in cloud (steal another org's paid course into your own).

The theft is not hypothetical read-through: it materializes a new course the attacker fully
controls (as TUTOR), so the stolen content and answer keys persist under their ownership.

## Reproduction

Preconditions: target up; a STUDENT session; a target `courseId`. Org id
`48bbdff8-2ad5-46a3-a259-2ca3d52677dd`.

1. (Setup) An admin course X has a lesson `SECRET-LESSON-<rand>` and a graded exercise whose
   correct option is labelled `CORRECT-ANSWER-<rand>` (`isCorrect=true`).
2. As a STUDENT who is **not** a member of X:
   ```
   POST http://localhost:21527/course/<X>/clone
   cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
   Content-Type: application/json

   {"title":"Stolen","slug":"stolen-<rand>","organizationId":"48bbdff8-2ad5-46a3-a259-2ca3d52677dd"}
   ```
   → `HTTP 200`, `course.id` = the clone.
3. Confirm in Postgres (clone = `<newId>`, its `group_id` = `<g>`):
   - `select role_id from groupmember where group_id='<g>' and profile_id='<student>';` → `2` (TUTOR).
   - `select count(*) from lesson where course_id='<newId>' and title='SECRET-LESSON-<rand>';` → `1`.
   - answer key: join `option→question→exercise→lesson` on `course_id='<newId>'` and
     `label='CORRECT-ANSWER-<rand>'` → `is_correct = t`.
4. Automated: `./run.sh` → `[OK]`, exit 0; `run.log` shows all three proofs.

## Impact

- **Intellectual-property theft:** full course content copied into an org the attacker
  controls; cross-tenant in cloud (another tenant's paid course).
- **Assessment-integrity compromise:** exercise answer keys (`isCorrect`) are copied, so a
  student learns every correct answer — and can also chain to VULN-006 to rewrite the
  original exercise once they hold content-write access.
- **Privilege gain:** self-granted TUTOR on the clone; combined with VULN-006 this is
  full content control over the copied course.
- **Blast radius:** any course whose uuid the attacker can enumerate (leaked via the
  unauthenticated catalog reads).

## Suggested fix

`apps/api/src/routes/course/course.ts` + `services/course/clone.ts`:

1. Require the caller to be a **team member of the source course** — reuse
   `courseTeamMemberMiddleware`, or verify `getCourseOrganizationId(courseId)` equals the
   caller's authorized org before cloning.
2. Bind the destination `organizationId = c.get('orgId')` and drop it from `ZCourseClone`.
3. Reconsider unconditionally granting the cloner TUTOR — inherit the caller's role, or
   require tutor/admin to clone.

## References

- OWASP API Security Top 10 2023 — API1:2023 Broken Object Level Authorization; API3:2023
  Broken Object Property Level Authorization.
- CWE-639 Authorization Bypass Through User-Controlled Key; CWE-269 Improper Privilege
  Management.
- In-repo positive control: `/:courseId/download/content` (`courseMemberMiddleware`) in the
  same router.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 82 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — only the 9 known ClassroomIO CVEs; none mention course cloning.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; none concern `/course/:courseId/clone`; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio course clone vulnerability IDOR "clone" answer keys tutor` — nothing on clone/answer keys; closest hit is CVE-2026-111368 (submission IDOR).
5. `classroomio "clone" course endpoint student copy course without permission` — no clone-related results; only the known course-level IDOR CVEs.
6. Direct read of the repo issue list filtered for security — no issue mentions cloning or answer-key exposure.
7. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — covers submission/lesson routes only; no clone route.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-111369 (GHSA-qg24-w69h-hf3v) — lesson PUT/DELETE in the same `course` router, authorized by `courseMemberMiddleware`; different route and different defect (unscoped lesson id vs. unauthorized source course read + body-chosen destination org + self-TUTOR here).
- CVE-2025-65670 / CVE-2025-65669 — course-id IDOR / unauthorized course deletion in the pre-1.0 Supabase stack; unrelated code path.

**Reasoning:** No public reference mentions `POST /course/:courseId/clone` (`apps/api/src/routes/course/course.ts`) or `cloneCourse` (`apps/api/src/services/course/clone.ts`), the missing source-course ownership check, the body-supplied destination `organizationId`, or the answer-key (`isCorrect`) copy. Course-level authorization bugs are a recurring, actively researched class in this project, so confidence is tempered. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
