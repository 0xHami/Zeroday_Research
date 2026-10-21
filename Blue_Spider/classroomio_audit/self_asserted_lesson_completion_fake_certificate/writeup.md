# VULN-035 — Client-asserted lesson completion → self-issued certificate / fake compliance

| | |
|---|---|
| **ID** | VULN-035 (raw F-22) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.3** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any enrolled STUDENT |
| **What an attacker gains** | A genuine certificate / satisfied compliance record with zero real work |

## Summary

Lesson completion is written from a **client-supplied `isComplete`**, with the only server
guard being a refusal when the lesson's policy is `video_watch`. Course progress is computed
directly from these self-declared rows, and once progress meets the threshold (default 100%)
and there is no required graded exercise, the server **self-issues the certificate** by stamping
`groupmember.certificateEarnedAt`. Confirmed live: a student marked two lessons complete
(`{"isComplete":true}`), progress hit 100%, `eligibleForCertificate` became true, and
`certificateEarnedAt` was stamped in the DB — no exercises submitted, no video watched.

## How it works (mechanism & code trace)

**Completion write — `packages/core/src/services/lesson/lesson.ts:412-433`.** The body value is
trusted verbatim:

```ts
export async function upsertLessonCompletionService(lessonId, profileId, isComplete: boolean) {
  const lesson = await getLessonById(lessonId);
  if (!lesson) throw new AppError('Lesson not found', ..., 404);
  if (lesson.completionPolicy === 'video_watch' && isComplete) {
    throw new AppError('This lesson completes automatically ...', ..., 400);   // ONLY guard
  }
  const completionData: TNewLessonCompletion = { lessonId, profileId, isComplete };   // <- client value trusted
  return await upsertLessonCompletion(completionData);
}
```

**Route — `apps/api/src/routes/course/lesson.ts:275-308`.** After writing, it fires the
certification evaluation:

```ts
const completion = await upsertLessonCompletionService(lessonId, user.id, isComplete);
if (isComplete) void evaluateCourseCertification(courseId, user.id).catch(...);
```

**Progress from self-declared rows — `apps/api/src/utils/course-completion.ts:11-24`.**

```ts
const totalItems = params.totalLessons + params.exercisesCount;
const completedItems = params.lessonsCompleted + params.exercisesCompleted;  // lessonsCompleted = self-declared rows
return Math.round((completedItems / totalItems) * 100);
```

**Self-issue — `apps/api/src/services/course/completion.ts:195-237`.** Eligibility needs only
threshold + content + deadline + (absent) final-exercise rule, then the certificate is claimed:

```ts
const eligibleForCertificate = !!progress.groupMemberId && meetsThreshold && hasContent && withinDeadline && finalEval.meetsFinalExerciseRule;
...
if (evaluation.eligibleForCertificate && !certificateEarnedAt && progress.groupMemberId) {
  if (await orgHasCertificatesEnabled(courseRow.orgId)) {
    const earnedAt = new Date().toISOString();
    await claimMemberCertificateEarned(progress.groupMemberId, earnedAt);   // <- certificate granted from self-declared progress
  }
}
```

**Why the framework doesn't save it.** `evaluateFinalExerciseRule` returns
`{ meetsFinalExerciseRule: true }` whenever `requiredExerciseId` is absent — the common case,
and true of the seeded COMPLIANCE courses. So for any lessons-only (or no-required-exercise)
course, self-declared completion alone reaches 100% and issues the certificate.

## Why it is a vulnerability

Completion is a client assertion rather than a server-verified event, and certification consumes
that self-declared progress directly. The integrity of the certificate — and of compliance
attestations built on it ("SOC 2", "HIPAA" training) — depends on completions being earned;
here any enrolled student manufactures them. The result is a genuine earned-certificate record
(`certificateEarnedAt`), not a cosmetic UI state.

## Reproduction

1. Admin creates course `C` (lessons, no required exercise), enables a downloadable certificate
   (`threshold:100`).
2. A student enrols in `C`.
3. Student `PUT /course/C/lesson/<L>/completion {"isComplete":true}` for each lesson → **200**.
4. Student `GET /course/C/certification-evaluation` → `progressPercent:100`,
   `eligibleForCertificate:true`, `certificateEarnedAt` set.
5. DB `groupmember.certificate_earned_at` for the student is non-null.
6. `./run.sh` → `[OK]`, exit 0.

(Environment: the local API runs in cloud mode, so the org was put on an active ENTERPRISE plan
to enable the certificate feature — see `notes.md`. Under the intended self-hosted mode this is
automatic.)

## Impact

- **Integrity (I:H):** fraudulent certificates and false compliance attestations without doing
  the work — directly defeats the compliance-training use case.
- **Chaining:** VULN-050 prints an **arbitrary name** on the resulting certificate → a
  valid-looking credential in anyone's name, earned by no one; VULN-007 covers courses that
  *do* gate on a graded exercise (forge the grade instead).

## Suggested fix

Derive completion server-side from verifiable signals — time-on-content, verified video-watch
progress, required-exercise pass — at least for compliance-flagged courses; do not trust a
client `isComplete`:

```ts
// upsertLessonCompletionService — reject client-asserted completion where a signal is required
if (isComplete && lessonRequiresVerifiedSignal(lesson)) {
  const earned = await hasMetCompletionSignal(lessonId, profileId, lesson);  // watch %, dwell time, exercise pass
  if (!earned) throw new AppError('Completion requirements not met', ErrorCodes.VALIDATION_ERROR, 400);
}
```

## References

- CWE-602 Client-Side Enforcement of Server-Side Security; CWE-807 Reliance on Untrusted Inputs
  in a Security Decision.
- OWASP API Security Top 10 — business-logic abuse; OWASP ASVS V1/V4 (server-side trust).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; none concerns lesson completion or certificates.
2. `classroomio github security advisory GHSA` — 9 GHSAs; none on completion/certificate integrity.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no match.
5. Issue tracker `"lesson completion" OR "mark as complete" OR isComplete OR "fake certificate" OR certificateEarnedAt OR certificate security` — 92 hits; #1365 (grading doesn't re-check certificate), #1368 (no certificate verification), #1326/#1327 (download plan check), #1395 (required content); none report client-asserted completion yielding a certificate.
6. Issue tracker `certificate OR "lesson completion" OR sanitize OR "stored XSS" OR community` — #1284 / #1317 add public-API recording of lesson completion (feature); none.
7. Commit search `"custom domain" OR "automation key" OR sanitize OR certificate OR PUBLIC_IS_SELFHOSTED` — b65d24d (#1327 paid plan required for certificate download), 5a8f50f ("certification rules"); no completion-integrity fix.
(Note: WebSearch quota exhausted after the general sweep; items 4–7 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- Issue #1365 (open, 2026-10-18) — certificate eligibility not re-evaluated after a submission is graded; an adjacent integrity gap in the opposite direction (earned but not issued).
- Issue #1368 (open) — no way to verify a certificate's authenticity; feature request.
- Issue #1326 / PR #1327 — certificate download lacked an org-plan check; authorization, not completion integrity.

**Reasoning:** Nothing public states that `upsertLessonCompletionService` trusts a client `isComplete` (guarded only for `video_watch`) and that `evaluateCourseCertification` stamps `certificateEarnedAt` from that self-declared progress. The public certificate discussion concerns re-evaluation, verification and plan gating. This is business-logic that the vendor may consider by design for non-compliance courses, and the class is easy to rediscover, so confidence is 75.
