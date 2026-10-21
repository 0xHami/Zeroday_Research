**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 5.3)
**Validated at**: 2026-09-27

## Preconditions
- An enrolled STUDENT of a course that has lessons, a **non-`video_watch`** completion policy
  (the default), no `requiredExerciseId`, and certificates enabled.
- The course's certificate is made downloadable via `PUT /course/<C> {certificate:{isDownloadable:true,threshold:100}}` (admin).
- **Environment note (not part of the bug):** the running API process is in *cloud* mode
  (`PUBLIC_IS_SELFHOSTED` unset — a documented local-dev gotcha), so
  `orgHasCertificatesEnabled` requires the org to be on a non-BASIC plan, and the org had no
  active plan (default 20-student cap, also blocking enrolment after prior stage runs). To
  match the **intended self-hosted audit mode** (where certificates are always enabled and
  students unlimited), an `organization_plan` row `{plan_name:'ENTERPRISE', is_active:true}`
  was inserted for the org via psql. This only enables the certificate feature/lifts the seat
  cap; it does not touch the completion-trust logic under test. Under self-hosted
  (`PUBLIC_IS_SELFHOSTED=true`) no such change is needed — both gates are no-ops.

## Request
See `request.http`. Decisive requests:
```
PUT http://localhost:21527/course/<C>/lesson/<L>/completion
Content-Type: application/json
Cookie: classroomio.session_token=<attacker student session>

{"isComplete":true}          # repeated for every lesson
```
then
```
GET http://localhost:21527/course/<C>/certification-evaluation   # runs the claim synchronously
```

## Response
See `response.txt` / `run.log`.
- each completion PUT → `HTTP 200`
- certification-evaluation → `progressPercent=100, eligibleForCertificate=true, certificateEarnedAt="2026-09-27 08:13:17.417+00"`
- DB `groupmember.certificate_earned_at` for the attacker = `2026-09-27 08:13:17.417+00` (non-null).

## Observation
`upsertLessonCompletionService` (`lesson.ts:412-433`) writes the client-supplied `isComplete`
verbatim (only refusing `completionPolicy==='video_watch'`). Course progress is computed purely
from these self-declared `lesson_completion` rows (`course-completion.ts:11-24`), and
`evaluateCourseCertification` (`completion.ts:213-272`) stamps `groupmember.certificateEarnedAt`
once progress ≥ threshold with no `requiredExerciseId`. The attacker did zero real work (no
exercises, no video watched) yet holds a genuine earned-certificate record.

## Side effects
- Marks lessons complete and stamps `certificate_earned_at` on the attacker's fresh
  groupmember row (random course/user each run). No pre-existing data modified.

## Research & references
- CWE-602 Client-Side Enforcement of Server-Side Security; CWE-807 Reliance on Untrusted Inputs
  in a Security Decision.
- OWASP API Security — business-logic / BOLA-adjacent: completion is a security-relevant state
  that must be server-verified (time-on-content, required-exercise pass, verified watch).

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. (The certificate *download artifact* itself requires the Cloudflare render backend —
see VULN-050 — but the "certificate earned" state proven here is stamped server-side and needs
no rendering.)
