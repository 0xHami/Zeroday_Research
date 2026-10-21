# VULN-012 — Submission file-answer IDOR: presigned download minted for any client-supplied `fileKey`

| | |
|---|---|
| **ID** | VULN-012 (raw F-07) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 8.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any enrolled course member (STUDENT) on an exercise with a FILE_UPLOAD/VIDEO_RECORDING question |
| **What an attacker gains** | A working presigned download of any `documents`/`videos` object whose key is known — other users' uploads here, cross-tenant files in cloud |

## Summary

When a submission is rendered, the server mints a presigned **download** URL from the
`fileKey`/`storageKey` that was **copied verbatim from the client's submission payload**, with
no check that the key was ever issued to this user or belongs to their org. A student submits a
FILE_UPLOAD answer whose `fileKey` is an arbitrary storage object, reads the submissions
overview, and receives a signed GET for that object. Confirmed live: a student referenced a
seeded foreign-org key `documents/11111111-…/lecture-<rand>-payroll.pdf`, and the returned
`fileUrl` downloaded the exact secret bytes of that object (which they never uploaded).

## How it works (mechanism & code trace)

**Taint source — `packages/question-types/src/answer-codecs.ts:173-188`.** The FILE_UPLOAD
codec parses the client's answer JSON and returns `fileKey` unchanged:

```ts
fromApiPayload(payload) {
  if (!payload.answer) return null;
  const p = JSON.parse(payload.answer) as { fileKey: string; fileName?: string; ... };
  return { type: 'FILE_UPLOAD', fileKey: p.fileKey, fileName: p.fileName ?? '', ... };   // verbatim
}
```

**Persist — `apps/api/src/routes/course/exercise.ts:284-316` → `createSubmissionService`.** The
answer (with the attacker's `fileKey`) is stored as a `question_answer.answer_data` row.

**Sink — `apps/api/src/services/submission/submission.ts:175-206` (`enrichFileUploadAnswersArray`).**
When submissions are listed, the stored key is signed with no authorization:

```ts
const fileKeys = answers.map(a => a.answerData).filter(isFileUpload).map(d => d.fileKey);   // client-controlled
...
const [documentUrls] = await Promise.all([ generateDocumentDownloadPresignedUrls(fileKeys) ]);
return answers.map(answer =>
  isFileUpload(answer.answerData)
    ? { ...answer, answerData: { ...answer.answerData, fileUrl: documentUrls[answer.answerData.fileKey] } }
    : answer);
```

`generateDocumentDownloadPresignedUrls` (`packages/core/src/utils/s3.ts:55-129,190-193`) signs a
GET for whatever key it is handed, against the `documents` bucket.

**Reachable to the attacker — `apps/api/src/routes/course/exercise.ts:78-90`.** For a student,
`listExerciseSubmissionsOverview` returns their own submissions (`mySubmission`) with the
enriched `fileUrl` — so the attacker reads back their own answer's signed URL.

**Why the framework doesn't save it.** The dedicated presign routes DO call
`findUnauthorizedDownloadKeys` (`presign-auth.ts:58-87`), but that guard is never wired into the
submission path — and even it only enforces **org-level** ownership (per its own docstring),
which is a no-op in a single-org deployment. Submission-level authorization constrains *whether*
you may submit, never *which* storage key an answer may reference.

## Why it is a vulnerability

The presigned download key is derived entirely from attacker-controlled input and is never
validated against the object's owner/org or the submitting user. The trust boundary "a student
may only download files they were granted" collapses: any known key becomes a signed download.
Keys are `nanoid`-suffixed rather than sequential, but they circulate freely — to uploaders, to
every tutor of a course (in the grading overview JSON), and via the sibling object-storage
IDORs (VULN-011/016/019/033) — so a "known key" is a realistic precondition, and in cloud the
same key can belong to another tenant.

## Reproduction

1. Admin creates course `C` with an exercise `E` containing a FILE_UPLOAD question; a student
   enrols in `C`.
2. A victim object exists at `documents/<key>` (here seeded at a foreign org prefix).
3. Student `POST /course/C/exercise/E/submission` with
   `answers:[{questionId:q, answer:"{\"fileKey\":\"<victim key>\",\"fileName\":\"x.pdf\"}"}]` → **201**.
4. Student `GET /course/C/exercise/E/submissions` → `mySubmission[0].answers[].answerData.fileUrl`
   is a presigned GET for `<victim key>`.
5. Fetch `fileUrl` → **200**, the victim object's bytes.
6. `./run.sh` → `[OK]`, exit 0 (asserts the downloaded body equals the seeded secret).

## Impact

- **Confidentiality (C:H):** read any `documents`/`videos` object given its key — other
  students' uploaded submissions here, cross-tenant files in the multi-tenant cloud build.
- **Scope (S:C):** reads objects owned by other users/orgs.
- **Chaining:** part of the object-storage IDOR cluster (VULN-011 mints keys/exfil,
  VULN-019 covers HLS); key disclosure via VULN-016/033.

## Suggested fix

1. Validate every answer `fileKey`/`storageKey` at submit time (and before presigning): it must
   belong to the submission's org **and** have been issued to the submitting user.
   ```ts
   // createSubmissionService, per FILE_UPLOAD/VIDEO_RECORDING answer
   if (!(await keyIssuedToUser(fileKey, submittedByProfileId, courseOrgId))) {
     throw new AppError('Invalid file reference', ErrorCodes.FORBIDDEN, 403);
   }
   ```
2. Reuse/extend `findUnauthorizedDownloadKeys` on the submission render path, but make ownership
   **per-object** (record the uploader/owner of each key), so it is meaningful in single-org
   deployments.

## References

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization.
- CWE-639 Authorization Bypass Through User-Controlled Key.
- AWS S3 presigned URL guidance — never sign a client-named key without an ownership check.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — only the 9 known ClassroomIO CVEs; the only submission-related one is CVE-2026-111368 (write-side IDOR).
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; none about file keys or presigned URLs; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio submission fileKey presigned URL IDOR file upload answer vulnerability` — nothing on `fileKey`/presigning; only CVE-2026-111368 and the older course-id IDORs.
5. Direct read of the repo issue list filtered for security — #643 "submission permission bypass" concerns the old SvelteKit `/api/courses/submission` route (conditional `courseId` check), not answer file keys; #1266 is a cohort FILE_UPLOAD review UX issue.
6. Read VulnCheck/OSV records for CVE-2026-111368 and the HackMD report — scope is PUT/DELETE submission mutations by unscoped id; no mention of answer `fileKey`, `enrichFileUploadAnswersArray` or presigned downloads.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-111368 (GHSA-j6jm-jc5p-v7pp) — same submission service file, but a write-side IDOR on `:submissionId`; this finding is a read-side presign of a client-chosen storage key.
- GitHub issue classroomio/classroomio#643 — conditional authorization in the legacy dashboard submission route; different stack and defect.

**Reasoning:** No public reference describes the FILE_UPLOAD answer codec passing `fileKey` through verbatim or `enrichFileUploadAnswersArray` minting presigned GETs for it without ownership checks. The submission area has had recent public attention (CVE-2026-111368, issue #643), which lowers confidence somewhat, but both public items target different sinks. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
