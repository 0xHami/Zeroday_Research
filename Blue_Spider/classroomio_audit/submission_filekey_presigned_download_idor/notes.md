**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 3.1 8.1)
**Validated at**: 2026-09-27

## Preconditions
- An enrolled STUDENT of a course whose exercise has a FILE_UPLOAD (or VIDEO_RECORDING) question
  (admin creates the course + exercise; the student is `make_student`'d into it).
- A known/guessable target object key in the `documents` (or `videos`) bucket. For the
  end-to-end proof a victim document is seeded into MinIO at a **foreign org prefix**
  (`documents/11111111-…/lecture-<rand>-payroll.pdf`) via the admin `mc` client — an object the
  attacker never uploaded and has no entitlement to.

## Request
See `request.http`. Two decisive requests:
```
POST http://localhost:21527/course/<C>/exercise/<E>/submission
Content-Type: application/json
cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
Cookie: classroomio.session_token=<attacker student session>

{"exerciseId":"<E>","answers":[{"questionId":<q>,
  "answer":"{\"fileKey\":\"11111111-…/lecture-<rand>-payroll.pdf\",\"fileName\":\"my-homework.pdf\"}"}]}
```
then
```
GET http://localhost:21527/course/<C>/exercise/<E>/submissions
→ data.mySubmission[0].answers[].answerData.fileUrl  (a presigned GET for the victim key)
```

## Response
See `response.txt` / `run.log`.
- submit → `HTTP 201`
- overview → `answerData.fileUrl = http://localhost:21528/documents/11111111-…/lecture-<rand>-payroll.pdf?X-Amz-…`
- fetch `fileUrl` → `HTTP 200`, 66 bytes = the exact seeded secret
  (`%PDF-1.4 CONFIDENTIAL-VICTIM-DOCUMENT <rand> do-not-share`).

## Observation
`enrichFileUploadAnswersArray` (`submission.ts:175-206`) takes `answerData.fileKey` **verbatim
from the client's own submission** and calls `generateDocumentDownloadPresignedUrls([fileKey])`,
signing a GET for whatever key it is handed with no check that the key belongs to the submitter
or the org. The FILE_UPLOAD codec (`answer-codecs.ts:173-188`) copies `p.fileKey` straight out
of `JSON.parse(payload.answer)`. The correct guard `findUnauthorizedDownloadKeys`
(`presign-auth.ts:58-87`) is wired only into the dedicated presign routes, never this path. The
attacker downloaded the exact bytes of an object under a different org's prefix that they never
uploaded.

## Side effects
- Creates one attacker submission per run (random suffix) and one seeded victim doc (random key).
  No pre-existing data modified.

## Research & references
- OWASP API1:2023 BOLA; CWE-639 IDOR (object-storage presign of a client-controlled key).
- Even the "correct" `findUnauthorizedDownloadKeys` enforces only **org-level** ownership
  (a no-op in a single-org deployment) — a full fix must be **per-object/per-submitter**.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.
