# VULN-013 — Lesson-comment edit/delete IDOR via sequential integer id (cross-course)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: High — CVSS 3.1 8.1 (`AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:L`)
**Validated at**: 2026-09-27

## Preconditions
- Org "comments" app enabled (`organization.customization.apps.comments = true`) — already true on
  this instance; plus course + lesson comment flags (default `true`). This is a legitimate
  admin-owned feature toggle, not part of the vulnerability.
- Two self-registered STUDENTs: A enrolled in course X, B enrolled in a *different* course Y (B is
  NOT a member of X). Both created via the app's course share-link accept flow.

## Request
Decisive request (see `request.http`) — student B, a member of course Y only, deleting a comment
that lives in course X:
```
DELETE /course/<courseY>/lesson/comment/<N> HTTP/1.1
Host: localhost:21527
Cookie: classroomio.session_token=<STUDENT B session — member of course Y only>
```
where `<N>` is A's comment's low sequential id (see `request.http` for the exact value this run).
Also validated: `PUT /course/<courseY>/lesson/comment/<N>  {"comment":"HACKED by student B ..."}`.

## Response
`PUT` → **HTTP 200** (comment content replaced). `DELETE` → **HTTP 200** (comment removed). See
`response.txt` / `run.log`.

## Observation
- Student A created a lesson comment with a **low sequential bigint id** (id=1 on a fresh DB; the
  `lesson_comment_id_seq` increments by 1 per comment) — confirms the enumeration primitive.
- Ground truth: student B has **0** membership rows in course X (DB check), and B's org role is
  STUDENT (3) — B is a plain student of an unrelated course.
- After B's `PUT`, DB `lesson_comment[<N>].comment` = `"HACKED by student B <rand>"` (A's text
  overwritten). After B's `DELETE`, `select count(*) … where id=<N>` = `0` (row gone).
- The only server-side check before the mutation is `assertLessonCommentsEnabledForComment`, which
  inspects the three comment feature-flag booleans and **never** the caller or the URL course.

## Side effects
- Creates course X + a lesson + a comment, and course Y, per run (random suffixes). The comment is
  deleted by the exploit itself. Non-destructive to pre-existing data.

## Research & references
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization.
- CWE-639 Authorization Bypass Through User-Controlled Key; CWE-284 Improper Access Control.
- PortSwigger Web Security Academy — "Insecure direct object references": enumeration is trivial
  because the object key is a small incrementing integer.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. Cross-tenant reach in cloud is the same code path (the delete/update queries have no org
predicate at all); a single instance already demonstrates cross-course, which is the authorization
gap. Platform-wide sweep would iterate `commentId = 1..N`; the exploit deletes a single known id to
avoid destroying unrelated data.
