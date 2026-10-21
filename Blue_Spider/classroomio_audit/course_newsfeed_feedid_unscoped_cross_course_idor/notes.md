# VULN-027 — Course newsfeed item IDOR (cross-course read + reaction forge)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Medium — CVSS 3.1 5.4 (`AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L`)
**Validated at**: 2026-09-27

## Preconditions
- One course X (created by the admin) with a newsfeed item authored in it.
- One self-registered STUDENT enrolled only in a *different* course Y (not a member of X).

## Request
Decisive request (see `request.http`) — a student of course Y reading course X's newsfeed item:
```
GET /course/<courseY>/newsfeed/<feedX> HTTP/1.1
Host: localhost:21527
cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
Cookie: classroomio.session_token=<STUDENT session — member of course Y only>
```
Also validated: `PUT /course/<courseY>/newsfeed/<feedX>/react  {"reaction":{"clap":[...],...}}`.

## Response
`GET` → **HTTP 200** returning course X's item — `content` carries the confidential marker and
`courseId` equals **X**, not the path course Y. `PUT .../react` → **HTTP 200**. See `response.txt`.

## Observation
- The student has **0** membership rows in course X (DB check) and org role STUDENT (3).
- `GET /course/<Y>/newsfeed/<feedX>` returned `content = "CONFIDENTIAL course-X announcement <marker>"`
  and `courseId = <X>` — the item is served despite the path naming a different course →
  **cross-course confidentiality**.
- After `PUT .../react`, DB `course_newsfeed[<feedX>].reaction` =
  `{"clap":["<student id>","forged-<rand>"], ...}` → the student mutated another course's item state.

## Side effects
- Creates course X + a newsfeed item and course Y per run (random suffixes). The reaction on feedX
  is overwritten (this is the demonstrated effect). Non-destructive to unrelated data.

## Research & references
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization.
- CWE-639 Authorization Bypass Through User-Controlled Key.
- The `feedId` is a UUID but leaks in practice: the newsfeed notification email links
  `…/courses/<courseId>?feedId=<uuid>` (`apps/api/src/services/newsfeed/newsfeed.ts:432`).

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
Tutor-only edit/delete of another course's item (`PUT`/`DELETE /:feedId`) is the same IDOR gated by
`courseTeamMemberMiddleware`; it requires the attacker to be a tutor of *some* course. Not exercised
here (the read + react by a plain student already proves the missing course scope on `feedId`), but
the code path is identical (`updateNewsfeedService`/`deleteNewsfeedService` key on `feedId` only).
