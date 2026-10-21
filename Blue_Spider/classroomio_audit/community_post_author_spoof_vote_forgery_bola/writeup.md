# VULN-002 — Community forum BOLA: post & comment as any user, with forged votes

| | |
|---|---|
| **ID** | VULN-002 (raw F-11) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned, no tagged release |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Critical — **CVSS 3.1 9.6** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` (live single-org impact ≈ High) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any authenticated org member — a free, self-registered STUDENT |
| **What an attacker gains** | Publish community questions/comments **attributed to any other user** (impersonation), with **forged vote counts** on comments; in cloud, write into and read from arbitrary tenants, and wipe comment history by iterating a sequential id |

## Summary

The community forum's create paths decide *authorization* from the session + `cio-org-id` header,
but take the *data that establishes ownership* — `authorProfileId`, `organizationId`, `votes`,
`slug` — straight from the request body and insert it verbatim. Nothing binds `authorProfileId` to
the authenticated user. A self-registered STUDENT can therefore post a question or comment
**as any user id they choose** (e.g. the org ADMIN). Confirmed live: authenticated as a STUDENT
(`138b8a33-…`), a `POST /community` with `authorProfileId` set to the ADMIN (`0419cf7a-…`) produced
a forum post that the API and DB both attribute to the ADMIN, and a follow-up comment persisted with
an attacker-chosen `votes:9999` also attributed to the ADMIN.

## How it works (mechanism & code trace)

**Entry point — `apps/api/src/routes/community/community.ts:70-88`.** `POST /community` is gated by
`orgMemberMiddleware` (membership of the *header* org only) and forwards the body verbatim:

```ts
.post('/', authMiddleware, orgMemberMiddleware, zValidator('json', ZNewCommunityQuestion), async (c) => {
    const { title, body, courseId, organizationId, authorProfileId, votes, slug } = c.req.valid('json');
    const result = await createQuestion({ title, body, courseId, organizationId, authorProfileId, votes, slug });
    return c.json({ success: true, data: result }, 201);
```

The validator `ZNewCommunityQuestion` (`packages/utils/src/validation/community/community.ts:11-19`)
only checks the fields are non-empty strings — it does **not** constrain `authorProfileId` or
`organizationId` to the caller.

**Service — `apps/api/src/services/community.ts:102-123`.** The only check is *presence*, never
*ownership*:

```ts
export async function createQuestion({ title, body, courseId, organizationId, authorProfileId, votes, slug }) {
    if (!courseId || !organizationId || !authorProfileId) { throw new AppError('Missing required fields', ...); }
    const result = await createCommunityQuestion({ title, body, courseId, organizationId, authorProfileId, votes, slug });
```

`authorProfileId` is never compared to `c.get('user').id`, and `organizationId` is never compared to
`c.get('orgId')`.

**Sink — `packages/db/src/queries/community/community.ts:199-221`.** The insert writes the
attacker-supplied `authorProfileId`, `organizationId`, `slug` (with `votes` hardcoded to 0):

```ts
const result = await db.insert(communityQuestion).values({
    title, body, organizationId, authorProfileId, votes: 0, slug, courseId
}).returning();
```

`community_question.author_profile_id` is a FK to `profile.id`, and `profile.id` is itself a FK to
the auth `user.id` (`packages/db/src/schema.ts`, `profile_id_fkey`), so any real user's id is
accepted — including the ADMIN's.

**Comment path — `community.ts:120-144` → service `:162-185` → query `submitComment` `:133-155`.**
The comment insert honors the client `votes` verbatim:

```ts
// submitComment
const response = await db.insert(communityAnswer).values({ body, questionId, authorProfileId, votes }).returning();
```

So on the comment path both `authorProfileId` (impersonation) and `votes` (forgery) stick.

**Why the framework doesn't save it — the safe sibling proves it's a bug.** The *edit* and *delete*
routes for the same resource use `questionAuthorOrTeamMiddleware` (`community.ts:89-118`), which
resolves the question's own org/course and checks the caller is the author or a course team member.
The create and delete-comments routes simply omit that pattern.

## Why it is a vulnerability (reasoning)

The invariant that breaks is *"a user may only author content as themselves, within an org they
belong to."* Authorization is anchored to the session, but the persisted author is a free-form body
field. That is textbook Broken Object Level/Property Authorization: the server trusts a
client-supplied ownership key. The impact is integrity (impersonation, forged "official" posts,
forged engagement) and, in the multi-tenant build, confidentiality (cross-tenant reads) and
availability of discussion content (mass comment deletion over a guessable integer id). A skeptic
might note the question's `votes` is forced to 0 — true, and we report that precisely — but the
comment path *does* honor forged votes, and author spoofing lands on both, which is the core defect.

## Reproduction

Preconditions: target up; the manifest admin exists. `./run.sh` provisions its own STUDENT.

1. As a STUDENT, post a question naming the ADMIN as author:
   ```
   POST /community  (Cookie: STUDENT session; cio-org-id: <org>)
   { "slug":"notice_<rand>", "title":"OFFICIAL: ...", "body":"...",
     "courseId":"<student course>", "organizationId":"<org>",
     "authorProfileId":"0419cf7a-0f8b-4797-b953-e8747cc41939", "votes":9999 }
   ```
   → `201`.
2. Read it back: `GET /community/notice_<rand>` → `authorId` = the ADMIN, `authorFullname":"admin"`.
3. Forge a comment: `POST /community/<id>/comment {"body":"...","authorProfileId":"<ADMIN>","votes":9999}`
   → `201`, persisted with `votes=9999` attributed to the ADMIN.
4. `./run.sh` → `[OK] exploit confirmed …` and exit 0. Transcript in `run.log`; decisive
   request/response in `request.http` / `response.txt`.

Observable proof: DB `community_question.author_profile_id` equals the ADMIN's id while the creating
session was the STUDENT; `community_answer.votes = 9999` for the forged comment.

## Impact

- **Impersonation:** post "official" instructions, scams, or defamatory content attributed to staff
  or any peer — highly effective phishing inside a trusted LMS forum.
- **Forged engagement:** arbitrary `votes` on comments distort ranking/credibility.
- **Chaining:** combines with VULN-018 (mint the STUDENT session unauthenticated) and VULN-031 (the
  same write stores raw HTML). The sequential `community_question.id` (observed `id=1` on a fresh DB)
  makes the sibling `DELETE /:questionId/comments` a reliable enumerate-and-wipe primitive.
- **Cloud:** a foreign `organizationId` writes into another tenant, and `GET /:slug` reads any
  tenant's private forum + author PII (S:C / C:H drives the 9.6).

## Suggested fix

In `apps/api/src/routes/community/community.ts` / `services/community.ts`, derive ownership
server-side and stop trusting the body:

```ts
// createQuestion / createComment
const authorProfileId = c.get('user')!.id;      // never from body
const organizationId  = c.get('orgId')!;        // never from body
// drop authorProfileId/organizationId/votes from ZNewCommunityQuestion & ZCommunityComment
// hardcode votes: 0 on the comment insert too (the question insert already does)
```
Scope `GET /:slug`, `GET /?orgId=`, and `DELETE /:questionId/comments` by the resource's own org
(join question→course→org and require the caller's membership), matching the existing
`questionAuthorOrTeamMiddleware`.

## References
- OWASP API Security Top 10 — API1:2023 (BOLA), API3:2023 (Broken Object Property Level Authorization / mass assignment).
- CWE-639 Authorization Bypass Through User-Controlled Key; CWE-915 Improperly Controlled Modification of Object Attributes.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — only CVE-2025-65669/65670/65672/65675/65676/67259/67298 (v0.1.13–0.2.6, Supabase/PostgREST era) and CVE-2026-111368/111369 (Hono submission + lesson routes); nothing on the community forum.
2. `classroomio GHSA security advisory github.com/advisories` — github.com/advisories?query=classroomio lists exactly 9 advisories (the set above); none concern community/forum routes. Repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no huntr/HackerOne/Snyk reports; same CVE set.
4. `classroomio community forum authorProfileId impersonation vulnerability post as any user` — no relevant results (unrelated Moodle CVE-2014-3617 and the known ClassroomIO CVEs only).
5. `classroomio community question mass assignment organizationId body vote forgery` — no relevant results.
6. `site:github.com/classroomio/classroomio/issues security authorization leak` + direct read of the repo issue list filtered for security/IDOR — no issue mentions community/forum posts, author spoofing or votes.
7. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor (the only public research on the Hono API) — covers submission + lesson routes only; no community coverage.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-111368 / CVE-2026-111369 (GHSA-j6jm-jc5p-v7pp, GHSA-qg24-w69h-hf3v) — resource-id-scoping IDORs in the submission and lesson routes of the same Hono API; different component (no community routes) and different root cause (unscoped target id vs. body-supplied ownership fields here).
- CVE-2025-65670 / CVE-2025-65672 — course-id IDORs in the pre-1.0 Supabase/PostgREST stack; unrelated code path.

**Reasoning:** The complete public advisory set for ClassroomIO (9 GHSA entries, the VulnCheck advisories, the reporter's HackMD write-up and the repo issue tracker) contains nothing touching `apps/api/src/routes/community/community.ts` or the `authorProfileId`/`organizationId`/`votes` mass-assignment in `createQuestion`/`submitComment`. Authorization bugs are a very common class in this project and two related Hono-API IDORs were disclosed on 2026-10-15 by an active researcher, so a private report in flight cannot be excluded. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed; the project-wide sweeps enumerated every public ClassroomIO disclosure.
