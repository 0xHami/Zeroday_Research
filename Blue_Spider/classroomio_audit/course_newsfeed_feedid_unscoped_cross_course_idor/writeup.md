# VULN-027 — Course newsfeed item IDOR (read/react across courses)

| | |
|---|---|
| **ID** | VULN-027 (raw AC-1) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned, no tagged release |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.4** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any course member (STUDENT) to read/react; a course tutor to edit/delete |
| **What an attacker gains** | Read another course's (another tenant's, in cloud) newsfeed content, forge reactions, and — as a tutor — tamper with or delete other courses' announcements |

## Summary

The course newsfeed exposes get / react / edit / delete at
`/course/:courseId/newsfeed/:feedId`. Every handler is authorized against the path `:courseId` but
then operates on `:feedId` **without ever checking that the feed item belongs to that course**. So a
member of course Y can pass the `feedId` of an item in course X and read it or react to it; a tutor
of Y can edit or delete X's item. Confirmed live: a STUDENT enrolled only in course Y fetched a
confidential newsfeed item belonging to course X (the response's own `courseId` field is X, not the
path Y) and then forged a reaction on it.

## How it works (mechanism & code trace)

**Entry points — `apps/api/src/routes/course/newsfeed.ts:48-123`.** Read/react require only course
membership; edit/delete require team membership — all against the *path* course:

```ts
.get('/:feedId', authMiddleware, courseMemberMiddleware, ..., async (c) => {
    const { feedId } = c.req.valid('param');
    const feed = await getNewsfeedItem(feedId);                       // :51
    return c.json({ success: true, data: feed }, 200);
})
.put('/:feedId/react', authMiddleware, courseMemberMiddleware, ..., async (c) => {
    const { feedId } = c.req.valid('param');
    const { reaction } = c.req.valid('json');
    const feed = await updateNewsfeedReactionService(feedId, reaction);   // :106
```

`courseMemberMiddleware` verifies membership of the **path** `:courseId`; it says nothing about the
feed.

**Services — `apps/api/src/services/newsfeed/newsfeed.ts:74,140,171,201`.** Each keys on `feedId`
alone:

```ts
export async function getNewsfeedItem(feedId) { const feed = await getNewsfeedById(feedId); ... }         // :74
export async function updateNewsfeedService(feedId, data) { const updated = await updateNewsfeed(feedId, ...); }   // :140
export async function updateNewsfeedReactionService(feedId, reaction) { const updated = await updateNewsfeed(feedId, { reaction }); }  // :171
export async function deleteNewsfeedService(feedId) { const deleted = await deleteNewsfeed(feedId); }     // :201
```

`getNewsfeedById` / `updateNewsfeed` / `deleteNewsfeed` filter by the newsfeed id only — there is no
`courseId` predicate anywhere in the chain, so the URL course is never enforced against the item.

**Why the framework doesn't save it.** The route pattern makes it *look* course-scoped — the item is
nested under `/course/:courseId/…` — but the scope is never applied to the query. Compare the
newsfeed *comment thread* service (`getNewsfeedCommentThreadService`, `newsfeed.ts:263-272`), which
*does* check `root.courseNewsfeedId !== feedId` and rejects mismatches: the item-level handlers just
omit the equivalent `feed.courseId !== courseId` check.

## Why it is a vulnerability (reasoning)

The trust boundary is "a course's newsfeed is visible/modifiable only to that course's members/
staff." Authorization is anchored to the path course the caller *does* belong to, while the acted-on
object belongs to a different course. That is a classic IDOR: the object identifier is not
constrained to the authorization context. `feedId` is a UUID, but it is not a secret — the newsfeed
notification email embeds it as `?feedId=<uuid>` (`newsfeed.ts:432`), so recipients across courses
routinely hold valid ids. Impact is cross-course confidentiality (C:L — read announcements),
integrity (I:L — forge reactions, and tutor edits), and availability (A:L — tutor deletion); S:C
because it crosses the course/tenant authorization scope.

## Reproduction

Preconditions: target up. `./run.sh` provisions course X + a newsfeed item and a student in a
separate course Y.

1. Admin posts in course X: `POST /course/<X>/newsfeed {"courseId":"<X>","content":"CONFIDENTIAL …"}`
   → `201`, returns `feedX`.
2. As a student of course Y (not X): `GET /course/<Y>/newsfeed/<feedX>` → `200`, body `content` is
   X's confidential text and `courseId` = X.
3. Forge a reaction: `PUT /course/<Y>/newsfeed/<feedX>/react {"reaction":{"clap":["<me>","forged-…"],…}}`
   → `200`; DB `course_newsfeed[<feedX>].reaction` reflects it.
4. `./run.sh` → `[OK] exploit confirmed …`, exit 0. Transcript in `run.log`.

Observable proof: the returned item's `courseId` differs from the path course, and the DB reaction
of X's item is mutated by a non-member of X.

## Impact

- **Cross-course / cross-tenant read** of newsfeed announcements (may contain schedule, private
  cohort info, links) by any member of any one course.
- **Reaction forgery** on arbitrary items (this also compounds VULN-042's whole-object reaction
  write — the react body replaces the entire reaction object).
- **Tutor tampering/deletion:** a tutor of any course can `PUT`/`DELETE` another course's item,
  silently editing or removing announcements.
- Part of a systemic "authorize on the path id, act on an unscoped child id" family with VULN-006/
  007/013.

## Suggested fix

Scope every newsfeed operation to the item's own course. In each service, load the feed and compare:

```ts
const feed = await getNewsfeedById(feedId);
if (!feed || feed.courseId !== courseId) throw new AppError('Newsfeed item not found', ..., 404);
```
(Thread the route's `:courseId` into the service.) Keep edit/delete on `courseTeamMemberMiddleware`,
and derive the reacting user from the session rather than trusting a client reaction object
(see VULN-042).

## References
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization.
- CWE-639 Authorization Bypass Through User-Controlled Key; CWE-284 Improper Access Control.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; CVE-2026-111368 (submission routes) is the nearest; no newsfeed advisory.
2. `classroomio github security advisory GHSA` — 9 GHSAs; CVE-2026-111368 (submission) and CVE-2026-111369 (lesson) cover `/course/:courseId/{submission,lesson}/:id`, not `/newsfeed/:feedId`.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no newsfeed entry.
5. Issue tracker `newsfeed IDOR OR "newsfeed" authorization OR feedId OR "another course" OR "other courses" OR "cross-course"` — #1163 (cohort newsfeed public API), #1134 (cohort member scoping), #987 (org-admin newsfeed access); none report course newsfeed `feedId` unscoped to `courseId`.
6. Issue tracker `CORS OR "open redirect" OR "login link" OR newsfeed OR attendance` — 104 hits, feature noise; none.
7. Commit search `CORS OR redirect OR "login link" OR newsfeed OR attendance` — 117 commits; 3aaeba0 (#1163) and c5c984f (#987) inspected below.
8. Fetched PR #1163 (merged 2026-09-26) — its permissions table covers only cohort newsfeed middleware (`cohortNewsfeedCommentAuthorOrTeamMiddleware`); reviewer note concerns cohort comment deletion; `apps/api/src/routes/course/newsfeed.ts` / `feedId` are not mentioned.
9. Fetched PR #987 (merged 2026-09-04) — grants org admins course-newsfeed posting and requires live org membership for course access; no item-to-course scoping.
10. Fetched the hackmd writeup behind CVE-2026-111368/111369 — lists reviewed routers; newsfeed is not among them.
(Note: WebSearch quota exhausted after the general sweep; items 4–10 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-111368 / GHSA-j6jm-jc5p-v7pp and CVE-2026-111369 / GHSA-qg24-w69h-hf3v — identical "path courseId authorized, child id unscoped" pattern on submission/lesson routers; different routes and sinks.
- PR #1163 — tightened authorization on the cohort newsfeed (a different router).
- PR #1134 — cohort member mutation scoping.

**Reasoning:** No public record names the course newsfeed item handlers (`getNewsfeedItem`, `updateNewsfeedReactionService`, `updateNewsfeedService`, `deleteNewsfeedService`) or a `feed.courseId !== courseId` gap. The two Oct-2026 CVEs are the same root-cause family and their author explicitly listed the routers examined without newsfeed, and the recent cohort-newsfeed hardening (#1163) did not touch the course router. Because this scoping class is systemic and actively being reported/fixed in this codebase, confidence is held at 75.
