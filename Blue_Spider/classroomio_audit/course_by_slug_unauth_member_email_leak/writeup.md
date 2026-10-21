# VULN-016 — Unauthenticated `GET /course/slug/:slug` leaks any course + member emails

| | |
|---|---|
| **ID** | VULN-016 (raw F-36) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 7.5** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | **None** (fully unauthenticated) |
| **What an attacker gains** | The full content of any unpublished / private / in-development course, plus the **email address of every enrolled member** (students and tutors), by slug |

## Summary

The public "course by slug" endpoint has no authentication and no visibility gate. Its query filters only on `status='ACTIVE'`, which every course satisfies by default, so an anonymous caller who knows or guesses a slug receives the complete course object of a course that was never published — including the group member roster with each member's email. Confirmed live: an anonymous `GET /course/slug/<slug>` for an unpublished (`isPublished:false`, `type:"SELF_PACED"`) course returned HTTP 200 with `admin@cvehunt.local` and an enrolled student's email in `data.group.members[].profile.email`.

## How it works (mechanism & code trace)

**Entry — `apps/api/src/routes/course/course.ts:117-132`.** The route is registered with only a param validator; there is no `authMiddleware`, `orgMemberMiddleware`, or any gate:

```ts
.get('/slug/:slug', zValidator('param', ZCourseGetBySlugParam), async (c) => {
  const { slug } = c.req.valid('param');
  const course = await getCourse(undefined, slug);
  return c.json({ success: true, data: course }, 200);
})
```

**Hop — `packages/core/src/services/course/course.ts:212-218`.** `getCourse` forwards straight to `getCourseWithRelations`:

```ts
const course = await getCourseWithRelations(courseId, slug, profileId);
```

**Sink / defect — `packages/db/src/queries/course/course.ts:428-436`.** The only predicate is `status='ACTIVE'`:

```ts
const courseQuery = slug
  ? db.select().from(schema.course)
      .where(and(eq(schema.course.slug, slug), eq(schema.course.status, 'ACTIVE')))
  : ...
```

and the same function selects the member roster **with emails** and returns it as `group.members` (`:465-489`, `:502-507`):

```ts
profile: {
  id: schema.profile.id, fullname: schema.profile.fullname,
  username: schema.profile.username, avatarUrl: schema.profile.avatarUrl,
  email: schema.profile.email          // ← PII returned to an anonymous caller
}
```

**Why the framework doesn't save it.** Course column defaults make the `status='ACTIVE'` filter a no-op for visibility: `status` defaults `'ACTIVE'`, `isPublished` defaults `false`, `type` defaults `'SELF_PACED'`. The project *has* a correctly hardened public reader — `packages/db/src/queries/course/public-course.ts:129-131` returns `null` unless `type==='PUBLIC' && isPublished && status==='ACTIVE'` — but this older by-slug route bypasses it entirely. Hono runs exactly the middleware chain declared on the route, and none is declared here.

## Why it is a vulnerability

An unauthenticated caller reads data scoped to a course/org it has no relationship with: (a) the structure and content of a course the owner has not published, and (b) the personal email addresses of every enrolled learner and tutor. That is a confidentiality breach of both private business content and member PII (`S:C/C:H`). Slugs are `slugify(title)-Date.now()`, guessable for known course titles, and the 404-vs-200 response is an existence oracle for enumeration.

## Reproduction

Preconditions: the target is up; a course exists (the exploit creates a private one to be self-contained).

1. As admin (setup only) create a `SELF_PACED` course, set a slug via `PUT /course/:id`, and enroll a student — the course stays `isPublished:false`.
2. Decisive request — **no cookie**:
   ```
   GET http://localhost:21527/course/slug/<slug>
   Origin: http://localhost:21526
   ```
   → `HTTP 200`, `data.isPublished=false`, `data.group.members[].profile.email` populated.
3. `./run.sh` prints the baseline, the anonymous 200, `leaked member roster emails: ['admin@cvehunt.local', 'u_ce6534a6@cvehunt.local']`, and `[OK]`. Transcript in `run.log`; body in `response.txt`.

Observable proof: an anonymous request returns an unpublished, non-PUBLIC course together with member email addresses.

## Impact

- **PII harvest at scale.** Every course's learner/tutor emails are readable by slug — direct input to the unauthenticated phishing relay VULN-024 and the analytics oracle VULN-015.
- **Leak of unpublished course material** (roadmap/competitive value) and full content structure.
- **Enumeration** via the 404/200 oracle. Cross-tenant in cloud (the slug is matched globally with no org predicate).

## Suggested fix

At `apps/api/src/routes/course/course.ts:117` either require auth + course membership for the full-relations payload, or route anonymous reads through the already-hardened public channel and drop PII:

```diff
- .get('/slug/:slug', zValidator('param', ZCourseGetBySlugParam), async (c) => {
-   const { slug } = c.req.valid('param');
-   const course = await getCourse(undefined, slug);
+ .get('/slug/:slug', zValidator('param', ZCourseGetBySlugParam), async (c) => {
+   const { slug } = c.req.valid('param');
+   // Public channel only: enforce type='PUBLIC' && isPublished && status='ACTIVE'
+   // and never emit group.members[].profile.email to an unauthenticated caller.
+   const course = await getPublicCourseBySlug(slug);   // packages/db/.../public-course.ts
```

Alternatively add the `type='PUBLIC' && isPublished` predicate to `getCourseWithRelations` when no authenticated `profileId` is present, and strip `group.members` emails from unauthenticated responses. Best: delete this route and remove the dashboard fallback to it.

## References

- OWASP API Security Top 10 2023 — API1:2023 (BOLA), API3:2023 (excessive data exposure).
- CWE-639 (authorization bypass through user-controlled key), CWE-200 (information exposure).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — 9 known ClassroomIO CVEs; CVE-2025-67259 is the closest (course data exposure to students via PostgREST).
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; none mention a slug endpoint or unauthenticated access; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio "course/slug" OR "by slug" unauthenticated course member emails leak unpublished course` — no results on slug lookups or member emails; only CVE-2025-65670/65672/2026-111368.
5. Read github.com/advisories/GHSA-rx88-8j23-4qxx (CVE-2025-67259, issue #642) — authenticated student rewrites a captured request against `/rest/v1/course` (Supabase PostgREST) to read other students' details and tutor/admin profiles; requires auth, different stack.
6. Direct read of the repo issue list filtered for security — #685 (students see admin analytics on the cloud dashboard) and #642 (CVE-2025-67259); nothing on `GET /course/slug/:slug` or unauthenticated reads.
7. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — no coverage of course read routes.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-67259 (GHSA-rx88-8j23-4qxx) — same impact family (course roster/profile exposure to an unauthorized reader) but in the pre-1.0 PostgREST `/rest/v1/course` endpoint, requiring an authenticated student; this finding is the unauthenticated Hono `GET /course/slug/:slug` route with a `status='ACTIVE'`-only predicate in `getCourseWithRelations`.
- CVE-2025-65670 — course-id IDOR in the old stack; different code path.

**Reasoning:** No public reference describes the Hono `/course/slug/:slug` route being unauthenticated or `getCourseWithRelations` emitting `group.members[].profile.email`. A thematically similar exposure (CVE-2025-67259) was disclosed for the legacy Supabase stack, which suggests the maintainers have seen roster leakage reported before, hence a moderate score. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
