# VULN-025 — Open redirect in login/signup and in the auth-handoff (`//evil.com`)

| | |
|---|---|
| **ID** | VULN-025 (raw F-15 + F-21) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 6.1** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None (victim clicks a crafted link) |
| **What an attacker gains** | Credible phishing hop from the trusted origin; on the server auth-handoff, an *authenticated* victim is bounced to the attacker origin after the session cookie is set |

## Summary

Every redirect guard on ClassroomIO's auth paths uses only `redirect.startsWith('/')`. A
protocol-relative URL `//evil.com` (and the backslash form `/\evil.com`) begins with `/`, so it
passes the check, yet browsers resolve it to a **different origin**. The two server-side auth
handoffs (`login-link`, `token-exchange`) emit the redirect **after** setting the session cookie,
so a freshly-authenticated victim is bounced to the attacker origin carrying session context.

Confirmed live with a raw HTTP request (no browser): `GET /api/auth/login-link?token=<valid>&
redirect=//evil.example/phish` returns `302 Location: //evil.example/phish` **plus**
`Set-Cookie: classroomio.session_token`. The absolute-URL control (`https://evil.example`) is
correctly rejected (falls back to `/`), isolating the `//`/`/\` bypass.

## How it works (mechanism & code trace)

**Query schema does not sanitize the param — `packages/utils/src/validation/organization/login-link.ts:3-6`:**

```ts
export const ZLoginLinkQuery = z.object({
  token: z.string().min(1),
  redirect: z.string().optional()          // any string; // and /\ pass through
});
```

**Server sink (decisive) — `packages/db/src/auth/plugins/login-link.ts:49,114-116`:**

```ts
const redirectUrl = query.data.redirect && query.data.redirect.startsWith('/') ? query.data.redirect : '/';
…
await setSessionCookie(c, { session, user: userPayload });   // session established first
return c.redirect(redirectUrl);                              // …then bounce — post-Set-Cookie
```

Identical shape in `packages/db/src/auth/plugins/token-exchange.ts:41,124`.

**Client sinks — `apps/dashboard/src/routes/(auth)/login/+page.svelte:109-110`** (and
`signup/+page.svelte:193-194`), reached via the `?redirect=` query param
(`login/+page.svelte:32` `redirectUrl = page.url.searchParams.get('redirect')`):

```ts
const redirect = redirectUrl || '/';
window.location.href = redirect.startsWith('/') ? redirect : `/?redirect=${encodeURIComponent(redirect)}`;
```

**Why the framework doesn't save it.** `startsWith('/')` is a prefix test, not an origin check.
`//evil.com` and `/\evil.com` both start with `/` but denote a cross-origin authority to a
browser (`new URL('//evil.com', origin).origin !== origin`). The repo **already ships the correct
guard** — `apps/dashboard/src/lib/features/org/utils/org-join-redirect.ts:3-13`,
`resolveOrgJoinRedirect`, which does a full `URL` origin comparison and rejects `//evil.com` — but
it is not used on any of these four sinks.

## Why it is a vulnerability

The redirect target is attacker-chosen and resolves cross-origin, so the trusted ClassroomIO
origin will send the user to an attacker page — the definition of an open redirect (CWE-601). The
server auth-handoff variant is worse than a plain client redirect: the bounce happens **after**
`Set-Cookie`, so the victim is redirected while newly authenticated, aiding session-context/token
capture on the attacker page and lending phishing credibility ("I clicked a real classroomio.com
link").

## Reproduction

1. Mint a valid login-link token (any authenticated account can, via
   `POST /account/view-as-student-token`).
2. Issue the auth-handoff request with a protocol-relative redirect (no browser needed):
   ```
   GET /api/auth/login-link?token=<valid>&redirect=//evil.example/phish
   → HTTP 302
     Location: //evil.example/phish
     Set-Cookie: classroomio.session_token=…
   ```
3. Controls (same run): `redirect=/\evil.example/phish` → `Location: /\evil.example/phish`
   (accepted); `redirect=/lms` → `/lms`; `redirect=https://evil.example/x` → `/` (rejected).
4. `./run.sh` → `[OK]`, exit 0:
   ```
   [PROOF] server emitted Location: '//evil.example/phish' — an attacker-controlled CROSS-ORIGIN redirect
   [PROOF] the 3xx follows Set-Cookie: classroomio.session_token → an *authenticated* victim is bounced
   ==> VULN-025: CONFIRMED — login-link auth-handoff open-redirects to //evil.example + backslash variant
   ```

The client sinks accept the same payload via `/(login|signup)?redirect=//evil.example/phish`
(the `window.location.href` navigation is client-side; the server-side 302 above already proves
the guard class is broken).

## Impact

- **Phishing / credential harvesting** launched from the legitimate origin.
- **Auth-handoff session leakage:** the post-Set-Cookie bounce sends a freshly-authenticated
  victim to the attacker page.
- **Chains** with VULN-026 (the same login-link GET is a login-CSRF primitive) and with any
  URL-fragment/token capture on the attacker landing page.

## Suggested fix

Replace `startsWith('/')` at all four sinks with the repo's own `resolveOrgJoinRedirect` (or an
equivalent full-`URL` origin comparison), explicitly rejecting `//` and `/\` prefixes:

```ts
// packages/db/src/auth/plugins/login-link.ts:49  (and token-exchange.ts:41)
import { resolveOrgJoinRedirect } from '@cio/dashboard/.../org-join-redirect';
const redirectUrl = resolveOrgJoinRedirect(query.data.redirect ?? '/', CONSTANTS.BASE_URL);
```
```ts
// login/+page.svelte:110  (and signup/+page.svelte:194)
window.location.href = resolveOrgJoinRedirect(redirect, window.location.origin);
```

## References

- CWE-601 URL Redirection to Untrusted Site (Open Redirect).
- OWASP — Unvalidated Redirects and Forwards Cheat Sheet; the `//` / `/\` `startsWith('/')`
  bypass is a documented classic.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs returned; none is an open redirect (CWE-601).
2. `classroomio github security advisory GHSA` — 9 GHSAs; none mentions `redirect`, `login-link`, or `token-exchange`.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no CWE-601 entry.
5. Issue tracker `"open redirect" OR "protocol-relative" OR "login-link" OR "login link" OR "session fixation" OR "login CSRF"` — 8 hits (#1023 BYOD redirects, #677 view-as-student handoff host, #887 sign-in PRD); none reports an open redirect.
6. Commit search `CORS OR redirect OR "login link" OR newsfeed OR attendance` — 117 commits; only e455dfd "enhance login link generation" looked relevant (inspected below).
7. Fetched commit e455dfd (2026-08-23) — touches only the CLI helper `packages/db/src/scripts/generate-login-link.ts`; its comment documents that the server plugin "drops any redirect that does not start with `/`" (i.e. the very `startsWith('/')` guard) without noting the `//` / `/\` bypass; the server sinks `login-link.ts` / `token-exchange.ts` were not changed.
8. Issue tracker `spoof OR "trusted proxy" OR ...` and `security in:title` — #728 (strip internal port from OAuth redirects) is functional; no redirect-security report.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- Commit e455dfd / PR #1023 / PR #728 — redirect-handling changes for custom domains and OAuth; functional fixes that do not address protocol-relative bypass.
- CVE-2025-67298 / GHSA-j8cg-23h3-5p99 — forgeable (unsigned base64) verification tokens at `/api/verify` before v0.2.6; different endpoint and root cause.

**Reasoning:** No public record describes a `//evil` / `/\evil` bypass of the `startsWith('/')` guard in the login-link / token-exchange auth-handoff or the login/signup pages. The one upstream commit touching login-link redirects re-documents the flawed guard rather than fixing it. Open redirect is a common class, so a low-profile report could exist, but nothing was found across advisories, OSV/Snyk, the tracker, or commit history.
