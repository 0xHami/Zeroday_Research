# VULN-018 — Unauthenticated session via the better-auth `anonymous()` plugin

| | |
|---|---|
| **ID** | VULN-018 (raw F-18) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 7.4** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | **None** |
| **What an attacker gains** | A real, authorized session with no signup/email/invite — the pre-auth root for VULN-004, VULN-033, VULN-010 and unbounded row/DoS creation |

## Summary

better-auth's `anonymous()` plugin is registered on the auth instance but is never
invoked by the frontend. It exposes `POST /api/auth/sign-in/anonymous`, which the
self-hosted `signupGuard` does not cover (that guard wraps only `/api/auth/sign-up/*`).
Any unauthenticated client can therefore mint a real `user` + session — no account,
email, org context, or invite — that satisfies every `authMiddleware` /
`authOrApiKeyMiddleware` gate. Confirmed live: routes returning 401 with no cookie
(`/account/profile`, `/organization`) return 200 with the minted anonymous session.

## How it works (mechanism & code trace)

**Registration — `packages/db/src/auth.ts:135-137`.** The plugin is enabled
unconditionally:

```ts
plugins: [
  admin(),
  anonymous(),   // :137  — exposes POST /api/auth/sign-in/anonymous
  sso({ ... }),
  ...
```

A repo-wide grep for callers of `sign-in/anonymous` / `signInAnonymous` finds none in
`apps/dashboard/src` (only unrelated PostHog and i18n strings), so the endpoint exists
purely as an unintended attack surface.

**Guard scope — `apps/api/src/app.ts:114`.** The signup control is scoped to sign-up
routes only:

```ts
.use('/api/auth/sign-up/*', signupGuard)          // :114  — sign-in/* is NOT guarded
.on(['POST', 'GET'], '/api/auth/*', ...)          // anonymous sign-in handled here, ungated
```

`signupGuard` is what enforces "self-hosted signup needs org context or an invite"
(`signup-guard.ts`), but `/api/auth/sign-in/anonymous` is a *sign-in*, so it sails past.

**Session issuance.** better-auth's anonymous handler creates a `user` row
(`isAnonymous: true`), runs the same `databaseHooks.user.create.after` → `createProfileHook`
(so a `profile` row is created too), and issues the standard
`classroomio.session_token` cookie. From that point `auth.api.getSession`
(`app.ts:80`) resolves a valid session and the app-wide middleware sets
`c.set('user', …)` / `c.set('session', …)`.

**Effect on the gates.** `authMiddleware` only checks `c.get('user') && c.get('session')`
(`middlewares/auth.ts`), and `authOrApiKeyMiddleware`'s first branch is the same test
(`auth-or-api-key.ts:15`). An anonymous session passes both. The account has empty
`orgRoles`, so `orgMemberMiddleware`-gated routes still reject it — but the many routes
gated by *only* `authMiddleware`/`authOrApiKeyMiddleware` (credit purchase, cohort
create, org read, …) are fully reachable.

## Why it is a vulnerability (reasoning)

The self-hosted product deliberately restricts who can obtain a session:
`signupGuard` blocks open registration, `joinOrganization` throws ("cloud only"), and
enterprise SSO is license-gated. The security invariant is *"no session without a
vetted onboarding path."* The unguarded anonymous sign-in breaks that invariant
outright: it hands out authorized sessions to anyone, for free, at scale.

By itself an anonymous session has no org role, so it is not a full account takeover —
hence the modest base score. Its true weight is as an **amplifier**: it converts every
"any authenticated session" bug into a *pre-auth* bug. We already used it to drive
VULN-004 (credit minting) and VULN-033 (org-config read) with no account. It also
enables unbounded creation of `user`/`profile`/session rows (storage/DoS) that, with
VULN-036/F-01's spoofable rate-limit key, cannot be throttled.

A skeptic might note the account is "just anonymous." The 401→200 differential refutes
the idea that it's inert: the app treats the session as authenticated everywhere the
gate is session-only. That is exactly the capability the self-hosted signup control was
meant to deny.

## Reproduction

Preconditions: none (target up).

1. Baseline: `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:21527/account/profile` → `401`;
   same for `/organization`.
2. Mint the session:
   ```
   POST http://localhost:21527/api/auth/sign-in/anonymous
   Origin: http://localhost:21526
   {}
   ```
   → `200`, `Set-Cookie: classroomio.session_token=…`; `GET /api/auth/get-session`
   shows `user.isAnonymous = true`.
3. Reuse the cookie: `GET /account/profile` → `200`, `GET /organization` → `200`.
4. Automated: `./run.sh` → prints the baseline 401s, the minted session, the 200s, and
   `[OK] exploit confirmed`, exiting 0. Transcript in `run.log`, session/body in
   `response.txt`.

Observable proof: identical requests differ only by the presence of the anonymous
cookie, and flip from 401 to 200.

## Impact

- **Pre-auth foothold.** Turns "any session" access-control bugs into unauthenticated
  ones — most importantly VULN-004 (unbounded AI spend), VULN-033 (org config /
  auth-posture disclosure), VULN-010 (cohort TUTOR self-grant), and the JSON body-size
  DoS (VULN-037).
- **Resource exhaustion.** Unlimited free `user`/`profile`/`session` rows; combined
  with the spoofable rate-limit key (VULN-036) this is unthrottleable.
- Blast radius: instance-wide; the anonymous accounts cannot read org-scoped data on
  their own (empty `orgRoles`), which bounds direct confidentiality impact.

## Suggested fix

At `packages/db/src/auth.ts:137`: remove the `anonymous()` plugin — it has no
frontend consumer. If a guest flow is ever needed, feature-flag it, rate-limit
`sign-in/anonymous`, and ensure `isAnonymous` sessions are never treated as authorized
by `authMiddleware`/`authOrApiKeyMiddleware` (add an explicit `!user.isAnonymous`
check to both). Principle: no code path should mint a session outside the vetted
onboarding flows the deployment intends.

## References

- better-auth `anonymous` plugin documentation (intended for opt-in guest sessions).
- OWASP WSTG-ATHN-01/-04 (testing authentication schema / bypass): the no-cookie-401
  vs anon-cookie-200 differential is the canonical demonstration.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — 9 known ClassroomIO CVEs; none concern better-auth plugins or anonymous sessions.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; none auth-plugin related; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio better-auth anonymous plugin "sign-in/anonymous" signup guard bypass session` — only better-auth's own documentation (the plugin as an intended opt-in guest feature); nothing about ClassroomIO enabling it or bypassing `signupGuard`.
5. `github.com/classroomio/classroomio issues security vulnerability 2026 IDOR SSRF anonymous` + direct read of the repo issue list filtered for security — no issue mentions anonymous sign-in; #682 (tenant auto-join) and #673 (account/join restrictions) concern real accounts.
6. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — no auth coverage.

**Related but distinct public references** (same class or component, not this bug):
- GitHub issue classroomio/classroomio#682 — a real account auto-joins another org as STUDENT on tenant login (`autoJoinOrg`, fixed by PR #965); different mechanism, requires an existing account.
- CVE-2025-67298 (GHSA-j8cg-23h3-5p99) — authentication spoofing via legacy `/api/verify`/`/rest/v1/profile` before v0.2.6; unrelated to the better-auth `anonymous()` plugin.
- better-auth anonymous plugin docs — documented intended behaviour, not a ClassroomIO advisory.

**Reasoning:** No public CVE, advisory, issue or write-up mentions the `anonymous()` plugin registered in `packages/db/src/auth.ts`, the `signupGuard` scope being limited to `/api/auth/sign-up/*`, or anonymous sessions satisfying `authMiddleware`/`authOrApiKeyMiddleware`. This is a configuration-level defect specific to ClassroomIO's auth wiring and has had no public scrutiny. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
