# VULN-026 — Login CSRF / session fixation via reusable self-mintable login-link GET

| | |
|---|---|
| **ID** | VULN-026 (raw F-24) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 6.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any authenticated user (to self-mint a token for their own account) + victim clicks |
| **What an attacker gains** | The victim's browser is silently signed into the **attacker's** account; anything the victim then enters (PII, uploads, a linked OAuth identity) accrues to the attacker |

## Summary

`GET /api/auth/login-link?token=<jwt>` creates and sets a full session with **no Origin/Referer/
CSRF check**. Under `SameSite=Lax` cookies a top-level cross-site GET navigation still sets
cookies, so an attacker can drive a victim's browser to this URL. The token is only
signature/expiry-verified — there is no `jti`/nonce and it is not consumed — so it is
**replayable**. Any authenticated user can self-mint a login-link token for their **own** account
(`POST /account/view-as-student-token`). An attacker mints for the **attacker** account, and the
victim ends up authenticated **as the attacker** — classic login CSRF / session fixation.

Confirmed live: two independent fresh cookie jars both performed the login-link GET with the
attacker's token and both resolved (via `get-session`) to the **attacker's** `user.id` — one of
them while sending `Origin: https://attacker.example` (proving no Origin check).

## How it works (mechanism & code trace)

**Session-establishing GET (no CSRF/Origin) — `packages/db/src/auth/plugins/login-link.ts:38-116`:**

```ts
loginLink: createAuthEndpoint('/login-link', { method: 'GET' }, async (c) => {
    …
    const verified = await jwtVerify(query.data.token, getLoginLinkSecret(), { algorithms: ['HS256'] });
    const [user] = await db.select().from(schema.user).where(eq(schema.user.id, parsedPayload.data.sub)).limit(1);
    if (!user || user.email.toLowerCase().trim() !== normalizedEmail) { /* 404 */ }
    const [sessionRow] = await db.insert(schema.session).values({ userId: user.id, token: sessionToken,
        expiresAt, …, impersonatedBy: 'login-link' }).returning();      // new session for token's user
    …
    await setSessionCookie(c, { session, user: userPayload });          // sets the session cookie
    return c.redirect(redirectUrl);                                     // no Origin/CSRF check anywhere
});
```

There is no nonce/`jti` and the token is never marked consumed, so it works repeatedly until its
TTL expires.

**Self-mint (any user, for their own account) — `apps/api/src/routes/account/account.ts:71-89`:**

```ts
.post('/view-as-student-token', authMiddleware, async (c) => {
    const user = c.get('user')!;
    const token = await createViewAsStudentToken({ id: user.id, email: user.email });   // self only
    return c.json({ success: true, data: { token } }, 200);
});
```
`apps/api/src/services/account/view-as-student.ts:18-24` → `mintLoginLinkToken({ userId, email,
ttlMinutes: 5 })`. The "self only" restriction is exactly what makes the attack work: the attacker
mints a valid token **for the attacker's own account** and lures the victim to redeem it.

**Why the framework doesn't save it.** The endpoint is a `GET` (better-auth's CSRF protection
targets state-changing verbs), the handler performs no Origin/Referer validation, and cookies are
`SameSite=Lax` — which explicitly permits cookie setting on top-level cross-site GET navigations.
So a plain link/redirect the victim follows is sufficient.

## Why it is a vulnerability

A **state-changing authentication action** (session creation) is exposed as a **cross-site-drivable
GET** with **no CSRF/Origin defense** and a **replayable** token that any user can self-mint. The
attacker fixes the victim's browser into the **attacker's** account. Everything the victim then
does — editing profile data, uploading files, linking a Google identity — lands in the attacker's
account, which the attacker later logs into to harvest. This inverts the usual CSRF (the victim
acts as the attacker's account rather than the attacker acting as the victim), and is the textbook
login-CSRF / session-fixation pattern.

## Reproduction

1. Attacker (authenticated) self-mints a token for their own account:
   ```
   POST /account/view-as-student-token  {}     → { data: { token: "<jwt>" } }
   ```
2. Victim's browser (fresh, no session — models a cross-site nav) follows:
   ```
   GET /api/auth/login-link?token=<attacker token>
   → 302, Set-Cookie: classroomio.session_token=…
   ```
3. The victim is now the attacker:
   ```
   GET /api/auth/get-session   → user.id == <attacker id>, email == <attacker email>
   ```
4. `./run.sh` → `[OK]`, exit 0:
   ```
   attacker account: id=357b40be-… email=u_d90e1126@cvehunt.local
   victim #1 … get-session user id=357b40be-…    (fixed to attacker)
   victim #2 (attacker Origin) … get-session user id=357b40be-…   (reusable, no Origin check)
   ==> VULN-026: CONFIRMED — cross-site login-link GET fixes a victim into the attacker's account; token reusable
   ```

## Impact

- **Silent account fixation → data capture.** Victim-entered PII/uploads accrue to the attacker's
  account; a victim who links an OAuth identity hands the attacker a durable login.
- **Reusable within TTL** → one token phishes many victims.
- **Chains** with VULN-025 (open redirect) to dress the link as a trusted-origin URL, and
  amplifies any data the victim submits while fixed.

## Suggested fix

1. Make login-link tokens **single-use**: embed a `jti`, record it on redemption, and reject
   replays (`packages/db/src/auth/plugins/login-link.ts`).
2. Do **not** establish sessions on a cross-site GET: require a POST with a CSRF token, or validate
   `Origin`/`Referer` against `TRUSTED_ORIGINS` before `setSessionCookie`:
   ```ts
   // login-link.ts, before creating the session:
   const origin = c.req.header('origin');
   if (origin && !TRUSTED_ORIGINS.includes(origin)) return c.json({ error: 'bad origin' }, 403);
   ```
3. Consider binding the handoff to the initiating session (short-lived, one device).

## References

- CWE-352 Cross-Site Request Forgery (login CSRF) and CWE-384 Session Fixation.
- OWASP — CSRF Prevention Cheat Sheet (§ Login CSRF) and Session Management Cheat Sheet
  (one-time, origin-validated session-establishment).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; none is a CSRF / session-fixation issue on the login-link endpoint.
2. `classroomio github security advisory GHSA` — 9 GHSAs; CVE-2025-67298 (verification-token forgery) is the only auth-token advisory and targets `/api/verify`, not `/api/auth/login-link`.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no CWE-352/CWE-384 entry.
5. Issue tracker `"open redirect" OR "protocol-relative" OR "login-link" OR "login link" OR "session fixation" OR "login CSRF"` — 8 hits; none security-related.
6. Issue tracker `CSRF OR "session fixation" OR "view as student" OR "token exchange" OR anonymous` — 49 hits; #677 (view-as-student handoff uses verified custom domain), #1067 PRD (origin allowlist enforced only at session exchange); none describe cross-site login-link redemption, token replay, or `view-as-student-token` abuse.
7. Commit search `CORS OR redirect OR "login link" OR newsfeed OR attendance` — e455dfd (CLI script only) and cf6f24f ("enhance cookie security" / base-URL handling); no `jti`/single-use or Origin check added to `packages/db/src/auth/plugins/login-link.ts`.
8. Fetched the CVE-2025-67298 gist — unsigned base64 verification tokens and client-writable `is_email_verified`; a different mechanism from the HS256-signed login-link JWT.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-67298 / GHSA-j8cg-23h3-5p99 — forgeable email-verification tokens (`/api/verify`, `/rest/v1/profile`) before v0.2.6; different endpoint, and the defect here is replay + no Origin/CSRF check on a correctly signed token, not forgery.
- PR #677 (merged 2026-06-19) — functional change to the host used for the view-as-student handoff.

**Reasoning:** Nothing public describes `GET /api/auth/login-link` establishing a session on a cross-site GET with no Origin check, the absence of a `jti`/consumption step, or self-minting via `POST /account/view-as-student-token` to fix a victim into the attacker's account. The only public auth-token advisory concerns a different, pre-0.2.6 verification flow. Login CSRF is a niche class and this project's public record is small and fully enumerated.
