# VULN-028 — `disableEmailPassword`/`disableGoogleAuth` enforced UI-only (dead-code server guards)

| | |
|---|---|
| **ID** | VULN-028 (raw F-37) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.8** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` (→ High where SSO is force-required for compliance) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None to abuse (the attacker uses the "disabled" method to log in) |
| **What an attacker gains** | Authenticate via a method the org believed it had turned off (defeats "force SSO" / method-lockdown; a compromised email/password stays usable after being "disabled") |

## Summary

An organization can set `disableEmailPassword` / `disableGoogleAuth` to force SSO or shut down a
compromised login method. But Better Auth registers both providers **unconditionally**, and the
guard functions that would enforce those flags — `checkEmailPasswordAllowed` /
`checkGoogleAuthAllowed` — have **zero callers repo-wide**. So the flags change only what the
dashboard renders; the server still authenticates the "disabled" method.

Confirmed live: with `organization.disable_email_password = true` **persisted in the database**,
`POST /api/auth/sign-in/email` with valid credentials still returned `200` with a
`Set-Cookie: classroomio.session_token`.

## How it works (mechanism & code trace)

**Providers registered unconditionally — `packages/db/src/auth.ts:52,64-71`:**

```ts
emailAndPassword: emailAndPassword,          // { enabled: true, … } — always on
…
socialProviders: {
  google: { clientId: process.env.GOOGLE_CLIENT_ID!, clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
            accessType: 'offline', prompt: 'select_account consent' } },   // always registered
```

**The guards that would enforce the flags exist — `packages/db/src/auth/hooks/auth-settings.ts:63-107`
(and `112-155` for Google):**

```ts
export async function checkEmailPasswordAllowed(email: string): Promise<{ allowed: boolean; message?: string }> {
  …
  if (org.disableEmailPassword) {
    return { allowed: false, message: 'Email/password login is disabled. Please use SSO or contact your administrator.' };
  }
  return { allowed: true };
}
```

**…but nothing calls them.** Grep across the repo returns only the definitions:

```
$ grep -rn "checkEmailPasswordAllowed" apps packages --include='*.ts'
  packages/db/src/auth/hooks/auth-settings.ts:63:export async function checkEmailPasswordAllowed(…)
$ grep -rn "checkGoogleAuthAllowed" apps packages --include='*.ts'
  packages/db/src/auth/hooks/auth-settings.ts:112:export async function checkGoogleAuthAllowed(…)
```

They are never wired into a Better Auth `before` hook on the sign-in endpoints. The only
server-side code touching the flags, `assertAuthSettingsEntitlement`
(`apps/api/src/services/organization.ts:758-778`), gates the **entitlement to change** the
settings, not the login itself.

**Why the framework doesn't save it.** Better Auth only enforces what it is configured to enforce;
with `emailAndPassword.enabled = true` hard-coded and no `before`-hook rejection, the sign-in path
never consults the org flags.

## Why it is a vulnerability

A security-relevant policy toggle is enforced **only in the client** (the dashboard hides the
form). The server-side control that should back it is dead code, so the toggle provides a false
sense of security: "force SSO" is not enforced, and a compromised email/password remains usable
after an admin "disables" it. Where SSO is mandated for compliance, this rises toward High.

## Reproduction

1. As org admin, disable email/password (`PUT /organization {"disableEmailPassword":true}`).
   - In this instance the API returned `403 UPGRADE_REQUIRED` — the *entitlement-to-change* gate,
     which trips because the API container runs with `PUBLIC_IS_SELFHOSTED` unset (cloud mode) and
     the org is on the default `BASIC` plan. That gate is unrelated to the auth bypass, so the flag
     was set directly on the org row (a legitimate operator action). In a true self-hosted
     deployment (`PUBLIC_IS_SELFHOSTED=true` in the API), the admin PUT succeeds and this step is
     API-only.
2. Confirm the flag is persisted: `psql → organization.disable_email_password = 't'`.
3. Sign in with the "disabled" method from a clean cookie jar:
   ```
   POST /api/auth/sign-in/email  {"email":"admin@cvehunt.local","password":"…"}
   → HTTP 200,  Set-Cookie: classroomio.session_token=…
   ```
4. `./run.sh` → `[OK]`, exit 0 (and it restores the flag afterwards):
   ```
   PUT /organization {disableEmailPassword:true} → HTTP 403; DB now = 'f'   (entitlement gate)
     … setting it via DB and retrying → DB now = 't'
   sign-in with email/password while DISABLED → HTTP 200  session cookie set = True
   ==> VULN-028: CONFIRMED — disableEmailPassword is UI-only; server still authenticates the disabled method
   ```

## Impact

- **Defeats method-lockdown / "force SSO".** An org that disables email/password (e.g. after a
  credential leak, or to mandate SSO) is still fully log-in-able via that method.
- **Compromised credentials stay live** after being "disabled".
- The **Google** flag shares the identical dead-guard defect (dormant here only because the
  instance uses placeholder OAuth credentials).
- **Chains:** undermines the whole auth-policy surface (pairs with the anonymous-session and
  login-link findings, which also bypass intended auth assumptions).

## Suggested fix

Wire the existing guards into Better Auth `before` hooks on the sign-in endpoints
(`packages/db/src/auth.ts`), rejecting a disabled method:

```ts
emailAndPassword: {
  ...emailAndPassword,
  // pseudo: before sign-in
  async before(ctx) {
    const { allowed, message } = await checkEmailPasswordAllowed(ctx.body.email);
    if (!allowed) throw new APIError(403, { message });
  }
},
// and the analogous hook for the Google social provider via checkGoogleAuthAllowed
```

Alternatively, register providers conditionally per-org and treat the flags as authoritative
server-side. Either way, the flag must gate authentication, not just UI rendering.

## References

- CWE-284 Improper Access Control; CWE-1188 Insecure Default (a policy whose server enforcement is
  absent/dead).
- OWASP ASVS V2 Authentication — the server must enforce which authentication mechanisms are
  permitted; client-only enforcement is not a control.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; none concerns auth-method lockdown or `disableEmailPassword`/`disableGoogleAuth`.
2. `classroomio github security advisory GHSA` — 9 GHSAs; none on sign-in method enforcement.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no match.
5. Issue tracker `disableEmailPassword OR disableGoogleAuth OR "disable email" OR "force SSO" OR "sign-in methods" OR checkEmailPasswordAllowed` — 6 hits (#954 locked auth fields on Early Adopter plan, #887 sign-in-methods PRD, #627 SSO planning); none reports that the flags are not enforced at sign-in.
6. Issue tracker `security in:title` — 11 items (#640/#642/#643 dashboard authz, #1069/#1093 fixes, SECURITY.md); none on auth-method lockdown.
7. Commit search `security` — 21 commits; 07ecfcf "authorization bypass vulnerabilities in plan-restricted features" fetched: only client-side `$isFreePlan` checks in five dashboard components, no sign-in enforcement.
8. Commit search `"custom domain" OR "automation key" OR sanitize OR certificate OR PUBLIC_IS_SELFHOSTED` — nothing touching `packages/db/src/auth/hooks/auth-settings.ts` or `checkEmailPasswordAllowed`.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- Commit 07ecfcf (2025-12-03) — plan-entitlement UI checks for custom domain/certificates/uploads/team; concerns who may change settings, not whether sign-in honours them.
- Issue #954 (closed 2026-09-04) — UI lock state of the "Auth General" settings fields; not enforcement.
- Issue #682 / PR #965 — auto-join bypassing invite-only/disabled-signup for existing accounts; a different auth-policy gap (signup, not sign-in method).

**Reasoning:** No public record states that `checkEmailPasswordAllowed` / `checkGoogleAuthAllowed` have no callers or that Better Auth registers both providers unconditionally, so a "disabled" method still authenticates. The closest public items concern plan gating of the settings UI. The project's public vulnerability record is small and fully enumerated; a private report remains possible.
