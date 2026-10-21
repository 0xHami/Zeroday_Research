# VULN-017 — Reusable, non-expiring ADMIN link-invite → any account becomes permanent org admin

| | |
|---|---|
| **ID** | VULN-017 (raw AC-4) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned, no tagged release |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 7.5** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Redeem: any authenticated account that obtains the link. Originate: one org admin. |
| **What an attacker gains** | Permanent **organization ADMIN** for arbitrary accounts from a single leaked link (full control of courses, members, settings) |

## Summary

ClassroomIO's "join by link" invite can be created for the **ADMIN** role, lives ~100 years,
persists its **raw** token in the DB and hands it back verbatim from the admin GET route, and is
**not consumed** on accept (only a revocation flag is checked). The combination turns one shared
URL into a permanent, reusable admin credential: anyone who ever sees the link — in chat, a
screenshot, browser history, a proxy log, or the token echoed by the API — can redeem it and
become a permanent org administrator, repeatedly, for any number of accounts.

Confirmed live: an admin created an ADMIN link-invite; `GET /organization/link-invite` returned
its raw token; two independent freshly-signed-up accounts each redeemed the same token and both
became org ADMIN — verified in the live session (`orgRoles[org]=1`) and in the database
(`organizationmember.role_id=1`).

## How it works (mechanism & code trace)

**Create — `apps/api/src/services/organization/invite.ts:513-550`.** The link invite permits the
ADMIN role, sets a ~100-year expiry, and stores the **raw** token in `metadata`:

```ts
const LINK_INVITE_FAR_FUTURE_MS = 100 * 365 * 24 * 60 * 60 * 1000;   // ~100 years
export async function getOrCreateLinkInvite(orgId, roleId, profileId) {
  if (roleId !== ROLE.ADMIN && roleId !== ROLE.TUTOR) {              // ADMIN is allowed
    throw new AppError('Invalid organization role for link invite', …, 400, 'roleId');
  }
  …
  const token = generateToken();
  const expiresAt = new Date(Date.now() + LINK_INVITE_FAR_FUTURE_MS).toISOString();
  const invite = await createLinkInvite({ organizationId: orgId, roleId, tokenHash,
    createdByProfileId: profileId, expiresAt,
    metadata: { token, source: 'ORG_SETTINGS_LINK_INVITE' } });     // raw token persisted
  …
  return { id: invite.id, token, roleId: invite.roleId, isRevoked: invite.isRevoked };
}
```

**Disclosure — `apps/api/src/routes/organization/organization.ts:209-217`.** The admin GET route
returns the raw token to any org admin (so it lands in history/screenshots/logs):

```ts
.get('/link-invite', authMiddleware, orgAdminMiddleware, async (c) => {
    const orgId = c.req.header('cio-org-id')!;
    const data = await fetchOrgLinkInvite(orgId);   // fetchOrgLinkInvite → { token: metadata.token, … }
    return c.json({ success: true, data }, 200);
});
```

**Accept — `apps/api/src/services/organization/invite.ts:609-638`.** The accept path checks
**only** `isRevoked` — no expiry check — and the doc-comment states it is deliberately **not
consumed**, then grants the invite's role:

```ts
/** …The invite is NOT consumed (reusable). Anyone with the link can join. */
export async function acceptLinkInvite(token, user, context = {}) {
    …
    const row = await getOrgLinkInviteWithOrg(tx, tokenHash);
    if (!row) { throw new AppError('Invalid invite link', …, 404); }
    if (row.invite.isRevoked) { throw new AppError('This invite link has been disabled', …, 403); } // only gate
    await syncOrgMemberForOrgInvite(tx, { organizationId: row.invite.organizationId,
      roleId: row.invite.roleId, normalizedEmail, userId: user.id });                                 // grants ADMIN
    await markUserAndProfileEmailVerified(user.id, tx);
    …
}
```

**Why nothing else saves it.** The accept route (`routes/invite/invite.ts:273-292`) only requires
`authMiddleware` (any logged-in user). There is no binding to a specific invitee, no single-use
consumption, and revocation is scoped per `(org, type)` rather than per invite id
(`queries/organization/link-invite.ts`), so re-creating resurrects a shared token. The `roleId`
allow-list explicitly includes ADMIN.

## Why it is a vulnerability

A high-privilege capability — organization administrator — is granted by **mere possession** of a
token that is (a) long-lived (~100 years), (b) reusable (not consumed), (c) admin-capable, and
(d) disclosed in cleartext by the API. Each property individually is a weakness; together they
make a single "share this link to join" URL a permanent org-takeover primitive. The trust
boundary — "only vetted people become admins" — collapses to "anyone who ever saw the URL".

## Reproduction

Preconditions: an org admin session. Everything else (the redeeming accounts) is created at
runtime with random suffixes.

1. As admin, create an ADMIN link-invite and read its raw token:
   ```
   POST /organization/link-invite   {"roleId":1}      → data.token = "D2LNpExP…Kmefyg", roleId=1
   GET  /organization/link-invite                     → data.token = "D2LNpExP…Kmefyg"  (raw)
   ```
2. From two independent fresh accounts, redeem the same token:
   ```
   POST /invite/link/D2LNpExP…Kmefyg/accept   {}      → 200 { roleId: 1 }   (account #1 → ADMIN)
   POST /invite/link/D2LNpExP…Kmefyg/accept   {}      → 200 { roleId: 1 }   (account #2 → ADMIN)
   ```
3. `./run.sh` → `[OK]`, exit 0. Ground truth from `run.log`:
   ```
   #1 u_5e3290c6@cvehunt.local: session_role=1 db_role=1
   #2 u_4ae377ab@cvehunt.local: session_role=1 db_role=1
   ==> VULN-017: CONFIRMED — ADMIN link-invite discloses its raw token and reusably grants org ADMIN
   ```
   Both users hold `organizationmember.role_id = 1` (ADMIN) despite having had no prior privilege.

## Impact

- **Silent, durable org takeover from a leaked link.** ADMIN unlocks the entire admin-gated
  surface: all courses/content, member management, org settings, invites, billing config.
- **Cannot be aged out** (~100-year expiry) and **reusable** (no consumption), so one leak
  compromises an unbounded number of accounts; coarse per-type revocation can be resurrected.
- **Chains:** the granted ADMIN role enables every admin-only finding (e.g. creating more
  invites, the CORS-trust surface, org-config changes). It is also the cleanest way to bootstrap
  a second privileged actor for other exploits.

## Suggested fix

In `apps/api/src/services/organization/invite.ts`:

```ts
// 1) Never allow ADMIN on a reusable link; forbid it in getOrCreateLinkInvite:
if (roleId !== ROLE.TUTOR) {                       // was: ADMIN || TUTOR
  throw new AppError('Link invites may not grant admin', …, 400, 'roleId');
}

// 2) Make link invites short-lived and single-use — consume on accept (add a use count / expiry):
const LINK_INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;   // days, not a century
// in acceptLinkInvite: reject if expired, and mark consumed (or decrement a maxUses counter).
```

In `apps/api/src/routes/organization/organization.ts:209-217` (and `fetchOrgLinkInvite`): return
an **opaque/masked** handle, never `metadata.token` raw. In
`packages/db/src/queries/organization/link-invite.ts`: revoke per invite **id**, not per
`(org, type)`, so revocation cannot be resurrected.

## References

- CWE-284 Improper Access Control; CWE-522 Insufficiently Protected Credentials.
- OWASP WSTG-ATHZ — testing for privilege escalation via invitation/registration flows.
- Invitation-token hardening: short TTL, single-use, invitee-bound, least-privilege role.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — 9 known ClassroomIO CVEs; none concern org link-invites.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; CVE-2025-65672 (course share/invite settings) and CVE-2025-67298 (`/api/verify` + `/rest/v1/profile` privilege escalation) are the only invite/privilege items, both in the pre-1.0 stack; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio link invite admin reusable token organization admin takeover vulnerability` — nothing on reusable/admin link invites; only CVE-2025-65670/65672.
5. Read github.com/advisories/GHSA-px6j-wc84-gwhf (CVE-2025-65672) — course-level share/invite settings IDOR by course id in 0.1.13; not the org link-invite service.
6. Direct read of the repo issue list filtered for security and of issue #682 — #682 is tenant-site auto-join as STUDENT on login (`autoJoinOrg`, fixed by PR #965); not link invites, not ADMIN.
7. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — no invite coverage.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-65672 (GHSA-px6j-wc84-gwhf) — course share/invite settings IDOR in the Supabase-era app; different component (course settings vs. `apps/api/src/services/organization/invite.ts` link invites) and different defect.
- CVE-2025-67298 (GHSA-j8cg-23h3-5p99) — privilege escalation via `/api/verify` and `/rest/v1/profile` before v0.2.6; legacy auth flow, unrelated to link-invite tokens.
- GitHub issue classroomio/classroomio#682 — unintended STUDENT auto-join on tenant login; different mechanism and role.

**Reasoning:** No public reference describes `getOrCreateLinkInvite` permitting ADMIN, the ~100-year expiry, the raw token persisted in `metadata` and echoed by `GET /organization/link-invite`, or `acceptLinkInvite` checking only `isRevoked`. The org link-invite feature is part of the new Hono API and is absent from every public ClassroomIO disclosure. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
