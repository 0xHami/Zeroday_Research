# VULN-021 — `/info` over-exposes session IP/UA + email & username history under a weaker privilege

| | |
|---|---|
| **ID** | VULN-021 |
| **Software** | NodeBB |
| **Repository** | https://github.com/NodeBB/NodeBB |
| **Affected version** | 4.16.0 (`install/package.json:5`; commit-pinned, untagged `master`) |
| **Commit** | `20623201cbf2cc8a37612726cdf10ee82083c9c3` |
| **Severity** | Medium (conditional) — **CVSS 3.1 6.5** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic, config-gated)** |
| **Auth required** | A member of a group to which `view:users:info` has been delegated. |
| **Attacker gains** | For any user: login session IP addresses + user-agents, and full email/username history — data the dedicated endpoints refuse to this role. |

## Summary
The account `/info` controller assigns session records (IP, UA, platform, datetime), full email history, and username history to its payload **unconditionally** — only `history`/`moderationNotes` are gated behind `isPrivileged`. The `/info` route is reachable under the global `view:users:info` privilege, a *weaker* bar than the `canEdit` gate on the dedicated `/sessions` route and the `showemail/self/privileged` gate on `listEmails` for the same data. So a holder of only `view:users:info` reads, for any user, session IPs/UAs and email/username history the other endpoints deny. Confirmed: a member with only `view:users:info` read the admin's 10 session records (first IP `172.18.0.1`) plus email/username history via `/info`, while `/sessions` returned 403 for the same caller.

## How it works (mechanism & code trace)

**Controller assigns sensitive fields with no per-field gate (`src/controllers/accounts/info.js:29-39`):**
```js
payload.sessions = sessions;      // each: IP, UUID, platform, browser, version, datetime
payload.usernames = usernames;    // full username history
payload.emails = emails;          // full email-address history
payload.invitedBy = invitedBy;
if (isPrivileged) {               // <-- ONLY these two are gated
    payload.history = history;
    payload.moderationNotes = notes.notes;
    payload.pagination = ...;
}
```

**The route's weaker gate (`src/middleware/user.js:192-193`).** `middleware.checkAccountPermissions` normally requires `privileges.users.canEdit` (self/admin/global-mod), but grants a `/info$`-path exception for the global `view:users:info` privilege. So access to `/info` — and thus to the unconditionally-assigned session/email/username data — is available to anyone with `view:users:info`.

**The divergence.** The same session data via `GET /user/:userslug/sessions` requires `canEdit` (that route shares `accountMiddlewares` but gets no `/info` exception), and email history via `usersAPI.listEmails` requires `isAdminOrGlobalMod || isSelf || showemail`. Dynamically this is exactly what happened: `/info` → 200 with the data, `/sessions` → 403, for the identical caller. The page-route JSON mirror returns the whole `/info` payload verbatim.

## Why it is a vulnerability (reasoning)
NodeBB deliberately treats session IPs/UAs and email history as sensitive — that is why `/sessions` and `listEmails` gate them behind `canEdit`/`showemail`. The `/info` view exposes the same data behind a *lower* privilege (`view:users:info`), so delegating that privilege — a plausible admin choice for a "trusted"/"staff" role that should see profile metadata — silently also hands over GDPR-sensitive session IPs and email/username history for the entire user base. The security invariant "the same data must be protected by the same authorization wherever it is served" is violated. The dynamic 200-vs-403 split is the proof: it is not that `view:users:info` is meant to grant this — the dedicated endpoints show the intended bar is higher. Conditional on the delegation, hence Medium.

## Reproduction
1. As admin, delegate `groups:view:users:info` to `registered-users` (or any lower group): `PUT /api/v3/categories/0/privileges/groups:view:users:info` `{"member":"registered-users"}`.
2. Log in as an ordinary member. `GET /api/user/admin/info` → response includes `sessions[].ip`, `emails[]`, `usernames[]`, `invitedBy`.
3. `GET /api/user/admin/sessions` → 403 (same caller, same session data).
4. `./run.sh` grants the privilege, creates a member, demonstrates the `/info` leak + the `/sessions` 403, then **rescinds** the privilege. Prints `[OK] exploit confirmed`. See `response.txt`/`run.log`.

## Impact
A delegated non-moderator role harvests login IP addresses, user-agents, and full email/username history for arbitrary users — GDPR-sensitive data beyond what the role was meant to see. The leaked emails feed VULN-022 (targeted reset mailbomb); session IP/UA aids targeted attacks and deanonymization. Confidentiality-high for the exposed data; conditional on the delegation.

## Suggested fix
Gate `sessions`/`emails`/`usernames`/`invitedBy` in `infoController.get` behind `isPrivileged`/`canEdit` (matching `/sessions` and `listEmails`), rather than relying on the `/info` route's `view:users:info` exception; or drop that session/email/username payload from the `view:users:info`-only view entirely, exposing only non-sensitive profile metadata under that privilege.

## References
- OWASP API Security Top 10 — API1:2023 (BOLA) / API3 (excessive data exposure); WSTG-ATHZ-02.
- CWE-200 (Exposure of Sensitive Information); CWE-284 (Improper Access Control).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `NodeBB "view:users:info" account info sessions IP address email history information disclosure` — only CVE-2020-15149 and CVE-2024-29316 (restricted admin-group tabs); nothing on the `/info` payload.
2. `NodeBB CVE 2025 2026 information disclosure OR "access control" OR "denial of service" advisory list` — only XSS CVEs (CVE-2026-73038, CVE-2025-29512) plus older CVE-2024-29316 / CVE-2023-30591; no match.
3. NodeBB GitHub security-advisories page + OpenCVE vendor listing (23 CVEs) — information-disclosure entries limited to CVE-2023-2850 (CSWSH); nothing on `/info`, sessions or email history.
4. Upstream history of `src/controllers/accounts/info.js` and `src/middleware/user.js` (master) — no commit gating `sessions`/`emails`/`usernames` behind `isPrivileged`/`canEdit`; the only 2026 changes are `1dae3d2` (adds `invitedBy`, widening the payload) and `3db92c5` (hide ban/mute/flags from self). Commit `a018478` ("only allow self/admins/gmods to view/list emails", Jul 2026) was examined: it hardens `usersAPI.listEmails`/`getEmail` only and does not touch the `/info` controller or the `view:users:info` exception.

**Related but distinct public references** (same class or component, not this bug):
- NodeBB commit a018478 (4.14.x) — restricted the dedicated `listEmails`/`getEmail` API to self/admin/global-mod; shows the intended bar for email history but leaves `/info` serving the same data under `view:users:info`.
- CVE-2024-29316 — low-privileged access to restricted admin-group tabs; different route and privilege.
- CVE-2023-2850 / GHSA-4qcv-qf38-5j3j — cross-site websocket hijacking leaking user information; different vector.

**Reasoning:** No advisory, issue or upstream fix addresses the `/info` controller unconditionally serving session IP/UA records and email/username history under the weaker `view:users:info` privilege while `/sessions` and `listEmails` require `canEdit`/admin. The issue is conditional on an admin delegating that privilege, which makes it less likely to have been reported, but nothing public matches the component. Web-search quota was exhausted mid-triage; later checks were direct fetches of GitHub/OpenCVE pages.
