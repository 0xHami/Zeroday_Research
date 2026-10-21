# VULN-014 — Password change and lost-password reset do NOT invalidate existing sessions

| | |
|---|---|
| **ID** | VULN-014 (raw ZN-035) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **5.4** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (post-compromise) |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: user/customer (own account) |
| **Attacker gains** | A captured/rogue session survives the victim (or admin) changing the password — account recovery does not lock the attacker out. |

## Summary
Neither the self-service password change nor either lost-password reset flow evicts existing
sessions. An attacker who holds a live session therefore keeps it after the victim changes their
password — defeating the standard "change your password to kick out the intruder" response.
Confirmed: after session A changed the account password, session B (an independent, pre-existing
login) remained fully authenticated.

## How it works (mechanism & code trace)
`Kernel/Output/HTML/Preferences/Password.pm`:
```perl
219:  my $Success = $UserObject->SetPassword( UserLogin => ..., PW => $GetParam{NewPw} );
...
227:  return 1;                       # <-- no RemoveSessionByUser() anywhere in this module
```
Every *other* preference module evicts sessions on change — e.g. `Preferences/Theme.pm:118` and
`Preferences/Language.pm:145` call `RemoveSessionByUser` — proving the omission is specific to the
password module. The lost-password reset flows in `InterfaceAgent.pm`/`InterfaceCustomer.pm`
likewise set a new password without `RemoveSessionByUser`.

Dynamic confirmation: two sessions (A, B) for one account; A changes the password (login with the
new password then succeeds, so it took effect); B's old session cookie still returns the
authenticated dashboard.

## Why it is a vulnerability
Session lifecycle best practice (OWASP) requires invalidating all other sessions when credentials
change, precisely so that a password change/reset can be used to evict an attacker who obtained a
session (via XSS, token theft, a shared machine, or VULN-037-style guessing). Here the primary
recovery action is ineffective: the victim (or an admin resetting a compromised account) changes
the password, believes the account is secured, yet the attacker's session persists until it
naturally expires. This is a session-management defect, not intended behaviour — the sibling
modules show the framework already has the eviction primitive.

## Reproduction
`./run.sh`: opens two sessions for one agent, changes the password via one, and shows the other
still authenticates (`session_B_still_valid_after_change=True`).

## Impact
Post-compromise persistence: password change/reset fails to terminate an attacker's session,
undermining incident response and account recovery. Applies to agents and customers.

## Suggested fix
In `Preferences/Password.pm` (and both reset flows) call
`$SessionObject->RemoveSessionByUser(UserLogin => ...)` (optionally preserving the current
session) after a successful `SetPassword`, mirroring `Theme.pm`/`Language.pm`.

## References
- OWASP Session Management Cheat Sheet (renew/terminate sessions on credential change). CWE-613
  (Insufficient Session Expiration).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 50 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. NVD API keyword pull for "Znuny" (17) and "OTRS" (120) grepped for session / password — CVE-2020-1776 (session kept after agent rename/invalidate), CVE-2026-78357 (OTRS JWT tokens not revoked on deactivation/password change), CVE-2020-1773 (predictable session IDs), CVE-2025-24387/24390 (cookie attributes); nothing for Znuny on password change
2. OSA-2020-13 / CVE-2020-1776 advisory page fetched — triggers are *rename* and *set to invalid*; "the page does not mention password changes"; fixed CE 6.0.29
3. OSA-2026-14 / CVE-2026-78357 advisory page fetched — JWT session revocation in the OTRS 8+/2023+ Agent/External Interface (CWE-613), fixed OTRS 2026.7.1, "no OTRS 7 patches"; OTRS Community Edition 6 and Znuny are not mentioned
4. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB (19 entries), Debian tracker reviewed — no session-invalidation advisory for Znuny
5. `gh search issues --repo znuny/Znuny "session password"` / `"RemoveSessionByUser password"` — none; commit search found only d6f287dc (2026-08-31, a comment on `RemoveSessionByUser` scoping, not a password-change hook)
6. (Shared WebSearch budget was exhausted before this finding; evidence comes from the primary sources above.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-78357 / OSA-2026-14 — identical root-cause class (credential change does not revoke existing authentication) but in OTRS's JWT token layer (OTRS 8+/2023+), a codebase Znuny does not share; Znuny's `Kernel::System::AuthSession` + `Preferences/Password.pm` / lost-password flows are not covered
- CVE-2020-1776 / OSA-2020-13 — OTRS CE 6 sessions kept after rename / invalidation; same `AuthSession` component, different trigger (password change not included, and Znuny inherits that fix)

**Reasoning:** No advisory or issue states that Znuny's self-service password change (`Preferences/Password.pm`) or either lost-password reset flow leaves existing sessions valid. The closest item, CVE-2026-78357 published nine days ago, describes the same weakness in OTRS's separate JWT implementation and explicitly scopes OTRS 7+/JWT, not Community Edition 6 or Znuny; it is a strong signal the class is on researchers' radar, so confidence is capped at 50, but the Znuny component and code path are not publicly disclosed.
