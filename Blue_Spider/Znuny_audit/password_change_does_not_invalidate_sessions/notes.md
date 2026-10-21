# VULN-014 — Password change and lost-password reset do NOT invalidate existing sessions

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (5.4)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- An agent account with two concurrent logged-in sessions (jars A and B). Any user/customer.

## Request / Response
Session A: `POST AgentPreferences;Subaction=Update;Group=Password;CurPw;NewPw;NewPw1;ChallengeToken`.
Then session B (old cookie) `GET AgentDashboard` → still "You are logged in". Login with the new
password also succeeds (change took effect). See `response.txt`.

## Observation
`password_changed=True`, `session_B_still_valid_after_change=True`. Confirms
`Preferences/Password.pm:219-227` calls `SetPassword` then `return 1` with no
`RemoveSessionByUser` — while sibling preference modules (Theme.pm:118, Language.pm:145) DO evict
sessions.

## Side effects
Changes a throwaway agent's password. Idempotent (random suffix).

## Research & references
- OWASP Session Management Cheat Sheet ("renew/terminate sessions on password change"). CWE-613.

## Notes
Same gap in the lost-password reset flows (InterfaceAgent/InterfaceCustomer): neither calls
`RemoveSessionByUser`, so an attacker's session survives the victim/admin resetting the password —
defeating the primary account-recovery action.
