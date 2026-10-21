# VULN-015 — Active=0 preference-group bypass → clear admin-provisioned 2FA secret

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (5.4, 2FA-conditional)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- An agent with an admin-provisioned `UserGoogleAuthenticatorSecretKey` (set here via
  `SetPreferences`). Full impact needs `AuthTwoFactorModule=GoogleAuthenticator` +
  `AllowEmptySecret=1` (default).

## Request / Response
`POST AgentPreferences;Subaction=Update;Group=GoogleAuthenticatorSecretKey;
UserGoogleAuthenticatorSecretKey=` (empty) + agent ChallengeToken → the stored secret becomes
empty (`user_preferences` value None). See `response.txt`.

## Observation
`before='ABCDEFGHIJKLMNOP' after=None`. Confirms `AgentPreferences.pm:251` checks only that the
Group is *registered* (`PreferencesGroups###GoogleAuthenticatorSecretKey` is Valid=1) and not that
it is *Active* (it ships Active=0, hidden from the UI); `Generic.pm:82-89` then `SetPreferences`
unconditionally, and the ValidateRegex `^([A-Z2-7]{16}|)$` accepts an empty value.

## Side effects
Clears a throwaway agent's 2FA secret. Idempotent.

## Research & references
- OWASP Authentication Cheat Sheet (MFA); CWE-862. Distinct from CVE-2025-43926 (which fixed the
  `AJAXUpdate` path, not this `Update` path).

## Notes
The bug is the missing Active check on the write path; a hidden preference group remains writable.
With `AllowEmptySecret=1` (default), a cleared secret means the next login passes with password
only — a self-service 2FA downgrade.
