# VULN-015 — `Active=0` preference-group bypass → clear admin-provisioned 2FA secret

| | |
|---|---|
| **ID** | VULN-015 (raw ZN-028) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **5.4** (2FA-conditional) — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: any agent/customer (own account) |
| **Attacker gains** | Self-service removal of an admin-mandated 2FA secret, downgrading the account to password-only. |

## Summary
The preferences `Update` handler validates only that the target preference **group** is
*registered*, never that it is *Active*. The GoogleAuthenticator 2FA-secret group ships `Active=0`
(hidden from the UI) but registered, and its value regex accepts an empty string. A user can
therefore POST that hidden group with an empty value and clear their own admin-provisioned 2FA
secret. Confirmed: an agent's admin-set secret (`ABCDEFGHIJKLMNOP`) was cleared to empty via one
request.

## How it works (mechanism & code trace)
`Kernel/Modules/AgentPreferences.pm`, `Subaction=Update`:
```perl
250:  my %Preferences = %{ ... ->Get('PreferencesGroups') };
251:  if ( !$Preferences{$Group} ) { return $LayoutObject->ErrorScreen(...); }   # REGISTERED-only check
```
The `Active` flag is consulted only in the *display* loop (`:587`), not here — so a group that is
`Active=0` (hidden) is still writable. The write is unconditional in
`Kernel/Output/HTML/Preferences/Generic.pm:82-89` (`SetPreferences`). The group definition
(`Framework.xml:3464-3482`) is `Valid=1` (registered), ships `Active=0`, `PrefKey=
UserGoogleAuthenticatorSecretKey`, and `ValidateRegex ^([A-Z2-7]{16}|)$` — the trailing `|`
allows an **empty** value. So `Group=GoogleAuthenticatorSecretKey&UserGoogleAuthenticatorSecretKey=`
passes validation and stores an empty secret. Dynamic proof: `user_preferences` value went from
`ABCDEFGHIJKLMNOP` to empty/None.

## Why it is a vulnerability
Setting a group `Active=0` is the mechanism admins use to *provision* a 2FA secret centrally while
preventing the user from editing it in their own preferences (the config docs say exactly this:
"Active=0 will only prevent agents from editing settings of this group in their personal
preferences"). The `Update` path breaks that guarantee: because it never checks `Active`, the user
*can* edit the hidden group — and, because empty is a valid value, they can erase the secret. With
`AuthTwoFactorModule::AllowEmptySecret=1` (default), an empty secret means the next login needs no
TOTP token, so the user unilaterally downgrades their account below the admin-mandated MFA policy.
This is a broken-auth/authorization defect, distinct from CVE-2025-43926 (which fixed the
`AJAXUpdate` path, not this `Update` path).

## Reproduction
1. Admin provisions a 2FA secret for an agent (`SetPreferences UserGoogleAuthenticatorSecretKey`).
2. As that agent, `POST AgentPreferences;Subaction=Update;Group=GoogleAuthenticatorSecretKey;
UserGoogleAuthenticatorSecretKey=` (empty) with the agent's ChallengeToken. 3. `./run.sh`:
```
[PROOF] stored 2FA secret before='ABCDEFGHIJKLMNOP' after=None
```

## Impact
A user overrides an admin-enforced MFA policy on their own account (integrity of the auth policy);
combined with the default `AllowEmptySecret=1`, the account reverts to single-factor, expanding the
blast radius of any password compromise (VULN-030/VULN-037). Conditional on 2FA being deployed.

## Suggested fix
In `AgentPreferences.pm` (and `CustomerPreferences.pm`), reject the Update when the target group's
`Active` is 0 for a self-service request (mirror the display-path check). Independently, do not let
the 2FA-secret regex accept an empty value from the user-facing path.

## References
- OWASP Authentication Cheat Sheet (MFA enforcement). CWE-862 (Missing Authorization). Related:
  CVE-2025-43926 (AJAXUpdate variant).
EOF
echo written
## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. ZSA-2025-07 / CVE-2025-43926 advisory page fetched (scanner's cited relative) — "agent with a valid session can elevate his permission via XSS by modifying his own preferences" via the `AgentPreferences` *UpdateAJAX* subaction with arbitrary keys; nothing about `Active=0` groups or the 2FA secret
2. NVD API keyword pull for "Znuny"/"OTRS" grepped for preference / two-factor / 2FA / GoogleAuthenticator — only CVE-2025-43926 and CVE-2026-50591 (stored XSS via user preferences); no 2FA-bypass or hidden-group CVE
3. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB (19 entries), Debian tracker reviewed — no entry on preference-group activation or 2FA secrets
4. `gh search issues --repo znuny/Znuny "GoogleAuthenticator"` — no results
5. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-43926 / ZSA-2025-07 — same module (`AgentPreferences`) but the `UpdateAJAX` path writing arbitrary preference keys; the `Update` path's missing `Active` check and the empty-secret regex are not covered
- CVE-2026-50591 / ZSA-2026-11 — stored XSS via user preferences; different class

**Reasoning:** No public advisory describes writing to a registered-but-`Active=0` preference group through `AgentPreferences;Subaction=Update`, nor the resulting self-service clearing of an admin-provisioned Google Authenticator secret. The preferences module has had two recent advisories, so it is an actively audited area and the vendor's CVE-2025-43926 fix touched the neighbouring code path, which lowers confidence somewhat; still, the specific defect and its 2FA-downgrade impact are not described anywhere public.
