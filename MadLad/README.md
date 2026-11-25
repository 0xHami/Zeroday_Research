<p align="center"><img src="spider.png" alt="Blue Spider" width="160"></p>
<h1 align="center">MadLad — Rocket.Chat Audit</h1>
<p align="center"><b>40 confirmed, previously undisclosed vulnerabilities and 8 proven attack chains in Rocket.Chat 9.1.0-develop</b></p>

## What is this?

This folder is the complete output of one [Blue Spider](../Blue_Spider/README.md) run against [Rocket.Chat](https://github.com/rocketchat/rocket.chat), the self-hosted team chat platform. Blue Spider is Kohi Research Corporation's autonomous source-code security auditor: it builds the target inside an isolated Docker lab, has a team of AI agents audit the code, and then **proves each finding with a working exploit** run from a sandboxed attacker container. Anything it cannot demonstrate against the running software is labelled as unproven, not reported as fact.

Unlike the curated [Blue Spider archive](../Blue_Spider/README.md), nothing here has been removed. Every finding the engine produced is still in `rocket.chat/exploits/`. This README sorts them by how far each one got:

1. **[Previously undisclosed vulnerabilities](#previously-undisclosed-vulnerabilities).** 40 findings that are dynamically confirmed, rated Medium or above (CVSS 3.1), and have no matching public report. These are the disclosure candidates.
2. **[Attack chains](#attack-chains).** 8 end-to-end compositions of confirmed findings, each proven by its own exploit.
3. **[Confirmed but already public](#confirmed-but-already-public)**: 13 reproduced bugs that match an existing issue, PR or report and are still unpatched in this build.
4. **[Everything else](#everything-else)**: 4 confirmed Low/Info findings, 15 that need a human (an Enterprise licence, an external service or a browser), and 12 that did not reproduce or turned out to be intended behaviour.

## Target

| | |
|---|---|
| Product | Rocket.Chat (Community edition, unlicensed, not Cloud-registered) |
| Repository | https://github.com/rocketchat/rocket.chat |
| Version audited | 9.1.0-develop (untagged, branch `develop`) |
| Commit | `9f3d6c8c48911e32ed6c2ce36befd431faa71190` |
| Lab | Vendor release image `rocketchat/rocket.chat:sha-9f3d6c8` behind Traefik, MongoDB 8.2.12 replica set, NATS 2.11, Mailpit |
| Baseline | Every security control at its shipped default: 2FA, password policy, failed-login blocking, REST rate limiter, CSP, protected files |
| Discovered / validated | 2026-11-23 to 2026-11-24 / 2026-11-24 |
| Known-issue check | 2026-11-24 (CVE/NVD, GHSA, OSV, vendor advisories, HackerOne, the GitHub issue tracker and PRs, upstream commits after the audited one) |

## At a glance

| | |
|---|---|
| Findings produced by the engine | 84 |
| Dynamically confirmed | 57 (needs manual 15, failed 11, intended 1) |
| **Confirmed, Medium+, not publicly known** | **40** (High 4 / Medium 36) |
| Of those, unauthenticated | 15 |
| Of those, exploitable on a default install | 20 |
| Confirmed but already public (unpatched) | 13 |
| Proven attack chains | 8 (High 5 / Medium 3) |
| Most common weakness classes (the 40) | CWE-863 (8), CWE-862 (6), CWE-400 (5), CWE-200 (4), CWE-203 (3) |
| Detection and exploitation artifacts | 114 Metasploit auxiliary modules (two per confirmed finding; msftidy-clean, not yet run against the lab), 20 Sigma rules validated against the lab's own logs |

**What was not found:** no unauthenticated remote code execution, no SQL or command injection, no unauthenticated file read, and no bypass of room membership on the main message routes. The one code-execution candidate (VULN-027, an isolated-vm sandbox escape) did not reproduce.

## What was discovered

- **Omnichannel customers can be impersonated by anyone.** A phone number returns a customer's Livechat token ([VULN-001](rocket.chat/exploits/VULN-001-livechat_visitor_token_idor/)). One open chat of your own lets you subscribe to everyone else's ([VULN-076](rocket.chat/exploits/VULN-076-livechat_stream_room_confusion/)). Agents get visitor tokens through an endpoint a previous GHSA fix missed ([VULN-077](rocket.chat/exploits/VULN-077-visitor_tokens_in_pages_visited/)). Anonymous callers write into any room ([VULN-046](rocket.chat/exploits/VULN-046-livechat_page_visited_anonymous_write/)) or read Omnichannel rooms ([VULN-047](rocket.chat/exploits/VULN-047-anonymous_read_omnichannel_rooms/)). Combined, these give [CHAIN-003](#attack-chains).
- **The second factor has holes.** A stolen session reads the TOTP seed ([VULN-004](rocket.chat/exploits/VULN-004-totp_seed_disclosed_to_session/)) and survives the victim's password change ([VULN-033](rocket.chat/exploits/VULN-033-realtime_session_survives_revocation/)). Codes are replayable ([VULN-040](rocket.chat/exploits/VULN-040-totp_code_replay/)), OAuth logins skip 2FA during the grace window ([VULN-043](rocket.chat/exploits/VULN-043-oauth_login_skips_2fa_grace/)), and deactivated accounts still log in through OAuth ([VULN-030](rocket.chat/exploits/VULN-030-deactivated_account_oauth_login_code/)).
- **Deleted messages are not deleted.** Thread roots ([VULN-059](rocket.chat/exploits/VULN-059-deleted_thread_root_disclosure/)) and, with edit history on, every deleted or edited message ([VULN-049](rocket.chat/exploits/VULN-049-deleted_content_via_edit_history/)) stay readable to members.
- **Moderation does not hold.** Banned members keep notifications and files ([VULN-009](rocket.chat/exploits/VULN-009-ban_bypass_notifications_and_files/)), invite links outlive their creator and cannot be revoked by room owners ([VULN-035](rocket.chat/exploits/VULN-035-invite_links_unrevocable/)), and ban lists are visible to every member ([VULN-068](rocket.chat/exploits/VULN-068-ban_list_disclosure_to_any_member/)).
- **Delegated roles reach further than intended.** A delegated role manager can demote every administrator ([VULN-069](rocket.chat/exploits/VULN-069-last_admin_removal/)), one integration permission family edits the other's scripts ([VULN-061](rocket.chat/exploits/VULN-061-integration_type_confusion/)), and any user can create auto-join rooms ([VULN-058](rocket.chat/exploits/VULN-058-team_room_mass_assignment/)) and post forged system notices in them ([VULN-012](rocket.chat/exploits/VULN-012-forged_system_messages_via_mediaconfirm/)).
- **Anonymous denial of service.** A mailer ReDoS stalls the whole server for 20 s per request ([VULN-073](rocket.chat/exploits/VULN-073-mailer_placeholder_redos/)), unbounded metric labels grow memory until it runs out ([VULN-074](rocket.chat/exploits/VULN-074-metric_label_cardinality/)), and a shared rate-limit bucket lets one anonymous client block every web login ([VULN-078](rocket.chat/exploits/VULN-078-ddp_rest_shared_rate_limit_key/)). None of them needs an account.
- **Fixes applied to one call site but not its siblings.** VULN-075 and VULN-081 are unguarded outbound fetches next to guarded ones, VULN-077 is the endpoint a token-projection fix missed, and VULN-079 is an input-validation fix applied per method instead of at the model.

## Previously undisclosed vulnerabilities

Columns: **CVSS** is the engine's computed 3.1 base score. **CWE** is as cited in the write-up. **Auth** is the lowest privilege needed ("Any user" means any self-registered account; public registration is on by default). **Precondition** is the non-default configuration the bug needs (— means it works on a default install). **Novelty** is the Known Issue Check's confidence (0–100) that nothing public matches.

| # | Finding | Severity | CVSS | CWE | Auth | Precondition | Novelty |
|---:|---|---|---:|---|---|---|---:|
| 1 | [VULN-001](rocket.chat/exploits/VULN-001-livechat_visitor_token_idor/): Livechat visitor registration IDOR: a customer's phone number returns their visitor token, their email rebinds the record | High | 8.2 | CWE-639, CWE-200 | None | Omnichannel in use | 50 |
| 2 | [VULN-073](rocket.chat/exploits/VULN-073-mailer_placeholder_redos/): Mailer placeholder ReDoS survives the CVE-2021-32832 fix; the anonymous offline form feeds it unbounded text (20 s stall per request) | High | 7.5 | CWE-1333, CWE-400 | None | — | 45 |
| 3 | [VULN-074](rocket.chat/exploits/VULN-074-metric_label_cardinality/): Unbounded metric-label cardinality: anonymous `method.call` requests grow the metrics registry until memory runs out | High | 7.5 | CWE-770, CWE-400 | None | — | 60 |
| 4 | [VULN-030](rocket.chat/exploits/VULN-030-deactivated_account_oauth_login_code/): Deactivated and pending-approval accounts get working tokens through the OAuth login-code path; REST never re-checks `active` | High | 7.1 | CWE-288, CWE-863 | A deactivated / unapproved account | OAuth login provider | 40 |
| 5 | [VULN-004](rocket.chat/exploits/VULN-004-totp_seed_disclosed_to_session/): `users.info` returns the caller's raw `services` document: TOTP seed and backup-code hashes go to anyone holding the session | Medium | 6.8 | CWE-522, CWE-200 | Holder of the victim's session | — | 75 |
| 6 | [VULN-037](rocket.chat/exploits/VULN-037-pre_registration_squatting_survives_meld/): Pre-registration squatting survives the owner's OAuth claim: the email meld keeps the squatter's sessions and personal access tokens | Medium | 6.8 | CWE-283, CWE-1464 | None (self-registration) | OAuth login provider | 45 |
| 7 | [VULN-019](rocket.chat/exploits/VULN-019-hooks_integration_token_confusion/): `/hooks` accepts any integration's id + token, disabled ones included, and the add/remove sub-routes skip the enabled and impersonation checks | Medium | 6.5 | CWE-287, CWE-863 | Holder of any webhook URL | Integrations configured | 75 |
| 8 | [VULN-026](rocket.chat/exploits/VULN-026-markdown_parser_dos/): One message stalls the whole workspace: super-quadratic markdown parser, no length cap on attachment descriptions | Medium | 6.5 | CWE-407, CWE-400 | Any user | — | 25 |
| 9 | [VULN-033](rocket.chat/exploits/VULN-033-realtime_session_survives_revocation/): Password change, reset and remove-other-tokens leave realtime sessions alive, and an admin-set password is broadcast to them in clear | Medium | 6.5 | CWE-1466, CWE-201 | Holder of a stolen session | — | 55 |
| 10 | [VULN-045](rocket.chat/exploits/VULN-045-profanity_filter_dos/): Profanity filter runs a per-token, per-word regex scan on the request path, so one member stalls the server for seconds per message | Medium | 6.5 | CWE-407, CWE-400 | Any user | Profanity filter on | 75 |
| 11 | [VULN-069](rocket.chat/exploits/VULN-069-last_admin_removal/): `users.update` strips the admin role without `assign-admin-role` and with no last-admin guard | Medium | 6.5 | CWE-269 | Delegated role manager | Role management delegated | 45 |
| 12 | [VULN-061](rocket.chat/exploits/VULN-061-integration_type_confusion/): Integration update/delete trusts the caller-named type, so one integration permission family edits the other's objects, scripts included | Medium | 6.0 | CWE-863 | One integration permission family | Integration perms delegated | 75 |
| 13 | [VULN-006](rocket.chat/exploits/VULN-006-anonymous_apps_stream_subscription/): `stream-apps` / `stream-importers` accept anonymous subscriptions; app setting-changed events carry the new value, secrets included | Medium | 5.9 | CWE-200, CWE-862 | None | Apps-Engine app with settings | 80 |
| 14 | [VULN-024](rocket.chat/exploits/VULN-024-protected_files_public_cache/): Protected file downloads and personal data exports are marked publicly cacheable for a year | Medium | 5.9 | CWE-524 | None (shares the cache) | Shared HTTP cache in front | 65 |
| 15 | [VULN-047](rocket.chat/exploits/VULN-047-anonymous_read_omnichannel_rooms/): `channels.anonymousread` serves Omnichannel conversations and hidden messages to unauthenticated callers | Medium | 5.9 | CWE-863 | None | Anonymous read on | 60 |
| 16 | [VULN-076](rocket.chat/exploits/VULN-076-livechat_stream_room_confusion/): Livechat stream access is checked against the room named in `extraData`, so one visitor reads every other Livechat room live | Medium | 5.9 | CWE-639, CWE-863 | Livechat visitor (anonymous) | Omnichannel on | 70 |
| 17 | [VULN-035](rocket.chat/exploits/VULN-035-invite_links_unrevocable/): Room invite links cannot be revoked by the room's owners, outlive their creator's rights, and their use limit is not atomic | Medium | 5.4 | CWE-863, CWE-367 | Any user holding an invite link | — | 65 |
| 18 | [VULN-077](rocket.chat/exploits/VULN-077-visitor_tokens_in_pages_visited/): `livechat/visitors.pagesVisited` hands any agent the visitor tokens the GHSA-cqj7-h8cj-jmf2 fix removed from `visitors.info` | Medium | 5.4 | CWE-200, CWE-862 | Livechat agent | Omnichannel on | 55 |
| 19 | [VULN-046](rocket.chat/exploits/VULN-046-livechat_page_visited_anonymous_write/): Anonymous write into any room via `livechat/page.visited`, which resolves neither the visitor token nor the room | Medium | 5.3 | CWE-862 | None | Visitor navigation as message¹ | 75 |
| 20 | [VULN-078](rocket.chat/exploits/VULN-078-ddp_rest_shared_rate_limit_key/): DDP-over-REST bridges key rate limits on the caller's own `X-Auth-Token`: anonymous callers share one bucket, a rotating header escapes it | Medium | 5.3 | CWE-799, CWE-400 | None | — | 30 |
| 21 | [VULN-066](rocket.chat/exploits/VULN-066-forgot_password_ddp_when_disabled/): Disabling password reset closes only the REST route; Meteor's `forgotPassword` still mails reset links anonymously | Medium | 4.8 | CWE-424, CWE-640 | None | Password reset disabled | 45 |
| 22 | [VULN-054](rocket.chat/exploits/VULN-054-offline_form_html_injection/): Omnichannel offline form mails visitor fields unescaped to the support mailbox, with the host field inside an `href` | Medium | 4.7 | CWE-116 | None | Offline-message recipient set | 55 |
| 23 | [VULN-007](rocket.chat/exploits/VULN-007-workspace_pii_disclosure_to_any_user/): `users.listByStatus` leaks every account's email, roles and last login to any user | Medium | 4.3 | CWE-359, CWE-203 | Any user | — | 70 |
| 24 | [VULN-009](rocket.chat/exploits/VULN-009-ban_bypass_notifications_and_files/): Room ban not enforced on notifications or file downloads: the banned member keeps following the room | Medium | 4.3 | CWE-863 | Banned room member | — | 70 |
| 25 | [VULN-011](rocket.chat/exploits/VULN-011-typing_write_into_inaccessible_room/): Typing indicators accepted for rooms the caller cannot access, private groups and DMs included | Medium | 4.3 | CWE-862 | Any user | — | 85 |
| 26 | [VULN-012](rocket.chat/exploits/VULN-012-forged_system_messages_via_mediaconfirm/): `rooms.mediaConfirm` mass assignment: a member sets the message type `t` and forges the server's own system notices | Medium | 4.3 | CWE-915, CWE-451 | Room member | — | 55 |
| 27 | [VULN-020](rocket.chat/exploits/VULN-020-role_membership_authorization_oracle/): `roles.addUserToRole` answers "already in role" before checking permission, revealing any user's roles in any room | Medium | 4.3 | CWE-203 | Any user | — | 80 |
| 28 | [VULN-041](rocket.chat/exploits/VULN-041-star_privacy_bypass/): Star privacy is enforced only in the REST serializer; message queries and the realtime broadcast reveal who starred what | Medium | 4.3 | CWE-359 | Room member | — | 70 |
| 29 | [VULN-042](rocket.chat/exploits/VULN-042-attacker_text_in_platform_email/): Attacker-chosen text inside the workspace's own registration and reset emails, sent to any address | Medium | 4.3 | CWE-451 | None | — | 30 |
| 30 | [VULN-049](rocket.chat/exploits/VULN-049-deleted_content_via_edit_history/): With edit history on, deleted and edited-away content stays readable through personal exports and `chat.getMessage` | Medium | 4.3 | CWE-212 | Room member | Message edit history on | 55 |
| 31 | [VULN-058](rocket.chat/exploits/VULN-058-team_room_mass_assignment/): `teams.create` mass assignment sets `default`, `featured` and other admin-only room flags | Medium | 4.3 | CWE-915 | Any user | — | 40 |
| 32 | [VULN-059](rocket.chat/exploits/VULN-059-deleted_thread_root_disclosure/): `chat.syncThreadsList` returns the hidden full copy of a deleted thread root | Medium | 4.3 | CWE-212 | Room member | — | 30 |
| 33 | [VULN-062](rocket.chat/exploits/VULN-062-preview_revocation_alternate_routes/): Revoking `preview-c-room` closes only history and the live stream; ten other routes still serve non-members | Medium | 4.3 | CWE-863 | User without `preview-c-room` | `preview-c-room` revoked | 35 |
| 34 | [VULN-067](rocket.chat/exploits/VULN-067-join_code_recovery_via_sort_oracle/): `channels.list` sorts on client-chosen fields before projecting, so a room's join code is recoverable by bisection | Medium | 4.3 | CWE-203 | Any user | — | 45 |
| 35 | [VULN-068](rocket.chat/exploits/VULN-068-ban_list_disclosure_to_any_member/): `rooms.bannedUsers` returns a room's ban list to any member; the client reserves it for `ban-user` holders | Medium | 4.3 | CWE-862 | Room member | — | 75 |
| 36 | [VULN-070](rocket.chat/exploits/VULN-070-autotranslate_missing_permission/): `autotranslate.translateMessage` skips the `auto-translate` permission its sibling routes require | Medium | 4.3 | CWE-862 | Any user | Auto-translate configured | 50 |
| 37 | [VULN-079](rocket.chat/exploits/VULN-079-nosql_operator_room_name_oracle/): NoSQL operator injection in `getRoomByTypeAndName`: private-room names enumerable by regex through two error codes | Medium | 4.3 | CWE-943, CWE-204 | Any user | — | 55 |
| 38 | [VULN-040](rocket.chat/exploits/VULN-040-totp_code_replay/): Second-factor codes are not single-use: TOTP replays inside the window, a backup code redeems twice concurrently | Medium | 4.2 | CWE-294, CWE-362 | Password + one observed code | — | 80 |
| 39 | [VULN-043](rocket.chat/exploits/VULN-043-oauth_login_skips_2fa_grace/): OAuth login skips 2FA for any account inside the registration grace window, even one with TOTP enrolled | Medium | 4.2 | CWE-288, CWE-308 | The account's IdP login | OAuth login provider | 70 |
| 40 | [VULN-081](rocket.chat/exploits/VULN-081-livechat_webhook_ssrf/): Livechat webhook sender and its test route keep `ignoreSsrfValidation` on for non-admin Omnichannel roles (SSRF) | Medium | 4.1 | CWE-918 | livechat-manager / -monitor | Omnichannel on | 50 |

¹ With the setting off, the same request still writes a hidden message into any room.

Each folder holds `writeup.md` (full technical write-up ending in a **Known Issue Check**), `finding.json`, a reproducible `automation.py`, the raw `request.http` / `response.txt`, the `run.log`, captured `evidence/`, an `escalation/` record, two Metasploit modules under `msf/`, and a Sigma rule under `detection/` where the attack shows in an access log.

## Attack chains

Every chain is built only from CONFIRMED findings and was proven end to end against the lab on 2026-11-24. Details, and the triage candidates that were dropped and why, are in [rocket.chat/chains/](rocket.chat/chains/README.md).

| Chain | Severity | What it achieves | Built from |
|---|---|---|---|
| [CHAIN-001](rocket.chat/chains/CHAIN-001-reset_link_to_permanent_account_ownership/) | High | One captured password-reset link becomes permanent ownership of a TOTP-protected account, recovery address included | [VULN-015](rocket.chat/exploits/VULN-015-mfa_bypass_via_password_reset/) → [VULN-004](rocket.chat/exploits/VULN-004-totp_seed_disclosed_to_session/) → *email-change step-up* → [VULN-033](rocket.chat/exploits/VULN-033-realtime_session_survives_revocation/) |
| [CHAIN-002](rocket.chat/chains/CHAIN-002-ordinary_account_defeats_the_second_factor/) | High | An account from the public registration form widens the TOTP window and lockouts, then guesses into a TOTP-protected administrator | [VULN-007](rocket.chat/exploits/VULN-007-workspace_pii_disclosure_to_any_user/) → [VULN-057](rocket.chat/exploits/VULN-057-settings_write_via_telemetry/) → [VULN-032](rocket.chat/exploits/VULN-032-lockout_bypass_by_email/) |
| [CHAIN-003](rocket.chat/chains/CHAIN-003-anonymous_omnichannel_customer_takeover/) | High | An unauthenticated outsider eavesdrops on support chats, becomes a chosen customer, and has the workspace mail that customer's transcript to them | [VULN-076](rocket.chat/exploits/VULN-076-livechat_stream_room_confusion/) → [VULN-001](rocket.chat/exploits/VULN-001-livechat_visitor_token_idor/) → [VULN-051](rocket.chat/exploits/VULN-051-livechat_transcript_html_relay/) |
| [CHAIN-004](rocket.chat/chains/CHAIN-004-delegated_role_strips_all_administrators/) | High | A delegated help-desk role enumerates and demotes every administrator, then breaks the auth policy nobody is left to repair | [VULN-020](rocket.chat/exploits/VULN-020-role_membership_authorization_oracle/) → [VULN-069](rocket.chat/exploits/VULN-069-last_admin_removal/) → [VULN-057](rocket.chat/exploits/VULN-057-settings_write_via_telemetry/) |
| [CHAIN-005](rocket.chat/chains/CHAIN-005-oauth_meld_to_admin_surviving_deactivation/) | High | An identity-provider account takes over an administrator past enrolled TOTP, and deactivation does not end the access | [VULN-002](rocket.chat/exploits/VULN-002-oauth_unverified_email_meld/) → [VULN-043](rocket.chat/exploits/VULN-043-oauth_login_skips_2fa_grace/) → [VULN-030](rocket.chat/exploits/VULN-030-deactivated_account_oauth_login_code/) |
| [CHAIN-006](rocket.chat/chains/CHAIN-006-self_made_default_room_speaks_as_the_server/) | Medium | An ordinary account builds a room every new employee is auto-joined to, and speaks in it with the server's own voice | [VULN-058](rocket.chat/exploits/VULN-058-team_room_mass_assignment/) → *default channels* → [VULN-012](rocket.chat/exploits/VULN-012-forged_system_messages_via_mediaconfirm/) |
| [CHAIN-007](rocket.chat/chains/CHAIN-007-ban_does_not_close_the_room/) | Medium | A room ban removes nobody: the banned member keeps reading and returns through an invite the owners cannot revoke | [VULN-035](rocket.chat/exploits/VULN-035-invite_links_unrevocable/) → [VULN-009](rocket.chat/exploits/VULN-009-ban_bypass_notifications_and_files/) → *notification prefs* → *public registration* |
| [CHAIN-008](rocket.chat/chains/CHAIN-008-deleted_content_recovered_by_anyone/) | Medium | Deleting a message deletes nothing: an outsider learns what was deleted, a member reads it back, an anonymous caller reads it too | [VULN-010](rocket.chat/exploits/VULN-010-deleted_message_metadata_disclosure/) → [VULN-059](rocket.chat/exploits/VULN-059-deleted_thread_root_disclosure/) → [VULN-049](rocket.chat/exploits/VULN-049-deleted_content_via_edit_history/) → [VULN-047](rocket.chat/exploits/VULN-047-anonymous_read_omnichannel_rooms/) |

## Confirmed but already public

These reproduce on 9.1.0-develop but match an existing public report, so they are **not** new disclosures. All of them are still unpatched in this build.

| Finding | Severity | CVSS | Public reference |
|---|---|---:|---|
| [VULN-057](rocket.chat/exploits/VULN-057-settings_write_via_telemetry/): `statistics.telemetry` lets any user increment any numeric setting: TOTP window, lockouts, rate limits | High | 8.1 | [Issue #42484](https://github.com/RocketChat/Rocket.Chat/issues/42484), closed as "we will track it", no fix |
| [VULN-002](rocket.chat/exploits/VULN-002-oauth_unverified_email_meld/): OAuth links accounts on an unverified email claim, so an IdP identity melds into any local account | High | 7.4 | [PR #43840](https://github.com/RocketChat/Rocket.Chat/pull/43840) review: vendor calls it a known issue and leaves it |
| [VULN-015](rocket.chat/exploits/VULN-015-mfa_bypass_via_password_reset/): `resetPassword` and `verifyEmail` are exempt from 2FA and return a session | High | 7.4 | [HackerOne #1701378](https://hackerone.com/reports/1701378); issue #10183 closed without a fix |
| [VULN-036](rocket.chat/exploits/VULN-036-role_mandatory_2fa_client_side/): Role-mandatory 2FA is enforced only by the web client; REST and DDP stay single-factor | Medium | 6.8 | [PR #9748](https://github.com/RocketChat/Rocket.Chat/pull/9748) discussion (2019); 2025 fix touched the client only |
| [VULN-003](rocket.chat/exploits/VULN-003-realtime_event_injection_notify_room_users/): `notify-room-users` cross-user event injection (userData and video-conference events) | Medium | 6.4 | [Issue #42669](https://github.com/RocketChat/Rocket.Chat/issues/42669); fix PR #42754 open. Residual of GHSA-r3v3-v742-55j5 |
| [VULN-014](rocket.chat/exploits/VULN-014-import_file_path_control/): `downloadPublicImportFile` reads any local path into the importer; the error is an existence oracle | Medium | 4.9 | [Issue #42355](https://github.com/RocketChat/Rocket.Chat/issues/42355); fix PR #42357 open |
| [VULN-032](rocket.chat/exploits/VULN-032-lockout_bypass_by_email/): Per-user lockout bypassed by logging in with the email address or a `totp` envelope | Medium | 4.8 | [Issue #40195](https://github.com/RocketChat/Rocket.Chat/issues/40195), closed with no fix merged |
| [VULN-051](rocket.chat/exploits/VULN-051-livechat_transcript_html_relay/): Livechat transcript relays visitor-written HTML from the workspace's mail address to any recipient | Medium | 4.7 | [Issue #42432](https://github.com/RocketChat/Rocket.Chat/issues/42432); fix PR #42433 open |
| [VULN-010](rocket.chat/exploits/VULN-010-deleted_message_metadata_disclosure/): `chat.getDeletedMessages` has no room authorization: deleted-message ids and timing for any room | Medium | 4.3 | [Issue #42481](https://github.com/RocketChat/Rocket.Chat/issues/42481), closed as "we will track it", no fix |
| [VULN-055](rocket.chat/exploits/VULN-055-retention_override_without_permission/): `retentionOverrideGlobal` has no permission check: any room owner exempts their room from retention | Medium | 4.3 | [PR #43383](https://github.com/RocketChat/Rocket.Chat/pull/43383) pins the behaviour in tests, no fix |
| [VULN-060](rocket.chat/exploits/VULN-060-password_policy_bypass_via_ddp/): Meteor `resetPassword` / `changePassword` ignore the password policy | Medium | 4.3 | [Issue #9434](https://github.com/RocketChat/Rocket.Chat/issues/9434) (open since 2018); policy leg unreported |
| [VULN-071](rocket.chat/exploits/VULN-071-e2e_waiting_users_membership_disclosure/): `e2e.fetchUsersWaitingForGroupKey` discloses private rooms' members | Low | 3.1 | [PR #41953](https://github.com/RocketChat/Rocket.Chat/pull/41953) open, unmerged |
| [VULN-005](rocket.chat/exploits/VULN-005-anonymous_permission_map/): Anonymous `permissions/get` returns the permission-to-role map | Info | 0.0 | [Issue #39821](https://github.com/RocketChat/Rocket.Chat/issues/39821) / PR #39822, both closed unmerged |

## Everything else

### Confirmed, Low / Informational

| Finding | Severity | CVSS | CWE | Novelty |
|---|---|---:|---|---:|
| [VULN-018](rocket.chat/exploits/VULN-018-oauth_userinfo_expired_token/): `/oauth/userinfo` accepts expired access tokens for 30 days; only the REST bearer path checks `expires` | Low | 3.7 | CWE-672 | 70 |
| [VULN-008](rocket.chat/exploits/VULN-008-stale_stream_subscription_after_revocation/): Room-message stream authorization is never re-evaluated: a previewer keeps receiving a channel after it is made private | Low | 3.1 | CWE-863 | 40 |
| [VULN-063](rocket.chat/exploits/VULN-063-missing_rest_rate_limiting/): On a fresh install the REST API has no per-route rate limiting until the server restarts | Info | 0.0 | CWE-799 | 30 |
| [VULN-084](rocket.chat/exploits/VULN-084-register_account_enumeration/): `users.register` answers "Email already exists" before checking whether registration is open | Info | 0.0 | CWE-204 | 60 |

### Needs manual verification

These are source-traced, but the sealed, unlicensed lab could not exercise them. Several are real candidates for follow-up, especially the CAS and SAML account-takeover paths.

| Finding | Severity | CVSS | What is missing |
|---|---|---:|---|
| [VULN-044](rocket.chat/exploits/VULN-044-cas_session_fixation/): CAS session fixation: the credential token is chosen in the service URL | High | 8.1 | Needs a trusted CAS server over HTTPS |
| [VULN-031](rocket.chat/exploits/VULN-031-saml_assertion_not_bound_to_sp/): SAML assertions not bound to this SP (no Audience, Recipient, Destination or InResponseTo check) | High | 7.4 | SAML is a licensed Enterprise module |
| [VULN-048](rocket.chat/exploits/VULN-048-external_frame_token_in_url/): Omnichannel external frame puts the agent's plaintext session token in the frame URL | High | 7.4 | Agent-side browser drive not run |
| [VULN-034](rocket.chat/exploits/VULN-034-url_parameter_session_handoff/): URL-parameter session handoff via `?loginClient=mobile` and `?resumeToken=` | Medium | 6.8 | Browser drive not run |
| [VULN-039](rocket.chat/exploits/VULN-039-apple_identity_token_replay/): Apple identity tokens replayable across workspaces (shared iOS audience, no nonce) | Medium | 6.8 | Needs Apple-signed identity tokens |
| [VULN-075](rocket.chat/exploits/VULN-075-importer_ssrf_raw_http/): Pending-file importer fetches export URLs with raw HTTP, bypassing the SSRF guard | Medium | 6.8 | Pending-file record not seeded in time |
| [VULN-053](rocket.chat/exploits/VULN-053-irc_bridge_room_exposure/): IRC bridge mirrors private groups and joins IRC users into same-named rooms | Medium | 6.5 | Needs an IRC peer |
| [VULN-013](rocket.chat/exploits/VULN-013-email_direct_reply_spoofing/): Email Direct Reply takes the posting identity from the `From` header | Medium | 5.9 | Mail poller interval not waited out |
| [VULN-052](rocket.chat/exploits/VULN-052-smarsh_export_html_injection/): Smarsh compliance export interpolates message text into archived HTML unescaped | Medium | 5.4 | Smarsh is a licensed Enterprise module |
| [VULN-064](rocket.chat/exploits/VULN-064-marketplace_cloud_token_exposure/): Apps marketplace REST routes hand any user a workspace Cloud token with purchase scope | Medium | 5.4 | Needs a Cloud-registered workspace |
| [VULN-050](rocket.chat/exploits/VULN-050-slack_bridge_name_binding/): Slack bridge binds channels and users by name | Medium | 4.8 | Needs a real Slack workspace |
| [VULN-028](rocket.chat/exploits/VULN-028-ai_search_prompt_injection/): Indirect prompt injection in AI Search; answers render markdown that fetches attacker URLs | Medium | 4.4 | Needs the licensed AI module + a model provider |
| [VULN-056](rocket.chat/exploits/VULN-056-postmessage_any_origin/): `postMessage` command channels accept any origin | Medium | 4.3 | Two-document browser drive not run |
| [VULN-038](rocket.chat/exploits/VULN-038-videoconf_share_chat_authorization/): `video-conference.share-chat` skips the membership and send checks of discussion creation | Medium | 4.2 | Needs a marketplace video-conference app |
| [VULN-082](rocket.chat/exploits/VULN-082-irc_parser_redos/): CVE-2025-5892's IRC parser ReDoS is still unfixed in this build (known) | Low | 3.7 | Needs an IRC peer |

### Did not reproduce

These are kept for transparency and are **not** claimed as vulnerabilities. Each folder records the variants that were tried and what stopped them.

| Finding | Claimed severity | Outcome |
|---|---|---|
| [VULN-027](rocket.chat/exploits/VULN-027-isolated_vm_sandbox_escape/): isolated-vm sandbox escape in integration scripts | Critical | isolated-vm 6.2.0 refused every navigation step; no host-realm execution reached |
| [VULN-021](rocket.chat/exploits/VULN-021-uploads_inline_same_origin/): Uploads render inline on the workspace origin | Medium | Payload never executed (no collector hit) |
| [VULN-022](rocket.chat/exploits/VULN-022-avatar_unintended_proxy/): Unintended proxy in `/avatar` | Medium | Traversal returned the SVG; marker absent |
| [VULN-080](rocket.chat/exploits/VULN-080-livechat_widget_paste_xss/): Livechat widget paste XSS | Medium | Paste did not execute in a real browser |
| [VULN-016](rocket.chat/exploits/VULN-016-mailer_unsubscribe_timestamp_token/): `mailer.unsubscribe` keyed on account creation time | Info | Identical responses; a 1-in-86.4M secret behind a limiter |
| [VULN-017](rocket.chat/exploits/VULN-017-client_address_from_x_real_ip/): Client address taken from `X-Real-IP` | Info | **Intended**: behind the documented proxy the header does not move the limiter |
| [VULN-023](rocket.chat/exploits/VULN-023-livechat_missing_csp/): `/livechat` served without CSP | Info | Real, but X-Frame-Options still blocks framing and nothing is reflected |
| [VULN-025](rocket.chat/exploits/VULN-025-integration_script_no_timeout/): Integration scripts have no timeout | Info | Real 7.5 s stall, but the code is admin-authored |
| [VULN-029](rocket.chat/exploits/VULN-029-saml_insecure_decryption_algorithms/): SAML decryption re-enables insecure algorithms | Info | SAML module absent; no oracle |
| [VULN-065](rocket.chat/exploits/VULN-065-head_request_rate_limit_bypass/): HEAD requests skip the GET rate limit | Info | Limiter does ignore HEAD; filtered as rate-limit only |
| [VULN-072](rocket.chat/exploits/VULN-072-data_export_switch_bypass/): Data export switch only hides the link | Info | Archive built and mailed, but the download is refused |
| [VULN-083](rocket.chat/exploits/VULN-083-email_otp_attempt_race/): Email OTP attempt-cap race | Info | Needs the victim's password first; widens a 5-guess cap |

## Folder guide

| Path | Contents |
|---|---|
| [`rocket.chat/rocket.chat_report.md`](rocket.chat/rocket.chat_report.md) | Full audit report: executive summary, every finding with code excerpts, CVSS breakdown and fix |
| [`rocket.chat/report.json`](rocket.chat/report.json) | Machine-readable report, including triage chain candidates and quick wins |
| [`rocket.chat/rocket.chat_summary.md`](rocket.chat/rocket.chat_summary.md) | Target manifest: lab topology, credentials, security baseline, how to rebuild |
| [`rocket.chat/rocket.chat_appmap.md`](rocket.chat/rocket.chat_appmap.md) | Application map: request path and where each feature lives in the source |
| [`rocket.chat/02_features.html`](rocket.chat/02_features.html) / [`.json`](rocket.chat/02_features.json) | Attack-surface feature graph |
| [`rocket.chat/known_issues.json`](rocket.chat/known_issues.json) | Known Issue Check verdict and novelty score per confirmed finding |
| [`rocket.chat/fingerprint.json`](rocket.chat/fingerprint.json) | Software fingerprint: signals that identify this Rocket.Chat build remotely |
| [`rocket.chat/exploits/`](rocket.chat/exploits/README.md) | One folder per finding (all 84), with the validation summary table |
| [`rocket.chat/chains/`](rocket.chat/chains/README.md) | The 8 proven attack chains |
| [`rocket.chat/detections/`](rocket.chat/detections/README.md) | Sigma rules with positive, clean-set and validation logs |
| [`rocket.chat/msf/`](rocket.chat/msf/) | Metasploit auxiliary modules with `msftidy` logs (not yet run against the lab) |

---

*Generated from the `finding.json`, `writeup.md` and `known_issues.json` of every finding in this folder. Blue Spider is a product of [Kohi Research Corporation](https://kohirc.com).*
