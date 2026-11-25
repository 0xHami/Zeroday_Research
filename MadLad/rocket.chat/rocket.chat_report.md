# Rocket.Chat: security audit

**Version** 9.1.0-develop; **Commit** `9f3d6c8c48911e32ed6c2ce36befd431faa71190`; **Source** https://github.com/rocketchat/rocket.chat

## Executive summary

Rocket.Chat 9.1.0-develop (commit `9f3d6c8c4891`, Community edition, no licence, not Cloud-registered) was audited against the lab's documented secure baseline: the vendor's release image for the audited commit behind Traefik, MongoDB as a replica set, SMTP pointed at Mailpit, every security control at its shipped value (2FA, password policy, failed-login blocking, REST rate limiter, CSP, protected files), and Omnichannel, OAuth, SAML, CAS and anonymous read off. This is the expanded report: 84 ids, 73 of them real findings (1 critical, 10 high, 58 medium, 4 low by CVSS 3.1 band), each with its own `findings/VULN-NNN.md` carrying a 5 to 15 line excerpt copied from the target by line range, a description that says what the code does and what it should do, numbered reproduction steps against this lab's base URL and credentials, the CVSS vector metric by metric, and a fix with its side effects named as either removing a feature or removing only the weakness. The 11 filtered or documented entries sit in the trailing table with their reason and have no writeup, by design. 41 real findings need a non-default business feature and are listed under Edge cases: they are real for every deployment that turned that feature on, which for Omnichannel, OAuth or SAML is most of them.

What was not found matters as much: no unauthenticated remote code execution, no SQL or command injection, no unauthenticated file read, and no cross-tenant bypass of room membership on the main message routes. The one code-execution path (VULN-027, critical) needs an integration-management permission: integration scripts escape the isolated-vm sandbox because the isolate is handed the host `ivm` module and a host function Reference. It is kept over the admin-only filter because it crosses the boundary the vendor built for exactly that role, and because the integration permissions are designed to be delegated.

The most actionable findings in the shipped configuration are VULN-057 (any user raises any numeric setting through `statistics.telemetry`, widening the TOTP window and lifting lockouts; a one-line allow-list fixes it), VULN-001 (anonymous Livechat visitor registration returns an existing customer's token by phone number), VULN-073 and VULN-078 (an anonymous ReDoS in the mailer reached through the offline form, and a rate-limit bucket keyed on a header the caller writes, so one anonymous client blocks every web login while a rotating header escapes the limits altogether), and VULN-004 with VULN-033 (a stolen session reads the TOTP seed and survives the victim's password change). Behind off-by-default features, VULN-044 (CAS session fixation) and VULN-002 (OAuth email meld into the env-created administrator) are account takeovers.

Two patterns run through the list and are worth more than any single finding. The first is authorization decided on an object the caller named rather than the object being accessed: VULN-076 is the clearest case, where a Livechat visitor's own room authorises a subscription to someone else's. The second is a fix applied to one call site and not to its siblings: VULN-075 and VULN-081 are two unguarded outbound fetches beside two that the vendor guarded, VULN-077 is the endpoint a token-projection fix missed, and VULN-079 is an input-validation fix applied per method rather than at the model. A maintainer reading this report will get more out of the four sibling cases than out of four separate patches.

Verification depth: every cited file:line was re-read at the pinned commit, every excerpt in `findings/` is copied from the target by line range (a stale range fails the build, so the excerpts cannot drift from the source), and the CVSS band is checked against the vector for every finding. No finding was run in this stage; statuses are source-traced, so 46 confirmed vulnerabilities and 18 likely ones go to stage 11 for dynamic validation, 9 need something the sealed lab cannot provide (an Enterprise licence, an external network or a third-party provider; each carries a `manual_reason`), 10 were filtered or disproved and 1 is documented behaviour. Expansion corrected one finding's own claim: VULN-080's title said the sanitiser that fixed CVE-2022-21830 was gone, and reading the file showed DOMPurify still imported and applied on the emoji-insertion path but not on the write that re-parses the visitor's text, with `shouldComponentUpdate` making a paste into an empty composer the trigger rather than typing. Known versus novel among the real findings: 61 novel, 12 known and still unpatched in this build, each cited per finding.

## Summary

Ordered by severity, then confidence (highest first), then id.

| ID | Severity | Confidence | Title | Category | Type | Status | CVSS | Auth | Known |
|----|----------|------------|-------|----------|------|--------|------|------|-------|
| VULN-002 | high | 9/10 | OAuth account linking by unverified email claim, so an IdP identity melds into any local account with that address | Authentication bypass (federated account linking on an unverified email claim) | Known issue | CONFIRMED (an identity provider asserting an administrator's email address, with no verification claim, yielded a full administrator session and reset that administrator's own password) | 7.4 | no | known-unpatched |
| VULN-057 | high | 9/10 | statistics.telemetry lets any signed-in user increment any numeric workspace setting, weakening 2FA, lockouts and rate limits | Missing function-level authorization (settings write via telemetry) | Known issue | CONFIRMED (an ordinary account raised Accounts_TwoFactorAuthentication_MaxDelta from 1 to 121 through statistics.telemetry, and the widened window then accepted a 20-minute-old TOTP code that the shipped value refuses) | 8.1 | yes | known-unpatched |
| VULN-001 | high | 8/10 | IDOR in anonymous Livechat visitor registration: a customer's phone number returns their visitor token, their email rebinds it | Broken access control (credential disclosure by user-controlled key) | Unique finding | CONFIRMED (an unauthenticated caller turned a customer's phone number into their Livechat token and read their conversation, and an email address stole the record from the customer outright) | 8.2 | no | novel |
| VULN-015 | high | 8/10 | MFA bypass through the recovery flow: resetPassword and verifyEmail are exempted from the second factor and return a session | Authentication (MFA bypass through the recovery flow) | Known issue | CONFIRMED (the mailbox alone produced a working session on a TOTP-protected account; password login for the same account still demanded the code) | 7.4 | no | known-unpatched |
| VULN-030 | high | 8/10 | Deactivated and pending-approval accounts get working tokens through the OAuth login-code path, which bypasses validateLoginAttempt, and REST never re-checks active | Authentication bypass through an alternate path (account state not enforced) | Unique finding | CONFIRMED (an account the administrator had deactivated signed in through the OAuth login-code path and its token read and wrote as that account, while the password path refused it) | 7.1 | yes | novel |
| VULN-073 | high | 8/10 | Mailer placeholder regex is still quadratic after the CVE-2021-32832 fix, and the anonymous offline form feeds it unbounded text | Denial of service (regular expression complexity, ReDoS) | Unique finding | CONFIRMED (an unauthenticated request held the server for 20.02s at 80000 characters, the cost growing 44.5x for 16x the input) | 7.5 | no | novel |
| VULN-044 | high | 7/10 | CAS session fixation: the credential token is chosen in the service URL, so a crafted link to the real CAS server hands the victim's account to the attacker | Authentication bypass (session fixation in the SSO handoff) | Unique finding | NEEDS_MANUAL (the CAS handshake needs a trusted CAS server over HTTPS, which this sealed lab cannot provide) | 8.1 | no | novel |
| VULN-048 | high | 7/10 | Omnichannel external frame puts the agent's plaintext session token in the frame URL, and the encryption key the setting promises is a public setting | Sensitive data exposure (session token in a URL; documented encryption not applied) | Unique finding | NEEDS_MANUAL (the agent-side browser drive did not fit this stage's time budget; the settings themselves are checked here) | 7.4 | no | novel |
| VULN-074 | high | 7/10 | Unbounded metric label cardinality: method.call samples are labelled with the raw request path, so anonymous requests grow the registry until memory runs out | Uncontrolled resource consumption (unbounded metric label cardinality) | Unique finding | CONFIRMED (300 anonymous requests with distinct paths added 7774 time series and grew the metrics body by 1024449 bytes, with nothing evicting them) | 7.5 | no | novel |
| VULN-031 | high | 5/10 | SAML assertions are not bound to this service provider: no Audience, Recipient, Destination or InResponseTo check, so another SP's assertion logs in | Authentication bypass (assertion not bound to its intended recipient) | Unique finding | NEEDS_MANUAL (SAML is a licensed enterprise module and is not present on this unlicensed workspace) | 7.4 | no | novel |
| VULN-010 | medium | 9/10 | Missing authorization on chat.getDeletedMessages: any user lists the deleted-message ids and timing of any room | Missing authorization (room metadata disclosure) | Known issue | CONFIRMED (any authenticated account reads the deleted-message ids, count and timing of a private group it is refused every other way) | 4.3 | yes | known-unpatched |
| VULN-003 | medium | 8/10 | Cross-user event injection on notify-room-users: any member forges userData and video-conference events into every other member's private stream | Broken access control on a realtime channel (cross-user event injection) | Known issue | CONFIRMED (one ordinary member injected a forced logout, a user-document rewrite (name and roles) and a forged incoming call into another member's private realtime channel) | 6.4 | yes | known-unpatched |
| VULN-007 | medium | 8/10 | users.listByStatus leaks every account's email, roles and last login to any ordinary user, and sorts on client-chosen fields before projecting | Authenticated data exposure (PII across teams) | Unique finding | CONFIRMED (an ordinary account read every account's email address, role list and last-login time, administrators included, and ordered the listing by a field the response never returns) | 4.3 | yes | novel |
| VULN-009 | medium | 8/10 | Room ban not enforced on the notification and file-download paths, because both match the banned subscription | Broken access control (ban not enforced on the notification and file paths) | Unique finding | CONFIRMED (a banned member kept receiving the room's new messages through notifications and downloaded its file, while the room's history refused it) | 4.3 | yes | novel |
| VULN-012 | medium | 8/10 | Mass assignment in rooms.mediaConfirm: a member sets any message type t, forging system notices that chat.sendMessage refuses | Mass assignment (forged system notices) | Unique finding | CONFIRMED (an ordinary member stored two messages with attacker-chosen system types and text, which the ordinary send path refuses outright) | 4.3 | yes | novel |
| VULN-026 | medium | 8/10 | Workspace-wide denial of service from one message: the markdown parser is super-quadratic and the attachment-description parse has no length cap | Denial of service (inefficient algorithmic complexity) | Unique finding | CONFIRMED (one ordinary member's message held the server for 3.05s at 4000 characters and 6.97s as an attachment description past the message-size limit, while a bystander's request waited up to 2.78s) | 6.5 | yes | novel |
| VULN-045 | medium | 8/10 | Profanity filter is a per-token, per-word regex scan on the request path, so one member stalls the whole server for seconds per message | Denial of service (inefficient algorithmic complexity on the request path) | Unique finding | CONFIRMED (one member's 500-token message took 3.32s of server time with the filter on against 0.31s with it off, and a bystander waited up to 2.78s) | 6.5 | yes | novel |
| VULN-046 | medium | 8/10 | Anonymous write into any room through livechat/page.visited, which resolves neither the visitor token nor the room | Missing authorization (anonymous write into arbitrary rooms; content spoofing) | Unique finding | CONFIRMED (an unauthenticated caller wrote an attacker-chosen notice into #general through livechat/page.visited, attributed to the workspace bot, and the write still lands (hidden) with the notice setting off) | 5.3 | no | novel |
| VULN-047 | medium | 8/10 | channels.anonymousread serves Omnichannel conversations and hidden messages to unauthenticated callers, and getRoomRoles skips its access check for them | Broken access control (anonymous read of Omnichannel rooms and hidden messages) | Unique finding | CONFIRMED (an unauthenticated caller read a customer support conversation and a deleted message through channels.anonymousread; the role-listing leg is not reachable, every entry point to it requires authentication) | 5.9 | no | novel |
| VULN-051 | medium | 8/10 | Livechat transcript relays visitor-written HTML from the workspace's own mail address to any recipient the caller names | HTML injection into outbound email (trusted-sender relay) | Known issue | CONFIRMED (an anonymous visitor made the workspace mail attacker-authored HTML, with a working phishing link, from its own address to a third party; the same markup as message text is escaped, so the upload description is the sink) | 4.7 | no | known-unpatched |
| VULN-054 | medium | 8/10 | Omnichannel offline form mails visitor fields unescaped to the support mailbox, and the host field lands inside an href | HTML injection into staff email (content spoofing) | Unique finding | CONFIRMED (an anonymous form submission delivered attacker-authored HTML and an attacker-chosen link into the support mailbox from the workspace's own address) | 4.7 | no | novel |
| VULN-055 | medium | 8/10 | Missing permission check on retentionOverrideGlobal lets any room owner exempt their room from the retention policy | Missing authorization on a compliance setting | Known issue | CONFIRMED (an ordinary room owner exempted its own room from the workspace retention policy, while the sibling retention field on the same route refused it) | 4.3 | yes | known-unpatched |
| VULN-058 | medium | 8/10 | Mass assignment in teams.create: the caller's room.extraData is spread into the new room, setting default, featured and other administrative flags | Mass assignment | Unique finding | CONFIRMED (an ordinary account created a room flagged default and featured for the whole workspace, which a new account then joined automatically) | 4.3 | yes | novel |
| VULN-059 | medium | 8/10 | chat.syncThreadsList returns the hidden full copy of a deleted thread root, so members read deleted content on a default install | Deleted data exposure (missing response filtering) | Unique finding | CONFIRMED (a member read the full text of a deleted message through the thread catch-up route, which its non-sync sibling withholds) | 4.3 | yes | novel |
| VULN-076 | medium | 8/10 | Livechat stream access is decided against the room the client names in extraData, so a visitor with one open chat of its own reads any other Livechat room's live messages | Broken access control (authorization decided on a client-chosen object) | Unique finding | CONFIRMED (an unauthenticated visitor subscribed to another customer's Livechat room by naming its own room in extraData and received that customer's messages) | 5.9 | no | novel |
| VULN-077 | medium | 8/10 | livechat/visitors.pagesVisited returns navigation messages whole, handing any agent the visitor tokens the GHSA-cqj7 fix stopped visitors.info from disclosing | Credential disclosure (missing projection and room authorization) | Unique finding | CONFIRMED (a non-admin agent read the customer's visitor token out of visitors.pagesVisited, which visitors.info withholds for the same caller, and used it to read the conversation and post as the customer) | 5.4 | yes | novel |
| VULN-004 | medium | 7/10 | users.info returns the caller's raw services document, disclosing the TOTP seed and backup-code hashes to any holder of the session | Sensitive data exposure (second-factor secret disclosed to the session) | Unique finding | CONFIRMED (a session read its own account's TOTP seed and backup-code hashes from users.info, and a code derived from that seed passed the second factor) | 6.8 | yes | novel |
| VULN-011 | medium | 7/10 | Typing indicators accept a room the caller cannot access, because the user-activity write rule only checks the claimed name | Missing authorization on a realtime write | Unique finding | CONFIRMED (an account refused both the history and the stream of a private group wrote activity events into it that the room's members received) | 4.3 | yes | novel |
| VULN-019 | medium | 7/10 | Improper authentication on /hooks: any integration id and token authenticate, and the add and remove sub-routes skip the enabled and impersonation checks | Authentication (credential accepted outside its purpose) | Unique finding | CONFIRMED (a webhook credential the administrator had revoked was refused by the posting route but still authenticated on /hooks/add, where it created an enabled outgoing integration that forwarded the channel to our listener) | 6.5 | yes | novel |
| VULN-020 | medium | 7/10 | Authorization oracle in roles.addUserToRole: the already-in-role answer precedes the permission check, revealing any user's roles in any room | Information disclosure (authorization oracle) | Unique finding | CONFIRMED (an unprivileged account read out global and room-scoped role membership, including the owner of a private group it cannot see, from the error code alone) | 4.3 | yes | novel |
| VULN-033 | medium | 7/10 | Password change, reset and remove-other-tokens leave open realtime sessions alive, and an admin-set password is broadcast in clear to them | Session management (revocation not applied to the realtime channel; credential in a broadcast) | Unique finding | CONFIRMED (a stolen token's realtime session survived both a password change and removeOtherTokens, kept reading the victim's private messages, and received the administrator's new password in clear, which then logged in) | 6.5 | no | novel |
| VULN-036 | medium | 7/10 | Mandatory 2FA for a role is enforced only by the web client, so its members keep single-factor access over REST and DDP | Security policy enforced client-side only (mandatory MFA) | Unique finding | CONFIRMED (a member of a role with mandatory two-factor authentication logged in with the password alone over REST and used the role's full access; the policy is read only by the web client) | 6.8 | yes | novel |
| VULN-037 | medium | 7/10 | Pre-registration squatting survives the owner's OAuth claim: the email meld resets the password but keeps the squatter's sessions and personal access tokens | Pre-account takeover (account claim does not purge prior access) | Unique finding | CONFIRMED (after the account's real owner claimed it through their identity provider, the earlier squatter's personal access token still read the account, its subscriptions and its direct messages) | 6.8 | no | novel |
| VULN-041 | medium | 7/10 | Star privacy is enforced only in the REST serializer, so the message query and the realtime broadcast disclose who starred what | Privacy setting bypassed through alternate channels | Unique finding | CONFIRMED (one member read another member's private stars: the query filter returned exactly the starred message, and the realtime broadcast carried the raw starred array) | 4.3 | yes | novel |
| VULN-049 | medium | 7/10 | With message edit history on, deleted and edited-away content stays readable: personal exports include the hidden copies and their files, and chat.getMessage returns them by id | Sensitive data exposure (soft-deleted content served to members) | Unique finding | CONFIRMED (a member read an edited-away secret and a deleted message's text through chat.getMessage, which the room's own history withholds) | 4.3 | yes | novel |
| VULN-060 | medium | 7/10 | Meteor's resetPassword and changePassword set any password: the policy is enforced in the browser and on one REST path only | Client-side enforcement (alternate channel missing checks) | Known issue | CONFIRMED (a one-character password was accepted through the method bridge and then logged in, on a workspace whose policy demands fourteen characters, and the change switch is not read there either) | 4.3 | yes | known-unpatched |
| VULN-062 | medium | 7/10 | Revoking preview-c-room only closes the history and the live stream: ten other message, file and thread routes still serve non-members | Authorization missing on alternate API routes | Unique finding | CONFIRMED (with preview-c-room revoked, 4 other route(s) (channels.messages, chat.syncMessages, chat.getMessage, chat.search) still served the channel's messages to a non-member while channels.history and the stream refused it) | 4.3 | yes | novel |
| VULN-066 | medium | 7/10 | Disabling password reset closes only the REST route: Meteor's forgotPassword still mails reset links anonymously and outside the REST limiter | Feature switch not enforced on an alternate channel | Unique finding | CONFIRMED (with self-service password reset switched off, an unauthenticated caller still had the workspace mail a working reset link, through the method bridge and outside the REST limiter) | 4.8 | no | novel |
| VULN-068 | medium | 7/10 | rooms.bannedUsers returns a room's ban list to any member, while the client shows it only to holders of ban-user | Missing authorization on a moderation view | Unique finding | CONFIRMED (an ordinary member and a non-member both read the room's banned-user list, which the interface shows only to holders of ban-user) | 4.3 | yes | novel |
| VULN-079 | medium | 7/10 | getRoomByTypeAndName passes an untyped method parameter into a Mongo filter, so any user enumerates private-room names by regular expression through its two distinct error codes | NoSQL operator injection (existence oracle) | Unique finding | CONFIRMED (ordinary accounts recovered the exact name of a private group they cannot see ('proj-015b') in 327 oracle questions, through a Mongo operator in a method parameter) | 4.3 | yes | novel |
| VULN-006 | medium | 6/10 | stream-apps and stream-importers accept anonymous subscriptions, and the app setting-changed event carries the new value (secrets included) | Unauthenticated information disclosure (realtime) | Unique finding | CONFIRMED (an unauthenticated websocket held subscriptions to the app and importer administration streams, which a logged-in-only stream refuses) | 5.9 | no | novel |
| VULN-014 | medium | 6/10 | External control of a file path in downloadPublicImportFile: any local path is read into the importer, and the error is an existence oracle | External control of a file path (privileged importer) | Known issue | CONFIRMED (a run-import holder read an arbitrary server-side file into the import store and distinguished existing from missing paths from the error alone, and the permission is delegable to an ordinary account) | 4.9 | yes | known-unpatched |
| VULN-024 | medium | 6/10 | Protected file downloads and personal data exports are marked publicly cacheable for a year, so a shared cache serves them to other people | Sensitive data in a shared cache | Unique finding | CONFIRMED (a private room's upload, which the workspace refuses to an unauthenticated caller, was served from a standard shared cache to a caller with no credentials, because the response says public, max-age=31536000) | 5.9 | no | novel |
| VULN-032 | medium | 6/10 | Account lockout bypass: the per-user failed-login block reads the username as typed, so logins by email or inside a totp envelope are never locked | Authentication (account lockout bypass) | Known issue | CONFIRMED (the per-user lock engaged for the username but 15 guesses by email were never blocked and the email form logged in while the username form was locked) | 4.8 | no | known-unpatched |
| VULN-034 | medium | 6/10 | URL-parameter session handoff: ?loginClient=mobile exports the resume token to the rocketchat:// scheme and ?resumeToken= logs the browser into another account | Session handoff driven by URL parameters (token export to a custom scheme; login CSRF) | Unique finding | NEEDS_MANUAL (the browser legs need the Playwright drive this stage did not have time to write) | 6.8 | no | novel |
| VULN-035 | medium | 6/10 | Room invite links are not revocable by the room's owners, outlive their creator's rights, and their use limit is not consumed atomically | Broken access control (share link not re-validated or revocable) | Unique finding | CONFIRMED (the room owner could neither list nor revoke a moderator's permanent link, and the kicked, demoted creator re-entered the private group with it) | 5.4 | yes | novel |
| VULN-040 | medium | 6/10 | Second-factor codes are not single-use: a TOTP code is replayable inside the window and a backup code can be redeemed twice by concurrent requests | MFA one-time code replay and consumption race | Unique finding | CONFIRMED (the TOTP code was replayed for 4 further sessions; the backup-code race gave 1 token(s)) | 4.2 | yes | novel |
| VULN-043 | medium | 6/10 | OAuth login skips the second factor for any account inside the registration grace window, even one that has enrolled TOTP | MFA skipped on an alternate login path (registration grace window) | Unique finding | CONFIRMED (an account with TOTP enrolled was signed in through OAuth with no second factor, inside the registration grace window, while its password login still demanded the code) | 4.2 | yes | novel |
| VULN-061 | medium | 6/10 | Integration updates and deletes trust the type the caller names, so one integration permission family reaches the other's objects, script included | Broken function-level authorization (type confusion between permission families) | Unique finding | CONFIRMED (an account with only the incoming-integration permissions changed and removed an outgoing integration by naming the other type in the body) | 6.0 | yes | novel |
| VULN-067 | medium | 6/10 | channels.list sorts on client-chosen fields before projecting, so a join code is recoverable by bisection | Sort oracle on a hidden field | Unique finding | CONFIRMED (recovered a 5-character join code exactly in 58 requests from the sort order alone, and joined the channel it protected) | 4.3 | yes | novel |
| VULN-069 | medium | 6/10 | Removing the admin role skips assign-admin-role: users.update replaces the role list with no last-admin guard | Role hierarchy not enforced | Unique finding | CONFIRMED (a delegate refused the promotion guard still removed the admin role from an administrator through users.update, which the sibling route refuses) | 6.5 | yes | novel |
| VULN-070 | medium | 6/10 | autotranslate.translateMessage omits the auto-translate permission its sibling routes and the client require | Missing permission check on one of three twin routes | Unique finding | CONFIRMED (an account without the auto-translate permission reached translateMessage, which its sibling route refuses it, and the handler ran to the provider) | 4.3 | yes | novel |
| VULN-075 | medium | 6/10 | Pending-file importer fetches export-supplied URLs with Node's raw HTTP client, bypassing the SSRF guard its sibling fetch now uses | Server-side request forgery (non-blind, privileged importer) | Unique finding | NEEDS_MANUAL (the pending-file record has to be seeded beside the run and that did not fit this stage's time budget) | 6.8 | yes | novel |
| VULN-078 | medium | 6/10 | The DDP-over-REST bridges key their rate limits on the caller's own X-Auth-Token header, so every header-less anonymous caller shares one bucket and a rotating header escapes it | Denial of service through a shared rate-limit key (and limit bypass) | Unique finding | CONFIRMED (one anonymous client exhausted the bucket every other anonymous client shares, and rotating the X-Auth-Token header escaped the limit entirely) | 5.3 | no | novel |
| VULN-081 | medium | 6/10 | The Livechat webhook sender and its test route keep ignoreSsrfValidation on, for the same non-admin Omnichannel roles PR #42201 stopped from reaching internal hosts through triggers | Server-side request forgery (privileged Omnichannel role) | Unique finding | CONFIRMED (a non-admin livechat-manager made the server fetch URLs of its choosing, including a host only the server can reach, and received the customer's conversation data at its own listener) | 4.1 | yes | novel |
| VULN-013 | medium | 5/10 | Email Direct Reply takes the posting identity from the From header, so one spoofed email posts as any user under any message id | Authentication bypass by spoofing (message impersonation) | Unique finding | NEEDS_MANUAL (the mail sink is in the lab but the poller interval could not be waited out inside this stage's time budget) | 5.9 | no | novel |
| VULN-038 | medium | 5/10 | video-conference.share-chat creates a discussion without the membership and send checks regular discussion creation enforces | Broken access control (secondary feature writing into a room; ban and mute bypass) | Unique finding | NEEDS_MANUAL (the route needs a call created by a marketplace video-conference app, which a sealed lab cannot install) | 4.2 | yes | novel |
| VULN-042 | medium | 5/10 | Attacker-chosen text in the workspace's own registration and reset emails, sent to any address | Trusted platform email carrying attacker-controlled text | Unique finding | CONFIRMED (the workspace sent its own genuine mail, from its own address, to a third party's mailbox carrying a sentence the attacker chose) | 4.3 | no | novel |
| VULN-052 | medium | 5/10 | Smarsh compliance export interpolates message text and sender names into the archived HTML unescaped, so a member forges or hides archive entries | Integrity of compliance records (HTML injection into archived email) | Unique finding | NEEDS_MANUAL (the Smarsh compliance export is a licensed enterprise module and is not present on this workspace) | 5.4 | yes | novel |
| VULN-056 | medium | 5/10 | postMessage command channels accept any origin: iframe login never checks it, and the iframe integration ships with origin * | Origin validation error (cross-window command injection) | Unique finding | NEEDS_MANUAL (the two-document browser drive did not fit this stage's time budget; the shipped origin settings are checked here) | 4.3 | no | novel |
| VULN-064 | medium | 5/10 | Apps marketplace REST routes have no manage-apps check, so any user obtains a workspace Cloud token with purchase scope | Missing authorization (server credential exposed) | Unique finding | NEEDS_MANUAL (the marketplace routes need a Cloud-registered workspace, which a sealed unlicensed lab does not have) | 5.4 | yes | novel |
| VULN-028 | medium | 4/10 | Indirect prompt injection in AI Search: other users' messages become instructions, and the answer renders as markdown that fetches attacker URLs | LLM prompt injection (indirect, through retrieved content) with a rendering sink | Unique finding | NEEDS_MANUAL (AI Search needs a licensed AI module and a model provider, neither of which exists in this workspace) | 4.4 | yes | novel |
| VULN-039 | medium | 4/10 | Apple identity tokens are replayable across workspaces, because the audience list always includes the shared official iOS app and no nonce is checked | Authentication (identity token accepted across relying parties) | Unique finding | NEEDS_MANUAL (the finding needs Apple-signed identity tokens, which a sealed lab cannot obtain or forge) | 6.8 | no | novel |
| VULN-050 | medium | 4/10 | Slack bridge binds channels and users by name, so a Slack member posts into a same-named private group as a same-named local user | Broken access control (room and identity binding by a user-controlled name) | Unique finding | NEEDS_MANUAL (the Slack bridge needs a real Slack workspace and outbound access, neither available in a sealed lab) | 4.8 | no | novel |
| VULN-053 | medium | 4/10 | IRC bridge mirrors every room, private groups included, to the IRC network and joins any IRC user into the local room of the same name | Exposure of private rooms to an external network | Unique finding | NEEDS_MANUAL (the IRC bridge needs an IRC server to peer with, which this sealed lab does not provide) | 6.5 | no | novel |
| VULN-008 | low | 7/10 | Room-message stream authorization is never re-evaluated, so a previewer keeps receiving a channel's messages after it is made private | Broken access control (authorization not re-evaluated after revocation) | Unique finding | CONFIRMED (an open stream subscription kept delivering a room's messages after the room was made private and every new read by the same user was refused) | 3.1 | yes | novel |
| VULN-018 | low | 7/10 | /oauth/userinfo accepts expired access tokens for 30 days, because only the REST bearer path checks expires | Session management (credential used after expiry) | Unique finding | CONFIRMED (an access token past its expiry still returned the account's identity from /oauth/userinfo, while the REST bearer path refused the same token) | 3.7 | no | novel |
| VULN-071 | low | 7/10 | e2e.fetchUsersWaitingForGroupKey takes room ids from the caller without authorizing them, disclosing private rooms' members | Object reference not authorized (membership disclosure) | Known issue | CONFIRMED (a non-member listed an encrypted private group's waiting members and their keys through a route that authorises no room id) | 3.1 | yes | known-unpatched |
| VULN-082 | low | 5/10 | CVE-2025-5892's IRC parser ReDoS is unfixed in this build: the quadratic whitespace expression is unchanged and the proposed fix was never merged | Denial of service (regular expression complexity, ReDoS) | Known issue | NEEDS_MANUAL (the IRC parser is only reachable from an IRC peer, which this sealed lab does not provide) | 3.7 | no | known-unpatched |
| VULN-063 | informational | 4/10 | On a fresh install the REST API has no per-route rate limiting until the server restarts, and changes to the default limit never apply | Missing rate limiting | Unique finding | CONFIRMED (4 ordinary GET routes accepted 25 calls each with the documented limit at 10 per 60000 ms, and lowering the default to 2 changed nothing: the default rule is never registered) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N | no | novel |
| VULN-005 | informational | 3/10 | Anonymous callers can read the permission-to-role map through the permissions/get method | Unauthenticated information disclosure | Unique finding | CONFIRMED (an unauthenticated DDP caller read the whole permission table (993 entries) with the roles that hold each permission) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N | no | novel |
| VULN-084 | informational | 3/10 | users.register answers Email already exists before it checks whether registration is open, a sibling of the enumeration CVE-2021-22892 closed | Account enumeration (existence oracle) | Unique finding | CONFIRMED (on a workspace with self-registration closed, an anonymous caller distinguishes an address that has an account from one that does not) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N | no | novel |

84 finding(s): 1 critical, 10 high, 58 medium, 4 low, 11 informational; 57 confirmed; 15 needing a person

## VULN-002: OAuth account linking by unverified email claim, so an IdP identity melds into any local account with that address

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (an identity provider asserting an administrator's email address, with no verification claim, yielded a full administrator session and reset that administrator's own password) |
| **Confidence** | 9/10 |
| **Confidence reasoning** | Proven end to end in the lab: an unverified email claim from a configured provider gave a full administrator session and reset the owner's password. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N |
| **CWE** | CWE-287, CWE-345 |
| **Category** | Authentication bypass (federated account linking on an unverified email claim) |
| **Location** | `targets/rocket.chat/apps/meteor/server/configuration/accounts_meld.js:30` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | known-unpatched |
| **Known evidence** | PR #43840 (merged 2026-11-20, present in this build via .changeset/brown-buses-own.md and customOAuth.ts:255): its public review states that custom-provider logins link to existing accounts by email without confirming the provider verified the email, merged without that mitigation; issue #18391 (2020) recorded that email_verified is ignored. No advisory and no fix; affects 9.1.0-develop at 9f3d6c8c. https://github.com/RocketChat/Rocket.Chat/pull/43840 |
| **Known confidence** | 7/10 |
| **Conditional** | yes: an OAuth login provider enabled (GitHub, Google, GitLab, Apple, or Custom OAuth with the oauth-enterprise module) |
| **Finding key** | `cc4bc784ff08fdaf` |

### Impact

High (CVSS 7.4): account takeover without the victim's password, bounded by whether the IdP can be made to assert the address. An attacker who makes a configured provider assert a victim's email is linked to the victim's local account and, when no second factor applies to it (the env-created administrator is exactly such an account, inserted with no services), the OAuth callback issues a login code for the victim. Even when 2FA stops the login the IdP link persists and the victim's address is marked verified, and a password account whose address was unverified has its password forcibly reset.

### Remediation

In accounts_meld.js:14-31 link only when the provider asserts the address as verified (OIDC email_verified, GitHub's verified primary email, GitLab confirmed_at, Apple email_verified) and otherwise refuse with a sign-in-and-link instruction; carry the verification flag through configureOAuthServices.ts:39-50 instead of dropping it; evaluate each provider's merge switch before any write and default it off, and give the built-in GitLab provider a keyField so the customOAuth.ts:263-300 hook that honours Accounts_OAuth_Gitlab_merge_users actually runs. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authentication_Cheat_Sheet.md (federated identity: never trust an unverified claim to bind an account).

### Side effects of the fix

Keeps social login and removes only the weakness: users whose IdP does not assert a verified address, and users who never linked, sign in once with their password and link from their profile; silent first-login merging stops for those providers, and a workspace that relied on it must link accounts explicitly.

### Detail

see findings


[analysis](findings/VULN-002.md)


### Dynamic validation

- **Status**: CONFIRMED (an identity provider asserting an administrator's email address, with no verification claim, yielded a full administrator session and reset that administrator's own password)
- **Confidence**: 9/10
- Exploit directory: `exploits/VULN-002-oauth_unverified_email_meld/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-002-oauth_unverified_email_meld/writeup.md](exploits/VULN-002-oauth_unverified_email_meld/writeup.md)

## VULN-057: statistics.telemetry lets any signed-in user increment any numeric workspace setting, weakening 2FA, lockouts and rate limits

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (an ordinary account raised Accounts_TwoFactorAuthentication_MaxDelta from 1 to 121 through statistics.telemetry, and the widened window then accepted a 20-minute-old TOTP code that the shipped value refuses) |
| **Confidence** | 9/10 |
| **Confidence reasoning** | Proven by our own run: an ordinary account raised a security setting and the widened window then accepted a stale TOTP code; one allow-list fixes it. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H |
| **CWE** | CWE-862, CWE-915 |
| **Category** | Missing function-level authorization (settings write via telemetry) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/statistics/functions/updateStatsCounter.ts:10` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | known-unpatched |
| **Known evidence** | Issue #42484 'statistics.telemetry lets any logged-in user $inc arbitrary settings' (2026-10-01; closed 2026-10-02 by the vendor, 'we will track it'), same handler and root cause; updateStatsCounter.ts:8-15 unchanged at 9f3d6c8c. No CVE or GHSA. https://github.com/RocketChat/Rocket.Chat/issues/42484 |
| **Known confidence** | 9/10 |
| **Conditional** | no |
| **Finding key** | `d5df504f77468c17` |

### Impact

High (CVSS 8.1): the telemetry endpoint needs only authentication and dispatches each submitted event by name; the registered updateCounter handler calls Settings.incrementValueById(data.settingsId, 1) on whatever id the caller supplies, filtered only by the setting not being blocked. Stage 06 counted 109 writable numeric settings in the shipped configuration, so the lowest role can raise Accounts_TwoFactorAuthentication_MaxDelta until most random TOTP codes verify, lift the failed-login thresholds and the email-code attempt cap, raise Message_MaxAllowedSize to widen the parser denial-of-service findings, or, in the other direction, raise the password minimum length and the unblock times until nobody can register, reset a password or log in after a single mistake. The change is applied through the settings store and broadcast as a normal setting change, with no entry in the settings audit trail, and the body schema sets no maxItems, so one request can carry thousands of increments.

### Remediation

Restrict the handler to the counters it exists for: in updateStatsCounter.ts accept only the fixed set of hidden statistics counter ids the client actually sends (or move those counters into their own collection, out of the settings store), and add maxItems to params in the telemetry schema (statistics.ts:57-73) so a single request cannot carry an unbounded number of increments. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Deny by Default; Enforce Least Privileges) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Mass_Assignment_Cheat_Sheet.md (allow-list the fields a request may address).

### Side effects of the fix

Keeps telemetry and removes only the weakness: the handful of counters the first-party client reports keep working, and any other settings id is refused, which no shipped client sends; a deployment with a custom client that incremented other settings through this path must use the settings API with a permission instead.

### Detail

see findings


[analysis](findings/VULN-057.md)


### Dynamic validation

- **Status**: CONFIRMED (an ordinary account raised Accounts_TwoFactorAuthentication_MaxDelta from 1 to 121 through statistics.telemetry, and the widened window then accepted a 20-minute-old TOTP code that the shipped value refuses)
- **Confidence**: 9/10
- Exploit directory: `exploits/VULN-057-settings_write_via_telemetry/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-057-settings_write_via_telemetry/writeup.md](exploits/VULN-057-settings_write_via_telemetry/writeup.md)

## VULN-001: IDOR in anonymous Livechat visitor registration: a customer's phone number returns their visitor token, their email rebinds it

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an unauthenticated caller turned a customer's phone number into their Livechat token and read their conversation, and an email address stole the record from the customer outright) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven unauthenticated on the shipped build for the disclosure and rebind legs, and with Omnichannel on for the read; the key is a customer's phone number. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N |
| **CWE** | CWE-639, CWE-200 |
| **Category** | Broken access control (credential disclosure by user-controlled key) |
| **Location** | `targets/rocket.chat/packages/omni-core/src/visitor/create.ts:112` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-01: searched the vendor tracker and OSV (npm @rocket.chat/meteor and rocket.chat at 9.1.0-develop: 0 advisories). Adjacent only: issue #42478 (rebind by visitor id, closed without fix, does not cover the phone or email branch), GHSA-cqj7-h8cj-jmf2 / CVE-2026-49278 (token returned by visitors.info, fixed 8.5.0), CVE-2026-65644 (visitor name HTML, fixed 8.8.0). |
| **Conditional** | yes: Omnichannel in use, so that real visitors with phone numbers or emails exist (the endpoint itself answers with Livechat_enabled off) |
| **Finding key** | `6b3b2c3e6a666452` |

### Impact

High (CVSS 8.2): unauthenticated, no victim interaction, full read of one customer's support history per request. Anyone who knows a customer's phone number receives that customer's visitor token, the only Livechat credential, and with it reads their conversations and transcripts and posts as them; a known email address instead re-keys the customer's visitor record to the attacker's token, so the attacker owns it and the customer's own token stops resolving.

### Remediation

In registerGuest (packages/omni-core/src/visitor/create.ts:105-115) create a new visitor when the caller's token is unknown instead of merging into a visitor found by phone or email; move returning-customer linking to the agent-side contact merge; never return token to a caller that did not present it (project it out of the livechat/visitor response); refuse the route while Livechat_enabled is false. This is the object-level check deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md (Mitigation) prescribes: resolve the visitor from the credential the caller presented, never from a key the caller supplies.

### Side effects of the fix

Keeps the feature and removes only the weakness: returning customers who lost their browser token are no longer re-attached to their old visitor record automatically (an agent merges the contact instead), and the route refuses registration while Omnichannel is off.

### Detail

see findings


[analysis](findings/VULN-001.md)


### Dynamic validation

- **Status**: CONFIRMED (an unauthenticated caller turned a customer's phone number into their Livechat token and read their conversation, and an email address stole the record from the customer outright)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-001-livechat_visitor_token_idor/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-001-livechat_visitor_token_idor/writeup.md](exploits/VULN-001-livechat_visitor_token_idor/writeup.md)
- **Detection**: [`detections/VULN-001.sigma.yml`](detections/VULN-001.sigma.yml) (high, validated: fired on 6/6 of this exploit's own log lines, silent on 400 clean ones). It sees any anonymous POST to the Livechat visitor route, which a default install (Omnichannel off) never makes; not the phone number or email in the body.

## VULN-015: MFA bypass through the recovery flow: resetPassword and verifyEmail are exempted from the second factor and return a session

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (the mailbox alone produced a working session on a TOTP-protected account; password login for the same account still demanded the code) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven: the mailbox alone gave a working session on a TOTP-protected account, while the password path still demanded the code. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N |
| **CWE** | CWE-308, CWE-640 |
| **Category** | Authentication (MFA bypass through the recovery flow) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/2fa/loginHandler.ts:23` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | known-unpatched |
| **Known evidence** | HackerOne #1701378 'Bypassing 2FA with conventional session management' (disclosed, about 2022) reports the verifyEmail leg; issue #10183 (2018, closed 2023-04-18 without a fix) names the reset bypass. This build still exempts both at 2fa/loginHandler.ts:23-24. No advisory, no fix. https://hackerone.com/reports/1701378 |
| **Known confidence** | 6/10 |
| **Conditional** | no |
| **Finding key** | `865cfc34f5e852a4` |

### Impact

High (CVSS 7.4): for an account protected with TOTP, the mailbox alone is enough to take it over. The onValidateLogin callback that enforces the second factor returns early for the password login produced by resetPassword and for verifyEmail, and Meteor's handlers for both hand back a login token, so an emailed reset link yields a full session without any code. That defeats the exact threat 2FA was enrolled against (someone who has the password or the mailbox), and the same session can then read the account's TOTP seed through another finding in this report, making the compromise permanent.

### Remediation

Let resetPassword and verifyEmail perform their action without issuing a session when the account has an active second factor (wrap Meteor's handlers, or move the reset to a REST route that does), or require a TOTP or backup code in the reset form itself; then remove the two exemptions at 2fa/loginHandler.ts:22-23 so the callback covers the recovery path like every other login. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md (a recovery flow must not be a way around the second factor) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Forgot_Password_Cheat_Sheet.md.

### Side effects of the fix

Keeps password reset and email verification and removes only the weakness: a user with 2FA enrolled signs in once more after resetting, presenting their second factor, and a user who has lost that factor uses the administrator reset path that already exists; users without 2FA see no change at all.

### Detail

see findings


[analysis](findings/VULN-015.md)


### Dynamic validation

- **Status**: CONFIRMED (the mailbox alone produced a working session on a TOTP-protected account; password login for the same account still demanded the code)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-015-mfa_bypass_via_password_reset/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-015-mfa_bypass_via_password_reset/writeup.md](exploits/VULN-015-mfa_bypass_via_password_reset/writeup.md)

## VULN-030: Deactivated and pending-approval accounts get working tokens through the OAuth login-code path, which bypasses validateLoginAttempt, and REST never re-checks active

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an account the administrator had deactivated signed in through the OAuth login-code path and its token read and wrote as that account, while the password path refused it) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven: a deactivated account signed in through the OAuth path and posted, while the password path refused it. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N |
| **CWE** | CWE-288, CWE-863 |
| **Category** | Authentication bypass through an alternate path (account state not enforced) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/loginCode.ts:56` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-30: searched deactivated user OAuth login token; adjacent (other paths, all fixed): GHSA-39hg-492f-3c4f / CVE-2026-49277, GHSA-6g3w-vg5p-w892 / CVE-2026-45757 (whose advisory notes REST checks no active), GHSA-7qr6-q62g-hm63 / CVE-2026-30831. |
| **Regression of** | CVE-2026-45757 |
| **Conditional** | yes: an OAuth login provider enabled (GitHub, Google, GitLab, Apple web, or Custom OAuth with the EE module) |
| **Finding key** | `5d6a87e984261c0c` |

### Impact

High (CVSS 7.1): the two account-state controls administrators rely on, deactivation for offboarding and manual approval for gatekeeping, do not hold for anyone who can sign in through a configured provider. Meteor's validateLoginAttempt refuses an inactive account, but the Passport callback never enters that pipeline: it mints a login code (or a 2FA challenge) for whatever user the upsert returned, loginCode.redeem turns the code into a login token through issueLoginToken, which only writes the hash, and REST authentication then finds the user by token and id with no active condition. A deactivated user therefore reads and posts in every room they belonged to and can mint personal access tokens; with manual approval on, an unapproved account gets a working session.

### Remediation

Put the state rules where tokens are made and used: have issueLoginToken load the user and refuse active !== true and type === 'app' (and run the failed-login and onValidateLogin callbacks there, or route the Passport result through a Meteor login handler so the existing pipeline applies), and add active: true to the token lookup in ApiClass.authenticatedRoute (ApiClass.ts:894-902), which the OAuth-bearer branch already does with findOneActiveById. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Deny by Default; Validate the Permissions on Every Request) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Session_Management_Cheat_Sheet.md.

### Side effects of the fix

Keeps social login and removes only the weakness: a deactivated or unapproved account can no longer obtain or use a token on any path, and every authenticated REST request matches one extra indexed field, which is negligible; a workspace that deliberately let deactivated users keep API access (no documented use) loses it.

### Detail

see findings


[analysis](findings/VULN-030.md)


### Dynamic validation

- **Status**: CONFIRMED (an account the administrator had deactivated signed in through the OAuth login-code path and its token read and wrote as that account, while the password path refused it)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-030-deactivated_account_oauth_login_code/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-030-deactivated_account_oauth_login_code/writeup.md](exploits/VULN-030-deactivated_account_oauth_login_code/writeup.md)

## VULN-073: Mailer placeholder regex is still quadratic after the CVE-2021-32832 fix, and the anonymous offline form feeds it unbounded text

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an unauthenticated request held the server for 20.02s at 80000 characters, the cost growing 44.5x for 16x the input) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven unauthenticated: one request held the workspace for twenty seconds and the cost grew quadratically. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |
| **CWE** | CWE-1333, CWE-400 |
| **Category** | Denial of service (regular expression complexity, ReDoS) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/notifications/email/replaceVariables.ts:2` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 08 R-03: parent GHSA-wpp8-mvvg-33rx / CVE-2021-32832 (GHSL-2020-310, fixed 3.11.3, 3.12.2, 3.13 by commit 4a0dce9, which replaced the exponential pattern with a quadratic one); vendor-tracker searches 'replaceVariables regex' and 'offline.message ReDoS': 0 results. |
| **Regression of** | CVE-2021-32832 |
| **Conditional** | no |
| **Finding key** | `c201662a7a8e42d0` |

### Impact

High (CVSS 7.5): replaceVariables runs /\{ *([^\{\} ]+)[^\{\}]*\}/gim over every string the mailer templates, and the two adjacent negated character classes overlap, so an opening brace followed by a long run of non-brace characters with no closing brace makes the engine try every split: quadratic work per brace, on the single thread that serves the whole workspace. The anonymous Livechat offline form reaches it with no length bound: its schema declares name, email and message as plain strings with no maxLength, and Mailer.send evaluates replace() on the subject and twice on the HTML body (for the text part and for wrap) before sendNoWrap even looks at the recipient, so no offline recipient needs to be configured for the work to happen. One unauthenticated request per five seconds per address is enough to hold the event loop.

### Remediation

Make the scan linear rather than regex-backtracked in replaceVariables.ts:1-2 (find a brace, read the key up to a space or a closing brace, give up at the next opening brace), and bound the inputs: add maxLength to name, email and message in the offline-message schema (rest-typings omnichannel.ts:2349-2372) and cap the strings the mailer will template at a few kilobytes. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Denial_of_Service_Cheat_Sheet.md (validate input size; bound the work per request) with deploy/knowledge/payloads/PayloadsAllTheThings/Regular Expression/README.md for the pattern shapes.

### Side effects of the fix

Keeps mail templating and the offline form and removes only the weakness: an offline message longer than the cap is refused with a 400, and templates with well-formed placeholders behave exactly as before (a malformed, unclosed brace is simply left as text, as it is today).

### Detail

see findings


[analysis](findings/VULN-073.md)


### Dynamic validation

- **Status**: CONFIRMED (an unauthenticated request held the server for 20.02s at 80000 characters, the cost growing 44.5x for 16x the input)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-073-mailer_placeholder_redos/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-073-mailer_placeholder_redos/writeup.md](exploits/VULN-073-mailer_placeholder_redos/writeup.md)
- **Detection**: [`detections/VULN-073.sigma.yml`](detections/VULN-073.sigma.yml) (high, validated: fired on 1/1 of this exploit's own log lines, silent on 400 clean ones). It sees the offline-message route failing with 503, which is the denial of service landing; not the long input, and not the requests that stall without timing out.

## VULN-044: CAS session fixation: the credential token is chosen in the service URL, so a crafted link to the real CAS server hands the victim's account to the attacker

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the CAS handshake needs a trusted CAS server over HTTPS, which this sealed lab cannot provide) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N |
| **CWE** | CWE-384, CWE-352 |
| **Category** | Authentication bypass (session fixation in the SSO handoff) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/cas/middleware.ts:54` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-44: searched CAS login credentialToken session fixation service URL; adjacent only GHSA-rr54-jf4h-6cj9 / CVE-2026-45688 (NoSQL injection hijacking in-flight CAS and SAML logins, fixed 8.5.0), CVE-2022-35248 (2FA bypass by asking for CAS, fixed), open PR #40196. |
| **Conditional** | yes: CAS_enabled with CAS_base_url and CAS_login_url pointing at the organisation's CAS server |
| **Manual reason** | external-network |
| **Finding key** | `2c8558c36a187304` |

### Impact

High (CVSS 8.1): the token that becomes a Rocket.Chat session is picked by whoever builds the CAS service URL, and anyone who knows it can redeem it. The client draws a random credentialToken and embeds it in the service URL as /_cas/<token>; the server validates the returned ticket against that same URL and stores the validated identity under the token from the request path; login({ cas: { credentialToken } }) then hands a full session to any caller presenting it within 60 seconds. Nothing binds the completed round trip to the browser that started it. So an attacker who picks their own token, sends the victim a link to the organisation's genuine CAS server with that token in the service parameter, and polls the login method, receives the victim's account, administrators included, with no password and with CAS explicitly exempted from Rocket.Chat's second factor.

### Remediation

Make the token the server's and bind it to one browser: generate it when the popup opens and pair it with a secret delivered only to that browser (an HttpOnly cookie scoped to /_cas, or a credentialSecret returned to the opener as Meteor's own OAuth flow does), and require both at login({ cas }); accept only serviceValidate (refuse proxy tickets unless allow-listed); and remove the cas exemption from the 2FA callback (2fa/loginHandler.ts:18-27) unless MFA is explicitly delegated to the identity provider. Grounding: deploy/knowledge/owasp/wstg/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation.md and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md (login CSRF).

### Side effects of the fix

Keeps CAS login and removes only the weakness: a CAS login completed in a different browser from the one that started it stops working (no first-party client does that), CAS users who have a Rocket.Chat second factor are asked for it unless MFA is delegated, and proxy tickets are refused unless allow-listed.

### Detail

see findings


[analysis](findings/VULN-044.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the CAS handshake needs a trusted CAS server over HTTPS, which this sealed lab cannot provide)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-044-cas_session_fixation/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-044-cas_session_fixation/writeup.md](exploits/VULN-044-cas_session_fixation/writeup.md)

## VULN-048: Omnichannel external frame puts the agent's plaintext session token in the frame URL, and the encryption key the setting promises is a public setting

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the agent-side browser drive did not fit this stage's time budget; the settings themselves are checked here) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N |
| **CWE** | CWE-598, CWE-311 |
| **Category** | Sensitive data exposure (session token in a URL; documented encryption not applied) |
| **Location** | `targets/rocket.chat/apps/meteor/client/views/omnichannel/ExternalFrameContainer.tsx:35` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-48: searched Omnichannel external frame token URL and the public JWK setting; adjacent only open PRs #43847 and #43848 (React rewrite of the container). |
| **Conditional** | yes: Omnichannel_External_Frame_Enabled with Omnichannel_External_Frame_URL and _Encryption_JWK set |
| **Manual reason** | browser |
| **Finding key** | `109fbe6cb60ae19b` |

### Impact

High (CVSS 7.4): the external-frame feature embeds a third-party CRM page beside a Livechat conversation, and the product's setting pair (a frame URL plus an encryption JWK) tells the operator the agent's token will be encrypted. The component does encrypt it, and then discards the result: the ciphertext is used only as a readiness flag in the memo's dependency list, while the URL receives frameURL.searchParams.append('t', authToken), the plaintext session token. That token is a 90-day credential already past any second factor, and it is now in a URL handed to an external host, so it lands in that host's access logs, in proxies and CDNs on the way, in Referer headers, in browser history and in any analytics or extension code running on the CRM page. Separately, the JWK that should have protected it is registered public: true, so every client (including an unauthenticated one through settings.public) can read it, making server-side encryption with that key worthless as well.

### Remediation

Append token.data, the ciphertext, as t and never authToken (ExternalFrameContainer.tsx:27-38), and register Omnichannel_External_Frame_Encryption_JWK with public: false so the key stays server-side, moving the encryption to the server; better still, mint a short-lived, single-purpose frame token and deliver it by postMessage to the frame's exact origin rather than putting any credential in a URL. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Session_Management_Cheat_Sheet.md (never transmit a session identifier in a URL) and deploy/knowledge/owasp/wstg/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables.md.

### Side effects of the fix

Keeps the feature and removes only the weakness: an external system that consumed the plaintext t must decrypt it, which is what the setting already documents, and the key is no longer readable by browsers, so any integration that decrypted client-side must move that step server-side.

### Detail

see findings


[analysis](findings/VULN-048.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the agent-side browser drive did not fit this stage's time budget; the settings themselves are checked here)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-048-external_frame_token_in_url/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-048-external_frame_token_in_url/writeup.md](exploits/VULN-048-external_frame_token_in_url/writeup.md)

## VULN-074: Unbounded metric label cardinality: method.call samples are labelled with the raw request path, so anonymous requests grow the registry until memory runs out

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (300 anonymous requests with distinct paths added 7774 time series and grew the metrics body by 1024449 bytes, with nothing evicting them) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven with the metrics endpoint on: 300 anonymous requests doubled the registry and nothing evicts the series. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |
| **CWE** | CWE-770, CWE-400 |
| **Category** | Uncontrolled resource consumption (unbounded metric label cardinality) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/middlewares/metrics.ts:57` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Not covered by any stage 07 search (the pointer came from stage 05); no advisory or issue names metrics label growth in Rocket.Chat; searching for it is left to stage 12. |
| **Conditional** | no |
| **Finding key** | `356468744da1ca0f` |

### Impact

High (CVSS 7.5): the REST metrics middleware normally labels a sample with the matched route pattern, which is a bounded set, but for any route whose pattern starts with method.call it substitutes decodeURIComponent(path), the raw request path. method.callAnon/:method matches any method name, is unauthenticated and explicitly opts out of the REST rate limiter, so each request with a fresh path segment creates a new label set in a prom-client Summary (with percentiles) and in two Histograms (fourteen and nine buckets), which are retained in process memory. The middleware is mounted by startRestAPI whether or not Prometheus is enabled, prom-client imposes no cardinality cap, and Prometheus_Reset_Interval ships at 0, so nothing ever clears them: an anonymous attacker with throughput grows the registry until the container's memory limit is reached and the process dies.

### Remediation

Label method-bridge samples with something bounded: use the route pattern, or the method name when it resolves to a registered Meteor method and the literal unknown otherwise, instead of decodeURIComponent(path) at metrics.ts:57; and cap the number of distinct label values the middleware will create per metric, dropping to a catch-all label beyond it. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Denial_of_Service_Cheat_Sheet.md (bound the resources one request may allocate) with deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Logging_Cheat_Sheet.md for not letting request data shape the telemetry.

### Side effects of the fix

Keeps the metrics and removes only the weakness: per-path series for method-bridge calls collapse into one series per method name (or into unknown for unregistered names), so a dashboard that counted invalid method paths individually loses that detail; valid method metrics are unchanged.

### Detail

see findings


[analysis](findings/VULN-074.md)


### Dynamic validation

- **Status**: CONFIRMED (300 anonymous requests with distinct paths added 7774 time series and grew the metrics body by 1024449 bytes, with nothing evicting them)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-074-metric_label_cardinality/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-074-metric_label_cardinality/writeup.md](exploits/VULN-074-metric_label_cardinality/writeup.md)
- **Detection**: [`detections/VULN-074.sigma.yml`](detections/VULN-074.sigma.yml) (high, validated: fired on 300/300 of this exploit's own log lines, silent on 400 clean ones). It sees any anonymous DDP method name outside the shipped client's own set, which is how the metric series are created; Sigma does not count, so the volume is the number of alerts.

## VULN-031: SAML assertions are not bound to this service provider: no Audience, Recipient, Destination or InResponseTo check, so another SP's assertion logs in

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (SAML is a licensed enterprise module and is not present on this unlicensed workspace) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | high |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N |
| **CWE** | CWE-345, CWE-287 |
| **Category** | Authentication bypass (assertion not bound to its intended recipient) |
| **Location** | `targets/rocket.chat/apps/meteor/ee/server/lib/saml/lib/parsers/Response.ts:151` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-31: searched SAML Audience Recipient Destination InResponseTo not validated; adjacent only CVE-2026-58066 (signature wrapping, fixed 8.7.0 via PR #41233), CVE-2026-46423, CVE-2026-45677, CVE-2026-22560, CVE-2020-29594. |
| **Conditional** | yes: the EE saml-enterprise licence with a SAML provider configured, and an IdP that signs assertions for several service providers with one key |
| **Manual reason** | config-flag |
| **Finding key** | `a7d734eb7f67c2ab` |

### Impact

High (CVSS 7.4): the SAML validator verifies the signature and the time windows and then trusts the assertion, without ever asking whether it was addressed to this workspace. Audience, SubjectConfirmationData/@Recipient and the response's Destination are never read, and InResponseTo is recorded into the profile but never compared with a request this server sent. Wherever an identity provider signs for several service providers with one key (a Keycloak realm key, an ADFS token-signing certificate, Shibboleth defaults), the operator of any other federated SP, or anyone who captures an assertion inside its validity window, can post it to Rocket.Chat and get a session as its subject, administrators included, with no password and past Rocket.Chat's own login checks.

### Remediation

In Response.ts refuse a response whose Destination is not this ACS URL, whose assertion Conditions/AudienceRestriction does not name this SP's entity id, and whose SubjectConfirmationData/@Recipient differs from the ACS URL; store the ids of AuthnRequests this server issued and require InResponseTo to match one, accepting unsolicited (IdP-initiated) responses only behind an explicit setting. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/SAML_Security_Cheat_Sheet.md (Service Provider considerations and Unsolicited Response considerations) with deploy/knowledge/payloads/PayloadsAllTheThings/SAML Injection/README.md for the test shapes.

### Side effects of the fix

Keeps SAML login and removes only the weakness: IdP-initiated logins require an administrator to opt in, and an identity provider configured to omit Audience, Destination or Recipient must be configured to send them (all three are standard and emitted by default by the common IdPs), so a misconfigured federation that worked by accident stops until it is corrected.

### Detail

see findings


[analysis](findings/VULN-031.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (SAML is a licensed enterprise module and is not present on this unlicensed workspace)
- **Confidence**: 5/10
- Exploit directory: `exploits/VULN-031-saml_assertion_not_bound_to_sp/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-031-saml_assertion_not_bound_to_sp/writeup.md](exploits/VULN-031-saml_assertion_not_bound_to_sp/writeup.md)

## VULN-010: Missing authorization on chat.getDeletedMessages: any user lists the deleted-message ids and timing of any room

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (any authenticated account reads the deleted-message ids, count and timing of a private group it is refused every other way) |
| **Confidence** | 9/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-862 |
| **Category** | Missing authorization (room metadata disclosure) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/chat.ts:1040` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | known-unpatched |
| **Known evidence** | Issue #42481 'chat.getDeletedMessages leaks deleted-message IDs of rooms the caller cannot access' (2026-10-01; closed 2026-10-02 by the vendor, 'we will track it'), same endpoint, root cause and reproduction; no fix merged, chat.ts:1016-1059 still has only authRequired at 9f3d6c8c. No CVE or GHSA. https://github.com/RocketChat/Rocket.Chat/issues/42481 |
| **Known confidence** | 9/10 |
| **Conditional** | no |
| **Finding key** | `d913397d86b25025` |

### Impact

Medium (CVSS 4.3): any account that knows a room id, including a private group or a direct message it has no part in, learns how many messages were deleted there, when, and their ids, by paging since backwards. The content is not returned, so this is metadata: the activity pattern of a room the caller cannot open (who is cleaning up and when) plus message ids that feed the per-message routes elsewhere in this report. Room ids are not secrets; they appear in permalinks, invite payloads, notification payloads and the responses of several other routes.

### Remediation

At the top of the handler (chat.ts:1036) refuse unless canAccessRoomIdAsync(roomId, this.userId) holds, the check the neighbouring history method performs before it reads anything (getChannelHistory.ts:39-42). Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md (look objects up within what the caller may reach).

### Side effects of the fix

Keeps the sync feature for members and removes only the weakness: a non-member gets 403 where it previously got a list, so a client that polled this route for rooms the user has since left stops receiving data for them.

### Detail

see findings


[analysis](findings/VULN-010.md)


### Dynamic validation

- **Status**: CONFIRMED (any authenticated account reads the deleted-message ids, count and timing of a private group it is refused every other way)
- **Confidence**: 9/10
- Exploit directory: `exploits/VULN-010-deleted_message_metadata_disclosure/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-010-deleted_message_metadata_disclosure/writeup.md](exploits/VULN-010-deleted_message_metadata_disclosure/writeup.md)
- **Detection**: [`detections/VULN-010.sigma.yml`](detections/VULN-010.sigma.yml) (medium, validated: fired on 2/2 of this exploit's own log lines, silent on 400 clean ones). It sees every call to chat.getDeletedMessages with the room it names (no first-party client calls this route); not whether the caller was entitled to that room.

## VULN-003: Cross-user event injection on notify-room-users: any member forges userData and video-conference events into every other member's private stream

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (one ordinary member injected a forced logout, a user-document rewrite (name and roles) and a forged incoming call into another member's private realtime channel) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:L |
| **CWE** | CWE-345, CWE-862 |
| **Category** | Broken access control on a realtime channel (cross-user event injection) |
| **Location** | `targets/rocket.chat/packages/streamer/src/notifications.module.ts:314` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | known-unpatched |
| **Known evidence** | Issue #42669 (filed 2026-10-09) reports the unvalidated video-conference relay; its fix PR #42754 is open and not in this build (notifications.module.ts:299-317 relays both events unvalidated at 9f3d6c8c). Residual of GHSA-r3v3-v742-55j5 (fixed 8.8.0 and backports, whose allow-list is at notifications.module.ts:304-308). The userData leg is in no public report. https://github.com/RocketChat/Rocket.Chat/issues/42669 |
| **Known confidence** | 8/10 |
| **Regression of** | GHSA-r3v3-v742-55j5 |
| **Conditional** | no |
| **Finding key** | `7c315bb9a870bc61` |

### Impact

Medium (CVSS 6.4): one DDP call from an ordinary account hits every online member of a shared room. A forged userData removed event makes their web clients discard stored credentials and drop to the login page (repeatable, so a persistent nuisance outage timed to push users at a phishing login); a forged updated event rewrites the client-side user record other members hold (displayed roles, status, profile); a forged video-conference call event rings them with an incoming call attributed to any user, including an administrator. Server-side sessions stay valid and nothing is read, so the loss is integrity and availability of other users' clients.

### Remediation

In notifications.module.ts:300-317 drop userData from the relay (no shipped client writes it) and run relayed video-conference events through VideoConf.validateAction with uid equal to this.userId, exactly as the direct notify-user write at :319-343 already does; better, give streamUser an emit rule so notify-user/<uid>/userData carries only server-produced events. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/WebSocket_Security_Cheat_Sheet.md (message-level authorization and input validation on every frame).

### Side effects of the fix

Keeps call ringing between room members and removes only the weakness: relayed userData events stop being delivered (no first-party client sends them, and the real ones come from the server), and malformed or impersonated call events are refused instead of forwarded.

### Detail

see findings


[analysis](findings/VULN-003.md)


### Dynamic validation

- **Status**: CONFIRMED (one ordinary member injected a forced logout, a user-document rewrite (name and roles) and a forged incoming call into another member's private realtime channel)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-003-realtime_event_injection_notify_room_users/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-003-realtime_event_injection_notify_room_users/writeup.md](exploits/VULN-003-realtime_event_injection_notify_room_users/writeup.md)

## VULN-007: users.listByStatus leaks every account's email, roles and last login to any ordinary user, and sorts on client-chosen fields before projecting

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an ordinary account read every account's email address, role list and last-login time, administrators included, and ordered the listing by a field the response never returns) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-359, CWE-203 |
| **Category** | Authenticated data exposure (PII across teams) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/lib/users.ts:171` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-07: searched users.listByStatus email disclosure; adjacent only CVE-2022-32219 (users.list query injection, fixed 4.7.5), CVE-2021-22892 and CVE-2020-28208 (email enumeration, fixed). Stage 08 R-27 links the residual client-chosen sort to CVE-2022-32219. |
| **Regression of** | CVE-2022-32219 |
| **Conditional** | no |
| **Finding key** | `69e09d462fa776ff` |

### Impact

Medium (CVSS 4.3): the lowest-privileged account enumerates the whole workspace directory. One paged call returns every user's email address, role assignments (which names the administrators) and last-login time, across every team, while the sibling users.list strips exactly those fields for the same caller. The address list is the input for the email-keyed attacks elsewhere in this report (OAuth email meld, Direct Reply spoofing, reset-mailbox 2FA bypass) and the roles say whom to aim them at; lastLogin shows which accounts are dormant. The client-chosen sort runs in MongoDB before the projection, so ordering also answers questions about fields the response never prints.

### Remediation

Gate users.listByStatus on view-user-administration (or view-full-other-user-info) at users.ts:789 instead of view-d-room, build the projection in findPaginatedUsersByStatus from the caller's rights the way the users.list path does through parseJsonQuery.ts:41-48 (emails, roles, lastLogin and services are already in defaultLimitedUserFieldsToExclude for unprivileged callers), and accept sort only from an allow-list of fields that are actually projected. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Enforce Least Privileges) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Input_Validation_Cheat_Sheet.md (allow-list, not deny-list).

### Side effects of the fix

Keeps the admin Users page working for administrators and removes only the weakness: ordinary users lose an endpoint the web client never calls on their behalf (the admin screen is the only caller), and a request sorting on a field outside the allow-list gets a 400 instead of a silent privileged sort.

### Detail

see findings


[analysis](findings/VULN-007.md)


### Dynamic validation

- **Status**: CONFIRMED (an ordinary account read every account's email address, role list and last-login time, administrators included, and ordered the listing by a field the response never returns)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-007-workspace_pii_disclosure_to_any_user/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-007-workspace_pii_disclosure_to_any_user/writeup.md](exploits/VULN-007-workspace_pii_disclosure_to_any_user/writeup.md)
- **Detection**: [`detections/VULN-007.sigma.yml`](detections/VULN-007.sigma.yml) (medium, validated: fired on 1/1 of this exploit's own log lines, silent on 400 clean ones). It sees the user listing ordered by services.password.bcrypt, the credential-field probe; not the plain listing call, which is the admin area's own request.

## VULN-009: Room ban not enforced on the notification and file-download paths, because both match the banned subscription

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a banned member kept receiving the room's new messages through notifications and downloaded its file, while the room's history refused it) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-863 |
| **Category** | Broken access control (ban not enforced on the notification and file paths) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/media/file-upload/lib/FileUpload.ts:543` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-09: searched banned users still receiving notifications and files; adjacent only PR #43318 (XMPP rooms ignoring bans), HackerOne #2028450 (banned user deleting messages), CVE-2026-48616 (a different check in the same file function). |
| **Conditional** | no |
| **Finding key** | `4718fc9635cb2f7b` |

### Impact

Medium (CVSS 4.3): a room ban, the moderators' tool for shutting one person out of a room, leaks on two side paths. The banned account keeps receiving new-message notifications for that room, and a notification payload carries the message text and sender, so the banned user follows the conversation in real time while the history and stream routes correctly refuse them; and with the shipped members-only download mode they keep downloading the room's files by id. The account stays active, so no further step is needed; what leaks is the text of new messages in that one room and its attachments.

### Remediation

Add status: { $exists: false } to the notification recipient query in sendNotificationsOnMessage.ts:292-299 so a marked subscription cannot be a recipient, and replace the members-only download check at FileUpload.ts:542-544 with the status-aware Subscriptions.countByRoomIdAndUserId (or with canAccessRoomIdAsync, which the sibling mode already uses); then audit the other call sites of the status-blind findOneByRoomIdAndUserId and give the model a status-aware variant so the next caller cannot repeat the mistake. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Deny by Default, and Enforce Authorization Checks on Static Resources for the file route).

### Side effects of the fix

Keeps notifications and file downloads for members and removes only the weakness: banned users stop receiving that room's notifications and can no longer fetch its files, which is what the ban already promises; no change for anyone who is not banned.

### Detail

see findings


[analysis](findings/VULN-009.md)


### Dynamic validation

- **Status**: CONFIRMED (a banned member kept receiving the room's new messages through notifications and downloaded its file, while the room's history refused it)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-009-ban_bypass_notifications_and_files/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-009-ban_bypass_notifications_and_files/writeup.md](exploits/VULN-009-ban_bypass_notifications_and_files/writeup.md)

## VULN-012: Mass assignment in rooms.mediaConfirm: a member sets any message type t, forging system notices that chat.sendMessage refuses

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an ordinary member stored two messages with attacker-chosen system types and text, which the ordinary send path refuses outright) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N |
| **CWE** | CWE-915, CWE-451 |
| **Category** | Mass assignment (forged system notices) |
| **Location** | `targets/rocket.chat/apps/meteor/server/meteor-methods/messages/sendFileMessage.ts:174` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-12: sibling path of CVE-2026-106075 (chat.sendMessage mass assignment, fixed 9.0.0) and of GHSA-fhc2-x8cp-c5ch / CVE-2026-45687 (sendFileMessage allow-list, which still includes t); this file-message path is not reported. |
| **Regression of** | CVE-2026-106075 |
| **Conditional** | no |
| **Finding key** | `01216ecbd489034f` |

### Impact

Medium (CVSS 4.3): an ordinary member posts messages that render as the server's own system notices in any room they can upload to. Confirming an upload with {"t":"r","msg":"Payroll-update-see-pinned-link"} renders as "Room name changed to Payroll-update-see-pinned-link" in system styling, and t:"ul" renders "User left this channel"; readers have no way to tell these from genuine server events, which makes them a strong in-workspace phishing and confusion primitive. The same field also admits t:"e2e", which satisfies the encrypted-room gate in sendMessage and so slips a plaintext message past the "no unencrypted messages in an encrypted room" rule.

### Remediation

In sendFileMessage.ts:164-182 stop accepting an arbitrary t: restrict it to the literal e2e and accept it only when content is present and the room is encrypted, or call the same MessageTypes.isSystemMessage refusal the plain send route applies at chat.ts:965-967. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Mass_Assignment_Cheat_Sheet.md (allow-list the bindable fields; never bind a field that changes how the object is interpreted).

### Side effects of the fix

Keeps file messages, captioned uploads and encrypted file messages and removes only the weakness: a client that sends any other t with a file receives error-invalid-arguments, and nothing can create a system-typed message through the upload path.

### Detail

see findings


[analysis](findings/VULN-012.md)


### Dynamic validation

- **Status**: CONFIRMED (an ordinary member stored two messages with attacker-chosen system types and text, which the ordinary send path refuses outright)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-012-forged_system_messages_via_mediaconfirm/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-012-forged_system_messages_via_mediaconfirm/writeup.md](exploits/VULN-012-forged_system_messages_via_mediaconfirm/writeup.md)

## VULN-026: Workspace-wide denial of service from one message: the markdown parser is super-quadratic and the attachment-description parse has no length cap

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (one ordinary member's message held the server for 3.05s at 4000 characters and 6.97s as an attachment description past the message-size limit, while a bystander's request waited up to 2.78s) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven: one member's message cost seven seconds of server time and a bystander's request waited nearly three. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H |
| **CWE** | CWE-407, CWE-400 |
| **Category** | Denial of service (inefficient algorithmic complexity) |
| **Location** | `targets/rocket.chat/apps/meteor/server/services/messages/hooks/BeforeSaveMarkdownParser.ts:43` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-26: parent CVE-2024-46935 / GHSA-6375-pg5j-8wph (message-parser < 0.31.30, fix PR #33227); OSV for @rocket.chat/message-parser@0.33.0 returns 0, so the parent fix is in; the residual cost and the uncapped description parse are not reported. |
| **Regression of** | CVE-2024-46935 |
| **Conditional** | no |
| **Finding key** | `8d1f1bf166765a2a` |

### Impact

Medium (CVSS 6.5): Rocket.Chat's server is single-threaded, and the markdown parse runs synchronously on the request that saves a message, so the parse time is an outage for every user. Stage 03 measured the bundled parser at about 9.8 s for 5000 asterisks and about 103 s for 20000: during that time no REST call, DDP frame or stream delivery is served, workspace-wide. The message body has a parse-length gate, but the first attachment's description is parsed with no length check at all, and chat.sendMessage places no maxLength on attachment items, so the cheapest path is an attachment description rather than a message body. The attack is repeatable at the shipped send limit.

### Remediation

Apply getMessageMaxParseLength() to every field the hook parses, not just message.msg (BeforeSaveMarkdownParser.ts:31-44); cap attachment descriptions at Message_MaxAllowedSize in validateMessage (sendMessage.ts:131-164, where attachments are already validated) and give the REST attachment items a maxLength; and bound the parser's own work, either by making the tokenizer linear or by running it with a time budget off the event loop and falling back to plain text. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Denial_of_Service_Cheat_Sheet.md (input validation and bounded work per request; do not let one request monopolise a shared thread).

### Side effects of the fix

Keeps markdown rendering and removes only the weakness: an attachment description longer than the cap is refused (or stored as plain text rather than parsed), and a pathological input renders unformatted instead of blocking the server; no legitimate message changes.

### Detail

see findings


[analysis](findings/VULN-026.md)


### Dynamic validation

- **Status**: CONFIRMED (one ordinary member's message held the server for 3.05s at 4000 characters and 6.97s as an attachment description past the message-size limit, while a bystander's request waited up to 2.78s)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-026-markdown_parser_dos/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-026-markdown_parser_dos/writeup.md](exploits/VULN-026-markdown_parser_dos/writeup.md)

## VULN-045: Profanity filter is a per-token, per-word regex scan on the request path, so one member stalls the whole server for seconds per message

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (one member's 500-token message took 3.32s of server time with the filter on against 0.31s with it off, and a bystander waited up to 2.78s) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven: one member's message cost ten times what the same message costs with the filter off, and a bystander waited with it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H |
| **CWE** | CWE-407, CWE-400 |
| **Category** | Denial of service (inefficient algorithmic complexity on the request path) |
| **Location** | `targets/rocket.chat/apps/meteor/server/services/messages/hooks/BeforeSaveBadWords.ts:60` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-45: searched bad-words clean slow performance denial of service; OSV bad-words@3.0.4 and badwords-list@1.0.0: 0; only competing-library benchmarks exist. |
| **Conditional** | yes: Message_AllowBadWordsFilter (the profanity filter) enabled |
| **Finding key** | `f278ceee2c6dd64b` |

### Impact

Medium (CVSS 6.5): with the profanity filter on, every message is passed synchronously through bad-words' clean() before the markdown parse, on the single thread that serves every other request. The bundled library splits the text on word boundaries and, for each token, compiles and tests a fresh regular expression for each of its roughly 900 built-in words plus the administrator's list, so the cost is the product of token count and list size. Stage 05 measured it in this build: about 3.96 s for 5000 characters of prose and about 8.9 s for a 5000-character message of single letters. During that time the workspace serves nothing: no REST, no DDP, no stream delivery. An ordinary member repeating such messages at the shipped send rate keeps the server saturated, and ordinary long messages cost seconds each even without an attacker.

### Remediation

Build one combined, escaped alternation (extending the existing badWordsRegex field in BeforeSaveBadWords.ts, which already does a single-pass replace for the administrator's list) when the settings change, and replace matches in one pass over the message instead of calling the library's per-token clean(); optionally run the filter off the event loop with a time budget and fall back to the unfiltered text. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Denial_of_Service_Cheat_Sheet.md (bound the work one request may do; never let a single request monopolise a shared thread).

### Side effects of the fix

Keeps the filter and both word lists and removes only the weakness: a few edge cases where the library's per-token matching and a single combined pattern disagree may mask slightly differently, and administrator-supplied words are treated as literals rather than as regular expressions.

### Detail

see findings


[analysis](findings/VULN-045.md)


### Dynamic validation

- **Status**: CONFIRMED (one member's 500-token message took 3.32s of server time with the filter on against 0.31s with it off, and a bystander waited up to 2.78s)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-045-profanity_filter_dos/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-045-profanity_filter_dos/writeup.md](exploits/VULN-045-profanity_filter_dos/writeup.md)

## VULN-046: Anonymous write into any room through livechat/page.visited, which resolves neither the visitor token nor the room

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an unauthenticated caller wrote an attacker-chosen notice into #general through livechat/page.visited, attributed to the workspace bot, and the write still lands (hidden) with the notice setting off) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N |
| **CWE** | CWE-862 |
| **Category** | Missing authorization (anonymous write into arbitrary rooms; content spoofing) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/omnichannel/tracking.ts:53` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-46: searched livechat page.visited navigation history any room unauthenticated; adjacent only PR #14970 (2019, removed the visitor and room validation, the origin of the gap), PR #10091, PR #42710, CVE-2021-48022. |
| **Conditional** | yes: Livechat_Visitor_navigation_as_a_message enabled (with it off, the same request still writes a hidden message into any room) |
| **Finding key** | `924d2d9490947319` |

### Impact

Medium (CVSS 5.3): the Livechat page-tracking endpoint takes a visitor token and a room id from an unauthenticated request and passes them to savePageHistory, which never looks the visitor up and never loads the room: it just saves a system message into the room id it was given, authored by rocket.cat, with the title and URL the caller supplied. With Livechat_Visitor_navigation_as_a_message enabled, that notice is visible, so anyone on the internet posts bot-attributed, system-styled text and links into #general or any room whose id they hold. With the setting at its shipped off, the same request still writes the document into that room marked _hidden, which bumps the room's counters and lands in exports and in the routes elsewhere in this report that return hidden messages.

### Remediation

Resolve the visitor from the token and require rid to be that visitor's own open Omnichannel room, exactly as the sibling livechat/upload route does with LivechatRooms.findOneOpenByRoomIdAndVisitorToken (upload.ts:31-34); refuse the route while Livechat_enabled is false; and store pre-room navigation with no room id rather than with a caller-supplied one (tracking.ts:9-54). Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md (resolve the object inside what the caller owns).

### Side effects of the fix

Keeps navigation history for real visitor conversations and removes only the weakness: a tracking call naming another room, a non-Omnichannel room or an unknown visitor is refused, and the endpoint writes nothing while Omnichannel is off.

### Detail

see findings


[analysis](findings/VULN-046.md)


### Dynamic validation

- **Status**: CONFIRMED (an unauthenticated caller wrote an attacker-chosen notice into #general through livechat/page.visited, attributed to the workspace bot, and the write still lands (hidden) with the notice setting off)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-046-livechat_page_visited_anonymous_write/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-046-livechat_page_visited_anonymous_write/writeup.md](exploits/VULN-046-livechat_page_visited_anonymous_write/writeup.md)
- **Detection**: [`detections/VULN-046.sigma.yml`](detections/VULN-046.sigma.yml) (medium, validated: fired on 2/2 of this exploit's own log lines, silent on 400 clean ones). It sees every call to livechat/page.visited, anomalous on any default install; not the room id or the injected notice text.

## VULN-047: channels.anonymousread serves Omnichannel conversations and hidden messages to unauthenticated callers, and getRoomRoles skips its access check for them

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an unauthenticated caller read a customer support conversation and a deleted message through channels.anonymousread; the role-listing leg is not reachable, every entry point to it requires authentication) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **CWE** | CWE-863 |
| **Category** | Broken access control (anonymous read of Omnichannel rooms and hidden messages) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/channels.ts:2100` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-47: parents fixed here: the 7.11.0 'Broken Access Control in AnonymousRead' hotfix (#36982) and CVE-2022-35247 (getRoomRoles ACL, HackerOne #1447440), whose check skips anonymous callers; the Livechat-room and hidden-message legs are not reported. |
| **Regression of** | CVE-2022-35247 |
| **Conditional** | yes: Accounts_AllowAnonymousRead enabled (main leg also needs Omnichannel in use) |
| **Finding key** | `e96313ce750d5bbe` |

### Impact

Medium (CVSS 5.9): with anonymous read enabled, the route meant to expose public channels exposes more than that. Its lookup, findChannelByIdOrName, admits rooms of type l (Omnichannel), so a Livechat conversation id returns the whole customer conversation to a caller with no session; the handler checks only the setting and a private-team special case rather than calling canAccessRoomAsync, and its query is { rid } with no _hidden filter, so hidden messages of public channels (which other findings here show include deleted and edited-away content) come back too. Separately, getRoomRoles runs its CVE-2022-35247 access check only when a user is present, so an anonymous DDP caller gets the owners, moderators and leaders of any room by id, and getRoomByTypeAndName likewise skips its check and its lastMessage redaction for anonymous callers.

### Remediation

Make the anonymous path use the shared validator rather than a partial re-implementation: in channels.anonymousread (channels.ts:2092-2123) accept only t 'c', call canAccessRoomAsync(findResult, this.user), which already handles anonymous callers and private teams, and add _hidden: { $ne: true } to the query; in getRoomRoles.ts:26 and publications/room/index.ts:81-93 run the same validator for anonymous callers instead of gating it on fromUser. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Deny by Default; Validate the Permissions on Every Request).

### Side effects of the fix

Keeps anonymous reading of public channels, which is what the setting is for, and removes only the weakness: Omnichannel conversations, hidden messages, private rooms' role lists and channels inside private teams are no longer served to callers without a session.

### Detail

see findings


[analysis](findings/VULN-047.md)


### Dynamic validation

- **Status**: CONFIRMED (an unauthenticated caller read a customer support conversation and a deleted message through channels.anonymousread; the role-listing leg is not reachable, every entry point to it requires authentication)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-047-anonymous_read_omnichannel_rooms/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-047-anonymous_read_omnichannel_rooms/writeup.md](exploits/VULN-047-anonymous_read_omnichannel_rooms/writeup.md)
- **Detection**: [`detections/VULN-047.sigma.yml`](detections/VULN-047.sigma.yml) (medium, validated: fired on 2/2 of this exploit's own log lines, silent on 400 clean ones). It sees every unauthenticated channels.anonymousread with the room id it asks for; not which messages came back.

## VULN-051: Livechat transcript relays visitor-written HTML from the workspace's own mail address to any recipient the caller names

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (an anonymous visitor made the workspace mail attacker-authored HTML, with a working phishing link, from its own address to a third party; the same markup as message text is escaped, so the upload description is the sink) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N |
| **CWE** | CWE-116, CWE-441 |
| **Category** | HTML injection into outbound email (trusted-sender relay) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/omnichannel/sendTranscript.ts:164` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | known-unpatched |
| **Known evidence** | Issue #42432 'escapeHtml result discarded in sendTranscript leaving attachment description unescaped' (open, 2026-09-29) and fix PR #42433 (open, unmerged); sendTranscript.ts:164 unchanged at 9f3d6c8c. The caller-chosen recipient and the unenforced Livechat_enable_transcript are not in that report. PR #36016 (transcript hotfix) escapes message text only. https://github.com/RocketChat/Rocket.Chat/issues/42432 |
| **Known confidence** | 8/10 |
| **Conditional** | yes: Livechat_enabled (Omnichannel on) with a room that can be opened |
| **Finding key** | `8089c23814c9a6fb` |

### Impact

Medium (CVSS 4.7): the anonymous transcript route takes the recipient address from the request body, and sendTranscript builds the mail body by interpolating a message's first attachment description into HTML with the escaping discarded: the code computes escapeHtml(messageContent) and throws the result away, then inserts the raw description. A visitor (anyone, since visitor registration is anonymous) uploads a file whose description is markup, then asks for the transcript to be sent to any address. The result is arbitrary HTML delivered by the organisation's own mail server, from its own sender address, so SPF, DKIM and DMARC all pass. The route also never checks Livechat_enable_transcript, so the workspace sends transcripts even where the operator disabled them, and the recipient need not be the address on the visitor's record.

### Remediation

Assign the escaped value (messageContent = escapeHtml(message.attachments[0].description || '')) and escape every interpolated field in sendTranscript.ts:158-176; in the transcript route, enforce Livechat_enable_transcript, send a visitor-requested transcript only to the address stored on that visitor or contact rather than to one supplied in the body, and cap the number of transcript requests per room. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md (output encoding for the HTML context, applied to every interpolated value) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.md.

### Side effects of the fix

Keeps transcripts and removes only the weakness: markup typed into an attachment description appears as text in the mail, a visitor can no longer choose an arbitrary recipient (the stored address is used), and the route refuses while the workspace has transcripts disabled.

### Detail

see findings


[analysis](findings/VULN-051.md)


### Dynamic validation

- **Status**: CONFIRMED (an anonymous visitor made the workspace mail attacker-authored HTML, with a working phishing link, from its own address to a third party; the same markup as message text is escaped, so the upload description is the sink)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-051-livechat_transcript_html_relay/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-051-livechat_transcript_html_relay/writeup.md](exploits/VULN-051-livechat_transcript_html_relay/writeup.md)
- **Detection**: [`detections/VULN-051.sigma.yml`](detections/VULN-051.sigma.yml) (medium, validated: fired on 1/1 of this exploit's own log lines, silent on 400 clean ones). It sees that a Livechat transcript was mailed; not the recipient address or the HTML, both of which are in the body.

## VULN-054: Omnichannel offline form mails visitor fields unescaped to the support mailbox, and the host field lands inside an href

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an anonymous form submission delivered attacker-authored HTML and an attacker-chosen link into the support mailbox from the workspace's own address) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N |
| **CWE** | CWE-116 |
| **Category** | HTML injection into staff email (content spoofing) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/omnichannel/messages.ts:45` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-54: searched livechat offline message email HTML injection; adjacent only CVE-2026-65644 (HackerOne #3872858, visitor name in the agent UI, fixed 8.8.0), PR #3147, HackerOne #833470. |
| **Regression of** | CVE-2026-65644 |
| **Conditional** | yes: an offline message recipient configured (Livechat_offline_email or a department email) |
| **Finding key** | `86a1a9545a18c263` |

### Impact

Medium (CVSS 4.7): the offline form is the anonymous "nobody is available, leave a message" box on the Livechat widget, and sendOfflineMessage builds its notification mail by concatenating the visitor's name, email address and message into HTML with no encoding, plus the host field directly inside an href attribute with no scheme check. The mail goes from the workspace's own From_Email to the configured support mailbox, so staff receive attacker-authored markup and links in a message their own system sent, with the organisation's SPF, DKIM and DMARC behind it. With message forwarding enabled, the same unescaped text is also posted into an internal channel as rocket.cat, so the content lands in the workspace too, attributed to the platform's bot.

### Remediation

HTML-escape name, email, message and host in messages.ts:39-48, accept host only when it parses as an http(s) URL before putting it in an href (or drop the link and show the text), and in offlineMessageToChannel.ts post the visitor's text as a quoted attachment with markdown and mentions disabled rather than concatenating it into the message body. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md (output encoding per context, including URL attributes) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md for the href.

### Side effects of the fix

Keeps offline messages and removes only the weakness: markup and links a visitor types appear as literal text in the staff mail and in the forwarded channel message, and a host value that is not an http(s) URL is shown as text instead of being linked.

### Detail

see findings


[analysis](findings/VULN-054.md)


### Dynamic validation

- **Status**: CONFIRMED (an anonymous form submission delivered attacker-authored HTML and an attacker-chosen link into the support mailbox from the workspace's own address)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-054-offline_form_html_injection/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-054-offline_form_html_injection/writeup.md](exploits/VULN-054-offline_form_html_injection/writeup.md)
- **Detection**: [`detections/VULN-054.sigma.yml`](detections/VULN-054.sigma.yml) (medium, validated: fired on 2/2 of this exploit's own log lines, silent on 400 clean ones). It sees every offline-form submission; not the unescaped HTML in the name, message and host fields.

## VULN-055: Missing permission check on retentionOverrideGlobal lets any room owner exempt their room from the retention policy

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (an ordinary room owner exempted its own room from the workspace retention policy, while the sibling retention field on the same route refused it) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N |
| **CWE** | CWE-862 |
| **Category** | Missing authorization on a compliance setting |
| **Location** | `targets/rocket.chat/apps/meteor/server/meteor-methods/rooms/saveRoomSettings.ts:363` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | known-unpatched |
| **Known evidence** | PR #43383 by a Rocket.Chat member (merged 2026-11-10; its tests are in this build at saveRoomSettings.test.ts:461-467): 'retentionOverrideGlobal has no permission check on the server. Only the UI hides it. Unit and API tests pin this behavior', and 'This PR does not change them'. No fix, no advisory. https://github.com/RocketChat/Rocket.Chat/pull/43383 |
| **Known confidence** | 9/10 |
| **Conditional** | yes: RetentionPolicy_Enabled for the room's type |
| **Finding key** | `cde5888d2c91bf6c` |

### Impact

Medium (CVSS 4.3): every other per-room retention field in saveRoomSettings has a validator that refuses a caller without edit-room-retention-policy in the room; retentionOverrideGlobal has a saver and no validator, so the only gate it inherits is edit-room, which owners and moderators hold (and any user becomes an owner by creating a channel). Setting it to true is enough: the prune job's global pass selects rooms with retention.overrideGlobal not true, so the room is skipped, and the per-room pass only takes rooms whose own retention.enabled is set, which the owner cannot set without the permission. The room's messages therefore escape the deletion schedule the organisation mandated, quietly: nothing audits the change and the UI does not show the field to users who lack the permission.

### Remediation

Add a retentionOverrideGlobal entry to the validator table in saveRoomSettings.ts that refuses unless the caller holds edit-room-retention-policy in the room (or the submitted value equals the stored one), exactly as retentionMaxAge, retentionExcludePinned, retentionFilesOnly and retentionIgnoreThreads already do at :185-237. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Deny by Default: a field without an explicit rule must not default to the weaker one).

### Side effects of the fix

Keeps per-room retention control for holders of edit-room-retention-policy and removes only the weakness: an owner without that permission can no longer set the override, which is what the UI already implies, so a workspace that silently relied on owners setting it must grant the permission explicitly.

### Detail

see findings


[analysis](findings/VULN-055.md)


### Dynamic validation

- **Status**: CONFIRMED (an ordinary room owner exempted its own room from the workspace retention policy, while the sibling retention field on the same route refused it)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-055-retention_override_without_permission/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-055-retention_override_without_permission/writeup.md](exploits/VULN-055-retention_override_without_permission/writeup.md)

## VULN-058: Mass assignment in teams.create: the caller's room.extraData is spread into the new room, setting default, featured and other administrative flags

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an ordinary account created a room flagged default and featured for the whole workspace, which a new account then joined automatically) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N |
| **CWE** | CWE-915 |
| **Category** | Mass assignment |
| **Location** | `targets/rocket.chat/packages/rest-typings/src/v1/teams/TeamsCreateProps.ts:23` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-58: parent HackerOne #1132202 (createRoom extraData override) was fixed by closing extraData on channels.create and groups.create only; PR #42053 notes the team path spreads room.extraData verbatim. Adjacent CVE-2026-72919 (channels.convertToTeam). |
| **Conditional** | no |
| **Finding key** | `18a071c10c1c4934` |

### Impact

Medium (CVSS 4.3): the teams.create body declares room as an open object, the team service strips only abacAttributes and options, and createRoom spreads the rest of extraData into the stored room document. So any user who may create a team (the default user role) sets room fields that belong to room administration: default: true makes every newly registered account a member of that room without an invitation, featured: true places it in the directory's featured list, and the retention and system-message fields are equally reachable. The sibling create routes close the same object with a comment naming exactly these fields, so the intended rule exists and this path misses it. The practical result is a private room, named to look official, that every newcomer silently joins and that the attacker runs.

### Remediation

Close the schema the way ChannelsCreateProps does: give room in TeamsCreateProps.ts:23-25 explicit properties (readOnly and an extraData limited to topic, broadcast and encrypted) with additionalProperties: false, or have Team.create pass only those keys through to Room.create rather than spreading roomProps and roomExtraData. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Mass_Assignment_Cheat_Sheet.md (bind an explicit, minimal set of fields) with deploy/knowledge/payloads/PayloadsAllTheThings/Mass Assignment/README.md for the probe shapes.

### Side effects of the fix

Keeps team creation and removes only the weakness: an API client that set other room fields at creation receives a 400 and must use rooms.saveRoomSettings afterwards, where the per-field permission checks apply; the web client's own create flow sends only the permitted fields.

### Detail

see findings


[analysis](findings/VULN-058.md)


### Dynamic validation

- **Status**: CONFIRMED (an ordinary account created a room flagged default and featured for the whole workspace, which a new account then joined automatically)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-058-team_room_mass_assignment/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-058-team_room_mass_assignment/writeup.md](exploits/VULN-058-team_room_mass_assignment/writeup.md)

## VULN-059: chat.syncThreadsList returns the hidden full copy of a deleted thread root, so members read deleted content on a default install

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a member read the full text of a deleted message through the thread catch-up route, which its non-sync sibling withholds) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-212 |
| **Category** | Deleted data exposure (missing response filtering) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/chat.ts:1212` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-59: open vendor PR #43343 'thread sync returns the content of deleted messages' covers only the trash-based remove list (unfixed here); this finding's hidden history copy in the update list is a different path. Also CVE-2026-65645 (DDP getThreadsList injection, fixed 8.8.0). |
| **Conditional** | no |
| **Finding key** | `42a41cccefe317a5` |

### Impact

Medium (CVSS 4.3): deleting a message that started a thread always keeps a copy, whatever the workspace's history setting says, because deleteMessage computes keepHistory as the setting OR "this is a thread root"; the clone carries every field of the original, its text and its files, marked _hidden with a fresh _updatedAt. chat.syncThreadsList then selects thread roots by rid and tcount with only an _updatedAt bound and returns the raw documents, with no _hidden filter and no per-user normalisation, while its paginated twin chat.getThreadsList does filter them. So in the shipped configuration any member can ask for threads updated since a time before a deletion and read the deleted message's original text, its attachment references, and the other members' star lists that normalisation would have removed.

### Remediation

Add _hidden: { $ne: true } to the update queries of chat.syncThreadsList (chat.ts:1212-1221) and chat.syncThreadMessages, as chat.getThreadsList already does at chat.ts:1140-1141, and pass the results through normalizeMessagesForUser so private per-user fields are filtered as on every other message route. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/User_Privacy_Protection_Cheat_Sheet.md.

### Side effects of the fix

Keeps thread synchronisation and removes only the weakness: clients stop receiving hidden history documents (no first-party client renders them) and stop receiving other members' star arrays, so a client that displayed a deleted thread root from its cache will show the "message removed" stub instead.

### Detail

see findings


[analysis](findings/VULN-059.md)


### Dynamic validation

- **Status**: CONFIRMED (a member read the full text of a deleted message through the thread catch-up route, which its non-sync sibling withholds)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-059-deleted_thread_root_disclosure/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-059-deleted_thread_root_disclosure/writeup.md](exploits/VULN-059-deleted_thread_root_disclosure/writeup.md)
- **Detection**: [`detections/VULN-059.sigma.yml`](detections/VULN-059.sigma.yml) (medium, validated: fired on 1/1 of this exploit's own log lines, silent on 400 clean ones). It sees every chat.syncThreadsList call with the room and the cursor (no first-party client calls this route); not the deleted roots in the response.

## VULN-076: Livechat stream access is decided against the room the client names in extraData, so a visitor with one open chat of its own reads any other Livechat room's live messages

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an unauthenticated visitor subscribed to another customer's Livechat room by naming its own room in extraData and received that customer's messages) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven unauthenticated: naming our own room in extraData opened another customer's live conversation. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **CWE** | CWE-639, CWE-863 |
| **Category** | Broken access control (authorization decided on a client-chosen object) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/omnichannel/roomAccessValidator.compatibility.ts:31` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 08 R-01: regression of CVE-2026-48616 (Livechat file access decided on a client-supplied room); the stream path keeps the same pattern; no tracker or advisory names the room-messages stream. |
| **Regression of** | CVE-2026-48616 |
| **Conditional** | yes: Livechat_enabled (Omnichannel on), with the attacker able to open one chat of its own |
| **Finding key** | `3fe2cc2b33366fb8` |

### Impact

Medium (CVSS 5.9): the stream-room-messages read rule passes the subscriber's own subscription arguments to canReadRoom as extraData, and for a Livechat room the third compatibility validator reloads LivechatRooms.findOneById(extraData.rid) and overwrites the room under test with it before comparing the visitor token. So an anonymous visitor who opens one chat of their own, and who knows a target room's id, subscribes to that target room and is authorized against their own: the server then pushes the other customer's conversation to them live. The same client-supplied-room pattern was the subject of CVE-2026-48616 on the file-access path; on the realtime path it is still there.

### Remediation

Compare the visitor token against the room actually being accessed. In roomAccessValidator.compatibility.ts:30-39, drop the extraData.rid reload and return extraData?.visitorToken && room.v?.token === extraData.visitorToken && room.open === true, refusing outright when extraData.rid is present and differs from room._id; give the upload path that genuinely has no room object its own validator that resolves the room from the upload record instead of from the client. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md (Mitigation: authorize the object being accessed) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request).

### Side effects of the fix

Keeps visitor streams for the visitor's own rooms and removes only the weakness: a subscription that names a different room in extraData.rid than the one it subscribes to is refused, which no first-party widget does.

### Detail

see findings


[analysis](findings/VULN-076.md)


### Dynamic validation

- **Status**: CONFIRMED (an unauthenticated visitor subscribed to another customer's Livechat room by naming its own room in extraData and received that customer's messages)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-076-livechat_stream_room_confusion/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-076-livechat_stream_room_confusion/writeup.md](exploits/VULN-076-livechat_stream_room_confusion/writeup.md)

## VULN-077: livechat/visitors.pagesVisited returns navigation messages whole, handing any agent the visitor tokens the GHSA-cqj7 fix stopped visitors.info from disclosing

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a non-admin agent read the customer's visitor token out of visitors.pagesVisited, which visitors.info withholds for the same caller, and used it to read the conversation and post as the customer) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Proven: the token visitors.info withholds came out of the sibling route and then read and wrote the conversation. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N |
| **CWE** | CWE-200, CWE-862 |
| **Category** | Credential disclosure (missing projection and room authorization) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/omnichannel/lib/visitors.ts:30` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 08 R-02: regression of GHSA-cqj7-h8cj-jmf2 / CVE-2026-49278 (visitors.info returned the visitor token; fixed 8.5.0, 8.4.2 and backports by projecting token: 0); vendor-tracker search 'pagesVisited token' returned only test PRs #42534 and #39419. https://github.com/RocketChat/Rocket.Chat/security/advisories/GHSA-cqj7-h8cj-jmf2 |
| **Regression of** | CVE-2026-49278 |
| **Conditional** | yes: Livechat_enabled (Omnichannel on) |
| **Finding key** | `fb19b6f9cf637b78` |

### Impact

Medium (CVSS 5.4): the route is gated on view-l-room alone, and findVisitedPages loads any Livechat room by the id in the URL, performs no room-access check, and returns its livechat_navigation_history messages with no projection. Each of those messages was written by the widget with the visitor's own token inside navigation.token, so the response hands the caller the credential that authenticates that customer. With it, an agent of one department reads another department's conversation through livechat/messages.history and posts into it as the customer through livechat/message. That is the impersonation GHSA-cqj7-h8cj-jmf2 was issued for, through a second endpoint the fix did not touch.

### Remediation

Authorize the room and withhold the token in findVisitedPages (lib/visitors.ts:26-36): call canAccessRoomAsync for the requesting user as the sibling findChatHistory does at :61, and pass projection: { 'navigation.token': 0 } to findPaginatedByRoomIdAndType; better still, stop writing the token into the navigation message at tracking.ts:35-38, since the room already records the visitor. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request) with deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Session_Management_Cheat_Sheet.md (a session identifier is never disclosed to a third party).

### Side effects of the fix

Keeps the navigation-history panel and removes only the weakness: agents see page history for the rooms they can access rather than for every room, and the token no longer appears in the response, which the first-party agent UI never reads.

### Detail

see findings


[analysis](findings/VULN-077.md)


### Dynamic validation

- **Status**: CONFIRMED (a non-admin agent read the customer's visitor token out of visitors.pagesVisited, which visitors.info withholds for the same caller, and used it to read the conversation and post as the customer)
- **Confidence**: 8/10
- Exploit directory: `exploits/VULN-077-visitor_tokens_in_pages_visited/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-077-visitor_tokens_in_pages_visited/writeup.md](exploits/VULN-077-visitor_tokens_in_pages_visited/writeup.md)
- **Detection**: [`detections/VULN-077.sigma.yml`](detections/VULN-077.sigma.yml) (medium, validated: fired on 1/1 of this exploit's own log lines, silent on 400 clean ones). It sees each read of livechat/visitors.pagesVisited and the conversation it was for; not whether the disclosed visitor tokens were then used.

## VULN-004: users.info returns the caller's raw services document, disclosing the TOTP seed and backup-code hashes to any holder of the session

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a session read its own account's TOTP seed and backup-code hashes from users.info, and a code derived from that seed passed the second factor) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| **CWE** | CWE-522, CWE-200 |
| **Category** | Sensitive data exposure (second-factor secret disclosed to the session) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/users/getFullUserData.ts:157` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-04: searched for users.info TOTP secret exposure; adjacent only HackerOne #842625 (users.info leaked the reset hash, fixed by PR #17238), CVE-2021-22911 and CVE-2022-32211 (2FA secret through injection, fixed). PR #35549 narrowed services on /me only (stage 08 R-26). |
| **Conditional** | no |
| **Finding key** | `68911c76abbc9ced` |

### Impact

Medium (CVSS 6.8): a one-off credential theft becomes durable control of the account. The self view of users.info returns services.totp.secret (the base32 TOTP seed) and services.totp.hashedBackup, so whoever holds the victim's token once can generate valid second-factor codes forever: after the stolen session is revoked they still pass every twoFactorRequired step-up (minting a 2FA-bypassing personal access token, changing the account email, disabling 2FA, deleting the account) and, with the password, future logins. OAuth provider tokens stored under services.<provider> are disclosed the same way.

### Remediation

Build the self view of services in getFullUserData.ts:152-177 from the allow-list getUserInfo.ts:120-131 already uses for /me (totp.enabled, email2fa.enabled, password.exists, linked provider names) instead of projecting services:1 and deleting four keys, and never return services.totp.secret, services.totp.hashedBackup, emailCode, provider access tokens or cloud tokens from any endpoint once enrolment is finished. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md (the TOTP seed is shown once at enrolment and never served again) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Secrets_Management_Cheat_Sheet.md.

### Side effects of the fix

Keeps the endpoint and removes only the weakness: an API client that read raw services from users.info for its own account now gets booleans (the web client already reads /me, which is already filtered), and nothing can retrieve a seed after enrolment, so a client that re-displayed the QR code from users.info must re-enrol the user instead.

### Detail

see findings


[analysis](findings/VULN-004.md)


### Dynamic validation

- **Status**: CONFIRMED (a session read its own account's TOTP seed and backup-code hashes from users.info, and a code derived from that seed passed the second factor)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-004-totp_seed_disclosed_to_session/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-004-totp_seed_disclosed_to_session/writeup.md](exploits/VULN-004-totp_seed_disclosed_to_session/writeup.md)

## VULN-011: Typing indicators accept a room the caller cannot access, because the user-activity write rule only checks the claimed name

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an account refused both the history and the stream of a private group wrote activity events into it that the room's members received) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N |
| **CWE** | CWE-862 |
| **Category** | Missing authorization on a realtime write |
| **Location** | `targets/rocket.chat/packages/streamer/src/notifications.module.ts:273` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-11: searched typing indicator writes into inaccessible rooms; adjacent only GHSA-27jx-236m-3f5j and GHSA-r3v3-v742-55j5 (other stream writes), PR #41910 (federated typing). |
| **Conditional** | no |
| **Finding key** | `308e196c61445dc3` |

### Impact

Medium (CVSS 4.3): any account can write presence events into any room by id, including private groups and direct messages it cannot open. Members of that room see a non-member "is typing", which is a falsified presence state and a usable social-engineering prop (a name appearing in a confidential room suggests they are in it); the accepted write also raises the server-side room.user-activity event, which the premium federation layer forwards to remote servers, and acceptance versus refusal is an existence oracle for room ids. No message content is read or written.

### Remediation

In canType (notifications.module.ts:228-271), or in the write rule that calls it at :273-285, require that the caller may access the room: load the room and refuse unless Authorization.canAccessRoom(room, user) passes, caching the answer per connection and room so a typing indicator still costs nothing per keystroke. The read side of the same stream already does exactly this at :199-226. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/WebSocket_Security_Cheat_Sheet.md (authorize each message, not just the connection).

### Side effects of the fix

Keeps typing indicators for room members and for Livechat visitors (the token branch is unchanged) and removes only the weakness: a write naming a room the caller cannot access is dropped, so a client that optimistically announced typing before its subscription landed may lose that first event.

### Detail

see findings


[analysis](findings/VULN-011.md)


### Dynamic validation

- **Status**: CONFIRMED (an account refused both the history and the stream of a private group wrote activity events into it that the room's members received)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-011-typing_write_into_inaccessible_room/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-011-typing_write_into_inaccessible_room/writeup.md](exploits/VULN-011-typing_write_into_inaccessible_room/writeup.md)

## VULN-019: Improper authentication on /hooks: any integration id and token authenticate, and the add and remove sub-routes skip the enabled and impersonation checks

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a webhook credential the administrator had revoked was refused by the posting route but still authenticated on /hooks/add, where it created an enabled outgoing integration that forwarded the channel to our listener) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven: a revoked webhook credential still created an enabled outgoing integration that exfiltrated the channel. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N |
| **CWE** | CWE-287, CWE-863 |
| **Category** | Authentication (credential accepted outside its purpose) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/webhooks.ts:402` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-19: searched incoming webhook outgoing token add remove disabled; adjacent only issue #4773 (logging disabled incoming webhooks). |
| **Conditional** | yes: integrations exist, and the integration's post-as user holds manage-outgoing-integrations or manage-own-outgoing-integrations |
| **Finding key** | `c5ded0fbf3dcbd0f` |

### Impact

Medium (CVSS 6.5): a webhook credential is accepted outside the purpose it was issued for. The lookup behind every /hooks route matches an integration by id and token with no type or enabled condition, so a disabled incoming webhook's URL still authenticates (the administrator's revocation only stops the posting route) and an outgoing integration's token, which the server sends to its own receiver in every payload, authenticates too. The add and remove sub-routes then run with the integration's user and skip the enabled and message-impersonate checks the posting route applies, so the holder of such a URL creates an outgoing integration pointed at their own listener and receives the watched rooms' messages continuously, or deletes existing integrations.

### Remediation

Filter the credential lookup to the purpose: in the /hooks authenticatedRoute (webhooks.ts:400-416) require { type: 'webhook-incoming', enabled: true }, and apply the posting route's guards (the enabled test and the message-impersonate check at webhooks.ts:227-238) inside the add, remove and info handlers as well, so no sub-route is weaker than the primary one. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Webhook_Security_Cheat_Sheet.md (scope a webhook secret to one direction and one purpose) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request).

### Side effects of the fix

Keeps incoming and outgoing webhooks working and removes only the weakness: a disabled webhook stops authenticating on every sub-route (which is what disabling already implies), an outgoing integration's token stops being accepted on /hooks (no first-party client sends it there), and add and remove now require the integration user's permissions.

### Detail

see findings


[analysis](findings/VULN-019.md)


### Dynamic validation

- **Status**: CONFIRMED (a webhook credential the administrator had revoked was refused by the posting route but still authenticated on /hooks/add, where it created an enabled outgoing integration that forwarded the channel to our listener)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-019-hooks_integration_token_confusion/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-019-hooks_integration_token_confusion/writeup.md](exploits/VULN-019-hooks_integration_token_confusion/writeup.md)
- **Detection**: [`detections/VULN-019.sigma.yml`](detections/VULN-019.sigma.yml) (medium, validated: fired on 3/3 of this exploit's own log lines, silent on 400 clean ones). It sees any use of /hooks/add/ or /hooks/remove/, and stays silent on an ordinary incoming webhook post; not the target_url it installs.

## VULN-020: Authorization oracle in roles.addUserToRole: the already-in-role answer precedes the permission check, revealing any user's roles in any room

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an unprivileged account read out global and room-scoped role membership, including the owner of a private group it cannot see, from the error code alone) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-203 |
| **Category** | Information disclosure (authorization oracle) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/roles.ts:142` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-20: searched roles.addUserToRole already-in-role disclosure; adjacent only PR #22407 (added the check), PR #42947 (team role checks). |
| **Conditional** | no |
| **Finding key** | `3028edfc93fbec4a` |

### Impact

Medium (CVSS 4.3): any account can ask, one question at a time, whether a named user holds a named role, globally or scoped to a room id, and read the answer from which error comes back. error-user-already-in-role means yes, error-action-not-allowed means no. That enumerates the global administrators and, with room ids, the owners and moderators of rooms the caller cannot see, which is the targeting information the role-demotion, account-takeover and phishing findings in this report need. Nothing is written: a caller without access-permissions never reaches the mutation.

### Remediation

Declare permissionsRequired: ['access-permissions'] on the roles.addUserToRole route (roles.ts:113-128) so the framework refuses before the handler runs, instead of relying on the check inside addUserToRole (addUserToRole.ts:10-15) which is reached only after hasRoleAsync has answered. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Deny by Default, and Verify that Authorization Checks are Performed in the Right Location: before any side effect or observable branch).

### Side effects of the fix

Keeps role assignment working for callers who hold access-permissions and removes only the weakness: an unauthorized caller receives 403 immediately instead of an error that distinguishes the two cases, so a client that relied on error-user-already-in-role to pre-check membership must use the roles listing instead.

### Detail

see findings


[analysis](findings/VULN-020.md)


### Dynamic validation

- **Status**: CONFIRMED (an unprivileged account read out global and room-scoped role membership, including the owner of a private group it cannot see, from the error code alone)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-020-role_membership_authorization_oracle/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-020-role_membership_authorization_oracle/writeup.md](exploits/VULN-020-role_membership_authorization_oracle/writeup.md)
- **Detection**: [`detections/VULN-020.sigma.yml`](detections/VULN-020.sigma.yml) (medium, validated: fired on 4/4 of this exploit's own log lines, silent on 400 clean ones). It sees every refused roles.addUserToRole call, which is the oracle's own answer, and stays silent on an administrator's successful grants.

## VULN-033: Password change, reset and remove-other-tokens leave open realtime sessions alive, and an admin-set password is broadcast in clear to them

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a stolen token's realtime session survived both a password change and removeOtherTokens, kept reading the victim's private messages, and received the administrator's new password in clear, which then logged in) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N |
| **CWE** | CWE-1466, CWE-201 |
| **Category** | Session management (revocation not applied to the realtime channel; credential in a broadcast) |
| **Location** | `targets/rocket.chat/apps/meteor/server/services/meteor/userReactivity.ts:75` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-33: searched password change does not log out other websocket sessions; adjacent only CVE-2023-28316 / HackerOne #992280 (sessions surviving 2FA activation, fixed, and enabling 2FA now broadcasts) and PR #41573. |
| **Regression of** | CVE-2023-28316 |
| **Conditional** | no |
| **Finding key** | `d1acb6f8759ed1d7` |

### Impact

Medium (CVSS 6.5): the remediation a user or administrator performs after a session is stolen does not close the attacker's socket. A DDP connection is disconnected only when a broadcast user diff carries services.resume.loginTokens, and the paths that remove tokens mostly do not broadcast that field: users.removeOtherTokens broadcasts nothing, the profile password change notifies a reduced diff, and Meteor's resetPassword has no hook at all, so the attacker's connection keeps delivering the victim's new messages, mentions and direct-message notifications while REST with the old token is already refused. Worse, when an administrator resets the password through users.update, saveUser broadcasts the data it was given to the user's own channel with the new plaintext password still in it, so the attacker's socket receives the credential the administrator just chose.

### Remediation

Make every token-removing path announce itself: have the model methods that clear tokens (removeNonLoginTokensExcept, removeNonPATLoginTokensExcept, unsetLoginTokens and the updater in setPasswordUpdater) broadcast the resulting token list (or an explicit forced-logout event for the removed hashes), hook Meteor's reset the same way, and delete password from the diff before notifyOnUserChange in saveUser.ts:365-374. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Session_Management_Cheat_Sheet.md (invalidate every session on a credential change; manual session expiration must reach all channels) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Secrets_Management_Cheat_Sheet.md for the broadcast credential.

### Side effects of the fix

Keeps realtime delivery and removes only the weakness: a user's other sessions are disconnected when the password changes, when it is reset and when they use remove-other-sessions, which is what the UI already promises; the session performing the change is unaffected, and clients that re-read the user after an admin update now fetch the password-free document (no client displays it).

### Detail

see findings


[analysis](findings/VULN-033.md)


### Dynamic validation

- **Status**: CONFIRMED (a stolen token's realtime session survived both a password change and removeOtherTokens, kept reading the victim's private messages, and received the administrator's new password in clear, which then logged in)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-033-realtime_session_survives_revocation/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-033-realtime_session_survives_revocation/writeup.md](exploits/VULN-033-realtime_session_survives_revocation/writeup.md)

## VULN-036: Mandatory 2FA for a role is enforced only by the web client, so its members keep single-factor access over REST and DDP

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a member of a role with mandatory two-factor authentication logged in with the password alone over REST and used the role's full access; the policy is read only by the web client) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven on both channels: the policy an administrator switched on is not read by the server at all. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| **CWE** | CWE-602, CWE-308 |
| **Category** | Security policy enforced client-side only (mandatory MFA) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/2fa/code/index.ts:230` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-36: searched mandatory2fa role bypass REST API; adjacent only PR #9748 (the feature), issues #17755, #20475, #24101 (UI enforcement bugs) and the GitLab analogue (GitLab issue 32215). |
| **Conditional** | yes: an administrator enabled mandatory 2FA on a role (a security control that is switched on but not enforced server-side) |
| **Finding key** | `ca44c3de6c27c30c` |

### Impact

Medium (CVSS 6.8): "Users must use Two Factor Authentication" on a role is a security control an administrator switches on, typically for admin, and it is implemented as a client-side redirect. The only reader of the role's mandatory2fa flag is a React hook that swaps the page for the security settings; on the server, the second-factor check returns true for a user with no enrolled method, whatever their roles say, so a member of that role who never enrolled logs in over REST or DDP and has the role's full access with the password alone. The control's whole purpose is that a stolen password should not be enough for a privileged role, and for every non-web client it is not enforced at all.

### Remediation

Enforce the flag where sessions are made: in the 2FA onValidateLogin callback (2fa/loginHandler.ts:31-36) and in issueLoginToken, refuse a full session when any of the user's roles carries mandatory2fa and getSecondFactorMethod finds no enrolled method, returning a distinguishable error (totp-setup-required) or a token scoped to the enrolment routes only; keep the client redirect as the user-facing path. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md (when MFA is required it is required on every channel) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Verify that Authorization Checks are Performed in the Right Location).

### Side effects of the fix

Keeps the feature and removes only the weakness: a member of a mandatory-2FA role who has not enrolled can no longer use API clients or the mobile apps until they do (which is the policy's intent), and an integration running as such an account needs a token minted after enrolment, so administrators should enrol service accounts or exclude them from the role before enabling it.

### Detail

see findings


[analysis](findings/VULN-036.md)


### Dynamic validation

- **Status**: CONFIRMED (a member of a role with mandatory two-factor authentication logged in with the password alone over REST and used the role's full access; the policy is read only by the web client)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-036-role_mandatory_2fa_client_side/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-036-role_mandatory_2fa_client_side/writeup.md](exploits/VULN-036-role_mandatory_2fa_client_side/writeup.md)

## VULN-037: Pre-registration squatting survives the owner's OAuth claim: the email meld resets the password but keeps the squatter's sessions and personal access tokens

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (after the account's real owner claimed it through their identity provider, the earlier squatter's personal access token still read the account, its subscriptions and its direct messages) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven: after the owner's provider claim the squatter's token still read the account, its subscriptions and its direct messages. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N |
| **CWE** | CWE-283, CWE-1464 |
| **Category** | Pre-account takeover (account claim does not purge prior access) |
| **Location** | `targets/rocket.chat/packages/models/src/models/Users.ts:3147` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-37: searched pre-account takeover email meld keeps sessions personal access tokens; adjacent only open PRs #43880 and #43888 (meld password handling) and PR #43840; none mentions sessions or PATs. |
| **Conditional** | yes: an OAuth login provider enabled, with the victim signing in through it after the attacker registered their address |
| **Finding key** | `abcc13b418d1c925` |

### Impact

Medium (CVSS 6.8): an attacker registers a future colleague's email address while registration is public (the default), signs in, and mints a personal access token. When the real owner later signs in through an OAuth provider, the email meld links the identity to that existing account and marks the address verified, and the only thing it clears is the password: resetPasswordAndSetRequirePasswordChange unsets services.password and nothing else, so services.resume.loginTokens, where both login tokens and personal access tokens live, survives intact. The attacker keeps reading everything the account receives (direct messages, mentions, the private rooms it joins) and can post as it, from the day the real person starts using the workspace, and the owner's own forced password change does not revoke those tokens because the revocation path requires a bcrypt hash the meld has just removed.

### Remediation

When the meld links an identity to an account whose address that identity did not verify, purge every credential the previous holder created, not only the password: unset services.resume.loginTokens (login tokens and PATs), the other linked services and any OAuth tokens, alongside the existing services.password unset in accounts_meld.js:22-31; better, stop linking by email without an authenticated session at all (the fix for the OAuth-meld finding), and force a reset when an address is first verified on an account whose password predates that verification. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authentication_Cheat_Sheet.md (account linking requires proof of control of both sides) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.md.

### Side effects of the fix

Keeps social login and removes only the weakness: anyone who pre-created an account and later signs in through the provider loses their earlier sessions and personal access tokens and must create new ones, and silent first-login merging stops for unverified addresses.

### Detail

see findings


[analysis](findings/VULN-037.md)


### Dynamic validation

- **Status**: CONFIRMED (after the account's real owner claimed it through their identity provider, the earlier squatter's personal access token still read the account, its subscriptions and its direct messages)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-037-pre_registration_squatting_survives_meld/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-037-pre_registration_squatting_survives_meld/writeup.md](exploits/VULN-037-pre_registration_squatting_survives_meld/writeup.md)

## VULN-041: Star privacy is enforced only in the REST serializer, so the message query and the realtime broadcast disclose who starred what

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (one member read another member's private stars: the query filter returned exactly the starred message, and the realtime broadcast carried the raw starred array) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-359 |
| **Category** | Privacy setting bypassed through alternate channels |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/channels.ts:517` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-41: searched starred messages visible to other users starredIds stream privacy; adjacent only HackerOne #1060837 (writing stars on arbitrary messages), issue #20099, CVE-2026-106075 (fixed 9.0.0). |
| **Conditional** | no |
| **Finding key** | `f9faf03e154787b6` |

### Impact

Medium (CVSS 4.3): Rocket.Chat presents stars as private ("only you have access to your stars") and enforces that in one place, the REST serializer, which trims each message's starred array to the caller's own entry. Two other paths ignore it. The room message routes (channels.messages, groups.messages, im.messages) build their Mongo filter from a client-supplied starredIds list and select on starred._id before the serializer runs, so a caller can ask "which messages in this room did this colleague star" and read the answer from the result set. And the realtime copy prepared for stream-room-messages drops hidden messages and private author fields but keeps starred in full, so every subscriber of a room sees the complete star list each time a message changes. Bookmark activity (interest in a job posting, an HR notice, a particular incident) is personal information the product promised not to share.

### Remediation

Apply the rule where the data is selected and where it is emitted, not only where it is serialized: accept starredIds only when it names the caller (or drop the parameter in favour of chat.getStarredMessages) in channels.ts:517, groups.ts:1210 and im.ts:659, and either remove starred from the payload getMessageToBroadcast returns (notifyListener.ts:443-470) or apply the per-subscriber filterStarred at emit time. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request, including on queries and on realtime pushes) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/User_Privacy_Protection_Cheat_Sheet.md.

### Side effects of the fix

Keeps stars and removes only the weakness: filtering a room's messages by another user's stars stops working (no first-party client does it, and the caller's own stars remain filterable), and clients learn their own star state from the REST response rather than from the shared array in a broadcast.

### Detail

see findings


[analysis](findings/VULN-041.md)


### Dynamic validation

- **Status**: CONFIRMED (one member read another member's private stars: the query filter returned exactly the starred message, and the realtime broadcast carried the raw starred array)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-041-star_privacy_bypass/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-041-star_privacy_bypass/writeup.md](exploits/VULN-041-star_privacy_bypass/writeup.md)
- **Detection**: [`detections/VULN-041.sigma.yml`](detections/VULN-041.sigma.yml) (medium, validated: fired on 1/1 of this exploit's own log lines, silent on 400 clean ones). It sees the channels.messages query filtered on starredIds, with the room and the user id it asks about; not the realtime leg of the same finding.

## VULN-049: With message edit history on, deleted and edited-away content stays readable: personal exports include the hidden copies and their files, and chat.getMessage returns them by id

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a member read an edited-away secret and a deleted message's text through chat.getMessage, which the room's own history withholds) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-212 |
| **Category** | Sensitive data exposure (soft-deleted content served to members) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/dataExport/exportRoomMessagesToFile.ts:217` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-49: searched Message_KeepHistory deleted messages included in data export getMessage hidden; adjacent only PR #43364 and CVE-2023-28318 / HackerOne #1379451. |
| **Conditional** | yes: Message_KeepHistory (keep per-message editing history) enabled |
| **Finding key** | `0d3f2e773434d80c` |

### Impact

Medium (CVSS 4.3): when Message_KeepHistory is enabled, deleting a message does not delete it. The delete path either clones the message as a hidden document or marks the original _hidden, and marks its uploads _hidden rather than removing them; editing likewise stores the previous version as a hidden document in the same room. The lists, sync and search routes do filter hidden messages, so the content disappears from the client, which is what makes the gap convincing: the personal data export queries the room by id with an empty filter and writes every document and every file it finds, and chat.getMessage loads a message by id with no hidden condition and returns it to any member of the room. So a member (including one who joined after the deletion) extracts credentials pasted by mistake, personal data and moderated content that the client told the author could not be recovered.

### Remediation

Honour the soft-delete marker on the paths that bypass it: add _hidden: { $ne: true } (and exclude the parent history copies) to the export query in exportRoomMessagesToFile.ts:217-219, which is called with an empty filter from processDataDownloads.ts:186-194, and to the lookup in getSingleMessage.ts:8; refuse hidden uploads on the file route unless the caller holds an administrative permission; and if edit history is meant for audit, expose it behind view-room-administration rather than to every member. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Deny by Default; Validate the Permissions on Every Request) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/User_Privacy_Protection_Cheat_Sheet.md.

### Side effects of the fix

Keeps edit history for administrators and compliance tooling and removes only the weakness: members' exports, chat.getMessage and direct file links stop returning deleted messages, earlier versions and deleted files, which the client already hides, so a user who relied on the export as an archive of their own deleted drafts loses that.

### Detail

see findings


[analysis](findings/VULN-049.md)


### Dynamic validation

- **Status**: CONFIRMED (a member read an edited-away secret and a deleted message's text through chat.getMessage, which the room's own history withholds)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-049-deleted_content_via_edit_history/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-049-deleted_content_via_edit_history/writeup.md](exploits/VULN-049-deleted_content_via_edit_history/writeup.md)

## VULN-060: Meteor's resetPassword and changePassword set any password: the policy is enforced in the browser and on one REST path only

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (a one-character password was accepted through the method bridge and then logged in, on a workspace whose policy demands fourteen characters, and the change switch is not read there either) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven: a one-character password was accepted and then logged in on a workspace that requires fourteen. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N |
| **CWE** | CWE-602, CWE-521 |
| **Category** | Client-side enforcement (alternate channel missing checks) |
| **Location** | `targets/rocket.chat/apps/meteor/server/meteor-methods/users/saveUserProfile.ts:75` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | known-unpatched |
| **Known evidence** | Issue #9434 '[BUG] Disabled password change bypass via forgot password' (opened 2018-01-17 by a Rocket.Chat member, still open) is the Accounts_AllowPasswordChange leg; this build still sets passwords through Meteor's methods without Rocket.Chat's checks. The policy leg has no public report; open PR #43199 fixes the sibling gap on users.create only. https://github.com/RocketChat/Rocket.Chat/issues/9434 |
| **Known confidence** | 6/10 |
| **Conditional** | no |
| **Finding key** | `fe60aa2a860207e9` |

### Impact

Medium (CVSS 4.3): Rocket.Chat's password rules (minimum length and composition, the no-reuse history, the Accounts_AllowPasswordChange switch and the second-factor step-up) live in its own REST path, saveUserProfile, and in the browser. Meteor's original accounts-password methods are still registered and still set passwords, and both are reachable from outside the browser through the method bridges (method.call for changePassword, method.callAnon for resetPassword) as well as over DDP. The reset page itself calls the Meteor method directly after validating in the client, so a caller who skips the page sets a one-character password on any account whose reset token they hold, and a signed-in user changes their own password to anything, including when an administrator has switched password changes off entirely.

### Remediation

Put the rules behind the method, not beside it: replace Meteor's changePassword handler with one that applies Accounts_AllowPasswordChange, the history check, passwordPolicy.validate and the second-factor step-up (or remove it, since no shipped client calls it), and validate the policy and history before Meteor's resetPassword completes, or have the reset page post to a REST route that already does (saveUserProfile.ts:61-76 is the reference implementation). Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authentication_Cheat_Sheet.md (implement password strength controls on the server, for every path) and deploy/knowledge/owasp/wstg/document/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy.md.

### Side effects of the fix

Keeps password reset and change and removes only the weakness: a weak password is refused by the server as the browser already refuses it, a user whose administrator disabled password changes can no longer change one through a method, and a third-party DDP client that called changePassword either gains the REST rules or must switch to the REST route.

### Detail

see findings


[analysis](findings/VULN-060.md)


### Dynamic validation

- **Status**: CONFIRMED (a one-character password was accepted through the method bridge and then logged in, on a workspace whose policy demands fourteen characters, and the change switch is not read there either)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-060-password_policy_bypass_via_ddp/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-060-password_policy_bypass_via_ddp/writeup.md](exploits/VULN-060-password_policy_bypass_via_ddp/writeup.md)
- **Detection**: [`detections/VULN-060.sigma.yml`](detections/VULN-060.sigma.yml) (medium, validated: fired on 2/2 of this exploit's own log lines, silent on 400 clean ones). It sees a password set through method.call/changePassword, which the shipped client never uses; the resetPassword leg shares the reset page's own route and is deliberately not matched.

## VULN-062: Revoking preview-c-room only closes the history and the live stream: ten other message, file and thread routes still serve non-members

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (with preview-c-room revoked, 4 other route(s) (channels.messages, chat.syncMessages, chat.getMessage, chat.search) still served the channel's messages to a non-member while channels.history and the stream refused it) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-863 |
| **Category** | Authorization missing on alternate API routes |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/channels.ts:522` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-62: searched preview-c-room removed channels.messages still readable non-member; adjacent only PRs #34922 and #35194 (the stream side). |
| **Conditional** | yes: an administrator removed preview-c-room from a role (a hardening control switched on but enforced on two read paths only) |
| **Finding key** | `0a4ab06bfbf8c7f0` |

### Impact

Medium (CVSS 4.3): preview-c-room is the permission an administrator removes to stop people reading public channels they have not joined. The rule lives in canReadRoom, which adds the preview test on top of canAccessRoom, and only two paths use it: the channel-history method and the room-message stream. Every other read of the same content calls canAccessRoom, which admits any view-c-room holder to a public channel, so after the revocation a non-member still reads the channel through channels.messages, chat.syncMessages, chat.getMessage, chat.search, the thread routes, pins, discussions, files and images. The administrator sees the timeline close in the web client and has no indication that the API never closed.

### Remediation

Make the preview rule the shared predicate rather than a special case: replace canAccessRoomAsync with canReadRoom (or introduce canReadRoomMessages and use it) in each message, file and thread read that currently calls canAccessRoom, starting with channels.messages (channels.ts:522), channels.files (channels.ts:1181), getSingleMessage.ts:14 and the chat.ts sync, search and thread routes. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request, through one shared decision point).

### Side effects of the fix

Keeps public channels exactly as they behave by default (preview-c-room is on the user role, so nothing changes until an administrator revokes it) and removes only the weakness: once revoked, non-members lose these reads as they already lost the history, and holders of the permission see no difference.

### Detail

see findings


[analysis](findings/VULN-062.md)


### Dynamic validation

- **Status**: CONFIRMED (with preview-c-room revoked, 4 other route(s) (channels.messages, chat.syncMessages, chat.getMessage, chat.search) still served the channel's messages to a non-member while channels.history and the stream refused it)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-062-preview_revocation_alternate_routes/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-062-preview_revocation_alternate_routes/writeup.md](exploits/VULN-062-preview_revocation_alternate_routes/writeup.md)

## VULN-066: Disabling password reset closes only the REST route: Meteor's forgotPassword still mails reset links anonymously and outside the REST limiter

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (with self-service password reset switched off, an unauthenticated caller still had the workspace mail a working reset link, through the method bridge and outside the REST limiter) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven: with reset switched off, an anonymous caller still had a working reset link mailed, outside the REST limiter. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N |
| **CWE** | CWE-424, CWE-640 |
| **Category** | Feature switch not enforced on an alternate channel |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/users.ts:1262` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-66: searched forgotPassword method Accounts_PasswordReset disabled; adjacent only GHSA-7c6v-m68v-v73r / CVE-2026-75575 (sendForgotPasswordEmail without a DDP rate limit, fixed 8.8.0), issue #9434, CVE-2020-28208. |
| **Regression of** | CVE-2026-75575 |
| **Conditional** | yes: Accounts_PasswordReset turned off (self-service reset disabled, a switch that is then not fully enforced) |
| **Finding key** | `2a314e28021f8ad4` |

### Impact

Medium (CVSS 4.8): Accounts_PasswordReset is the switch an administrator turns off when passwords are managed elsewhere (an identity team, an SSO-only workspace) so that nobody can mail themselves a reset link. The switch is read in the REST route users.forgotPassword and in the login form, not in the capability: Meteor's own forgotPassword handler looks the account up and mails the token with no Rocket.Chat check, and it is reachable over DDP and through POST /api/v1/method.callAnon/forgotPassword, a route that is anonymous and explicitly opts out of the REST rate limiter. So every account remains resettable by whoever controls its mailbox, and anyone can make the workspace send reset mail to any address at a pace only the DDP limiter bounds, while the administrator believes the feature is off.

### Remediation

Enforce the switch in the capability rather than in one route: wrap Meteor's forgotPassword and resetPassword handlers so they refuse while Accounts_PasswordReset is false, or refuse those method names in method.call, method.callAnon and the DDP dispatcher when the switch is off; the same wrapper is where the policy and second-factor gaps in the sibling finding belong. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Forgot_Password_Cheat_Sheet.md (the recovery flow is one capability, gated in one place) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request).

### Side effects of the fix

Keeps password reset working when it is enabled and removes only the weakness: with the switch off no reset mail can be requested over any channel, which is what the switch states, so a workspace that quietly relied on the Meteor method (no first-party client does) loses it.

### Detail

see findings


[analysis](findings/VULN-066.md)


### Dynamic validation

- **Status**: CONFIRMED (with self-service password reset switched off, an unauthenticated caller still had the workspace mail a working reset link, through the method bridge and outside the REST limiter)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-066-forgot_password_ddp_when_disabled/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-066-forgot_password_ddp_when_disabled/writeup.md](exploits/VULN-066-forgot_password_ddp_when_disabled/writeup.md)
- **Detection**: [`detections/VULN-066.sigma.yml`](detections/VULN-066.sigma.yml) (medium, validated: fired on 9/9 of this exploit's own log lines, silent on 400 clean ones). It sees every anonymous forgotPassword on the DDP bridge, a route the shipped client never uses for resets; not the target address.

## VULN-068: rooms.bannedUsers returns a room's ban list to any member, while the client shows it only to holders of ban-user

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an ordinary member and a non-member both read the room's banned-user list, which the interface shows only to holders of ban-user) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-862 |
| **Category** | Missing authorization on a moderation view |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/rooms.ts:1749` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-68: searched rooms.bannedUsers permission ban-user any member list; adjacent only PR #43138 (9.0 returns 403 for no room access) and PR #41402. |
| **Conditional** | no |
| **Finding key** | `6db81d32795a329d` |

### Impact

Medium (CVSS 4.3): the route's only gate is canAccessRoomIdAsync, so anyone who can open the room receives the banned members' user ids, usernames and display names. The client puts the same data behind a permission: the room-toolbox action that opens the Banned Users panel returns nothing unless usePermission('ban-user', room._id) holds, so in the interface the list is a moderators' view. Moderation decisions are personal and often deliberately quiet (who was removed from an incident room, who was banned after a complaint), and here every member of the room, and for a public channel every user who can see it, can enumerate them.

### Remediation

Check the same permission the client checks, scoped to the room: in rooms.ts:1749 require hasPermissionAsync(this.userId, 'ban-user', roomId) in addition to room access, mirroring useBannedUsersRoomAction.ts:12-17. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Enforce Least Privileges, and Verify that Authorization Checks are Performed in the Right Location: the server, not the toolbox).

### Side effects of the fix

Keeps the list for moderators and administrators and removes only the weakness: ordinary members receive 403 for a panel the interface never offered them, so a third-party client that displayed the ban list to everyone will show an error instead.

### Detail

see findings


[analysis](findings/VULN-068.md)


### Dynamic validation

- **Status**: CONFIRMED (an ordinary member and a non-member both read the room's banned-user list, which the interface shows only to holders of ban-user)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-068-ban_list_disclosure_to_any_member/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-068-ban_list_disclosure_to_any_member/writeup.md](exploits/VULN-068-ban_list_disclosure_to_any_member/writeup.md)

## VULN-079: getRoomByTypeAndName passes an untyped method parameter into a Mongo filter, so any user enumerates private-room names by regular expression through its two distinct error codes

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (ordinary accounts recovered the exact name of a private group they cannot see ('proj-015b') in 327 oracle questions, through a Mongo operator in a method parameter) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-943, CWE-204 |
| **Category** | NoSQL operator injection (existence oracle) |
| **Location** | `targets/rocket.chat/packages/models/src/models/Rooms.ts:1479` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 08 R-09: regression of GHSA-jx87-887q-554q / CVE-2022-32226 (getUsersOfRoom input not type validated, fixed 4.8.2; the fix was applied per method); no advisory names getRoomByTypeAndName (tracker search not completed: GitHub search API limit). https://github.com/advisories/GHSA-jx87-887q-554q |
| **Regression of** | CVE-2022-32226 |
| **Conditional** | no |
| **Finding key** | `4bf6821ca709f9d7` |

### Impact

Medium (CVSS 4.3): the Meteor method validates only that type and name are truthy, and for channel and private-group types there is no per-type roomFind, so the parameter reaches Rooms.findByTypeAndNameOrId and is placed into $or: [{ name: identifier }, { _id: identifier }] unchanged. An EJSON object such as {"$regex":"^acq"} therefore becomes a pattern match over every room of that type, and the method's two failure codes tell the caller which happened: error-no-permission when a room matched that the caller may not open, error-invalid-room when nothing matched. Bisecting one character at a time recovers the names of private groups the caller is not a member of, which in practice are project, deal and incident code names.

### Remediation

Type the parameters and collapse the error codes. At the top of getRoomByTypeAndName (publications/room/index.ts:53-58) add check(type, String) and check(name, String) (or a schema), and return the same error-invalid-room for both no match and no access so the response no longer distinguishes them. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Input_Validation_Cheat_Sheet.md (validate type before use) with the technique in deploy/knowledge/payloads/PayloadsAllTheThings/NoSQL Injection/README.md.

### Side effects of the fix

Keeps the method for its real callers and removes only the weakness: a non-string name is refused rather than treated as a query, and a caller can no longer tell a room they may not see from one that does not exist. A client that relied on telling those two cases apart (no first-party client does; the web client treats both as "room not found") would lose that distinction.

### Detail

see findings


[analysis](findings/VULN-079.md)


### Dynamic validation

- **Status**: CONFIRMED (ordinary accounts recovered the exact name of a private group they cannot see ('proj-015b') in 327 oracle questions, through a Mongo operator in a method parameter)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-079-nosql_operator_room_name_oracle/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-079-nosql_operator_room_name_oracle/writeup.md](exploits/VULN-079-nosql_operator_room_name_oracle/writeup.md)

## VULN-006: stream-apps and stream-importers accept anonymous subscriptions, and the app setting-changed event carries the new value (secrets included)

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an unauthenticated websocket held subscriptions to the app and importer administration streams, which a logged-in-only stream refuses) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **CWE** | CWE-200, CWE-862 |
| **Category** | Unauthenticated information disclosure (realtime) |
| **Location** | `targets/rocket.chat/packages/streamer/src/notifications.module.ts:369` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-06: searched stream-importers / stream-apps unauthenticated subscription; adjacent only PRs #34922 and #35194 (preview check on stream-room-messages). |
| **Conditional** | yes: an Apps-Engine app with settings installed, and an administrator changing one of its settings while the attacker is subscribed |
| **Finding key** | `7a657c8b49e8732f` |

### Impact

Medium (CVSS 5.9): an unauthenticated DDP socket held open collects the plaintext value of every Apps-Engine setting an administrator saves while it is subscribed. Those settings are where installed apps keep credentials for external systems (third-party API keys, webhook secrets, bot tokens), and the engine documents PASSWORD-type settings as not encrypted, so the value on the wire is the secret itself. Administrators save them at install time and on every rotation. The stream-importers leg additionally hands an anonymous listener the progress and record counts of any running import.

### Remediation

In notifications.module.ts:365-371 replace allowRead('all') with a permission check: logged (plus manage-apps for administrative events) for streamApps and run-import for streamImporters, and set allowEmit accordingly; in listeners.module.ts:528-531 and the AppServerNotifier emit only { appId, settingId } so no value travels on a stream at all, letting the admin UI re-read the setting over the authorized REST route. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/WebSocket_Security_Cheat_Sheet.md (authorize every subscription and message) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Deny by Default).

### Side effects of the fix

Keeps both streams for authorized clients and removes only the weakness: anonymous sockets can no longer subscribe, and a setting-changed event no longer carries the value, so the admin settings page must re-read the setting after the event (one extra authorized request) instead of taking it from the frame.

### Detail

see findings


[analysis](findings/VULN-006.md)


### Dynamic validation

- **Status**: CONFIRMED (an unauthenticated websocket held subscriptions to the app and importer administration streams, which a logged-in-only stream refuses)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-006-anonymous_apps_stream_subscription/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-006-anonymous_apps_stream_subscription/writeup.md](exploits/VULN-006-anonymous_apps_stream_subscription/writeup.md)

## VULN-014: External control of a file path in downloadPublicImportFile: any local path is read into the importer, and the error is an existence oracle

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (a run-import holder read an arbitrary server-side file into the import store and distinguished existing from missing paths from the error alone, and the permission is delegable to an ordinary account) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N |
| **CWE** | CWE-73, CWE-22 |
| **Category** | External control of a file path (privileged importer) |
| **Location** | `targets/rocket.chat/apps/meteor/server/meteor-methods/import/downloadPublicImportFile.ts:46` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | known-unpatched |
| **Known evidence** | Issue #42355 'Arbitrary Local File Read via downloadPublicImportFile API' (2026-09-25, closed 2026-10-21 without a fix); fix PR #42357 'reject local paths in public import download' is open; this build keeps copyLocalFile and fs.existsSync (downloadPublicImportFile.ts:30-48). The sibling SSRF GHSA-6x96-99rg-wg67 on the same endpoint is fixed here. https://github.com/RocketChat/Rocket.Chat/issues/42355 |
| **Known confidence** | 8/10 |
| **Conditional** | no |
| **Finding key** | `5ee5fc54e646723c` |

### Impact

Medium (CVSS 4.9): a holder of run-import, which is an operator permission the product is designed to delegate rather than an administrator-only one, turns the importer into a filesystem reader. Any value that does not start with http is treated as a server path: a missing path comes back inside the error message (an existence oracle for the container's filesystem), and an existing one is copied into the import store and parsed, so its content surfaces in the import preview, the import's progress records and its error output. A directory path is handed to the importer as-is. Readable targets include the bundle's own configuration, mounted secrets and anything else the Node process can open.

### Remediation

Resolve fileUrl with path.resolve against a configured import directory and refuse anything whose resolved path is not inside it, in executeDownloadPublicImportFile (downloadPublicImportFile.ts:35-47); apply the same containment to the stored name joined in getImportFileData.ts:58-61; and return one generic error for both missing and forbidden paths so the message stops echoing the probe. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.md (canonicalise, then verify the prefix) with deploy/knowledge/payloads/PayloadsAllTheThings/Directory Traversal/README.md for the probe shapes.

### Side effects of the fix

Keeps server-path imports and removes only the weakness: an operator must place the export file in the configured import directory (or use an HTTP URL, which already goes through the SSRF-checked fetch), and the error no longer names the path that was tried.

### Detail

see findings


[analysis](findings/VULN-014.md)


### Dynamic validation

- **Status**: CONFIRMED (a run-import holder read an arbitrary server-side file into the import store and distinguished existing from missing paths from the error alone, and the permission is delegable to an ordinary account)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-014-import_file_path_control/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-014-import_file_path_control/writeup.md](exploits/VULN-014-import_file_path_control/writeup.md)
- **Detection**: [`detections/VULN-014.sigma.yml`](detections/VULN-014.sigma.yml) (medium, validated: fired on 6/6 of this exploit's own log lines, silent on 400 clean ones). It sees that the importer's URL-download route was called at all, and how often; not the local path in the body.

## VULN-024: Protected file downloads and personal data exports are marked publicly cacheable for a year, so a shared cache serves them to other people

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a private room's upload, which the workspace refuses to an unauthenticated caller, was served from a standard shared cache to a caller with no credentials, because the response says public, max-age=31536000) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven through a standard shared cache: the product's own headers are enough to serve a private upload to a stranger. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **CWE** | CWE-524 |
| **Category** | Sensitive data in a shared cache |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/media/file-upload/lib/requests.ts:54` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-24: searched file-upload Cache-Control max-age private files cached; adjacent only PR #43168 (tests that pin the header on /data-export). |
| **Conditional** | yes: a shared HTTP cache (CDN or caching reverse proxy) in front of the whole workspace that honours Cache-Control |
| **Finding key** | `b22bfc8446cf9927` |

### Impact

Medium (CVSS 5.9): both responses are authorized per request (by cookie, query parameter or auth headers) and then sent with Cache-Control: max-age=31536000 and no private directive and no Vary: Cookie. A standards-following shared cache in front of the workspace, which the vendor's own deployment guide anticipates (a CDN or caching reverse proxy), may therefore store a private room's file or a complete personal data export and serve it to the next requester for the same URL, with no credential at all. The export case is the worse one: it is one archive containing a user's whole message history and their uploaded files.

### Remediation

Mark the responses correctly: Cache-Control: private, max-age=31536000 for protected uploads (requests.ts:53-54) and Cache-Control: no-store for personal data exports (userDataDownload.ts:50-51), and add Vary: Cookie where a cache might still key on the URL alone. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Web_Cache_Security_Cheat_Sheet.md (an access-controlled response is never shared-cacheable) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/HTTP_Headers_Cheat_Sheet.md (Cache-Control).

### Side effects of the fix

Keeps both features and removes only the weakness: shared caches and CDNs stop storing protected files, so those requests reach the origin (more origin traffic and bandwidth for image-heavy workspaces), while browsers still cache them privately; data exports are no longer cached anywhere, so a user re-downloading one fetches it again.

### Detail

see findings


[analysis](findings/VULN-024.md)


### Dynamic validation

- **Status**: CONFIRMED (a private room's upload, which the workspace refuses to an unauthenticated caller, was served from a standard shared cache to a caller with no credentials, because the response says public, max-age=31536000)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-024-protected_files_public_cache/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-024-protected_files_public_cache/writeup.md](exploits/VULN-024-protected_files_public_cache/writeup.md)

## VULN-032: Account lockout bypass: the per-user failed-login block reads the username as typed, so logins by email or inside a totp envelope are never locked

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (the per-user lock engaged for the username but 15 guesses by email were never blocked and the email form logged in while the username form was locked) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N |
| **CWE** | CWE-307 |
| **Category** | Authentication (account lockout bypass) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/auth/restrictLoginAttempts.ts:103` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | known-unpatched |
| **Known evidence** | Issue #40195 'Plan: Enhance Login Protection and Fix Email Bypass' (2026-04-17; closed 2026-10-08 with no fix merged): login protection is bypassed when the email address is used. This build still reads only methodArguments[0].user?.username (restrictLoginAttempts.ts:103-106). The totp-envelope leg is not in that report. https://github.com/RocketChat/Rocket.Chat/issues/40195 |
| **Known confidence** | 8/10 |
| **Conditional** | no |
| **Finding key** | `efa35e58c3da6834` |

### Impact

Medium (CVSS 4.8): "Block failed login attempts by username" is the documented per-account lockout, and it is decided on the identifier spelling rather than on the account. isValidAttemptByUser reads methodArguments[0].user?.username and returns true when it is absent, which is exactly the shape REST builds for a login by email address ({ email: ... }) and for every attempt carrying a second-factor code ({ totp: { code, login } }). Failures are still counted against the resolved account, so the victim is the one locked out of the username form while the attacker keeps guessing through the email form indefinitely. TOTP verification has no attempt cap of its own either, so an attacker who already has the password can grind six-digit codes under the per-address limits alone.

### Remediation

Key the per-user decision on the resolved account rather than on the request's spelling: look the account up once (by username, email or whatever identifier the envelope carries, including inside totp.login) and evaluate the block on login.user?._id, or move the decision into the failure and success hooks that already know which account was resolved (restrictLoginAttempts.ts:98-145); and give TOTP failures their own per-account counter and lock instead of TOTPCheck.maxFaildedAttemtpsReached returning false. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authentication_Cheat_Sheet.md (account lockout keyed on the account) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md (rate-limit second-factor verification).

### Side effects of the fix

Keeps the lockout feature and removes only the weakness: failures at email-form logins and inside totp envelopes now count toward the same lock, which is what the setting's name promises, and a TOTP cap can lock out a user who mistypes codes repeatedly, so it should share the existing unlock window and admin unlock path.

### Detail

see findings


[analysis](findings/VULN-032.md)


### Dynamic validation

- **Status**: CONFIRMED (the per-user lock engaged for the username but 15 guesses by email were never blocked and the email form logged in while the username form was locked)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-032-lockout_bypass_by_email/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-032-lockout_bypass_by_email/writeup.md](exploits/VULN-032-lockout_bypass_by_email/writeup.md)

## VULN-034: URL-parameter session handoff: ?loginClient=mobile exports the resume token to the rocketchat:// scheme and ?resumeToken= logs the browser into another account

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the browser legs need the Playwright drive this stage did not have time to write) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N |
| **CWE** | CWE-352, CWE-939 |
| **Category** | Session handoff driven by URL parameters (token export to a custom scheme; login CSRF) |
| **Location** | `targets/rocket.chat/apps/meteor/client/views/root/hooks/useShareSessionWithOtherClients.ts:32` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-34: searched loginClient=mobile rocketchat://auth token deep link and resumeToken query login; adjacent only Rocket.Chat.ReactNative PR #7447 (mobile side of the handoff) and PR #41788 (SAML deep link). |
| **Conditional** | no |
| **Manual reason** | browser |
| **Finding key** | `2c8a5b60d8828c69` |

### Impact

Medium (CVSS 6.8): two hooks mounted on every page act on bare query parameters that anyone can put in a link. With ?loginClient=mobile or desktop, a logged-in browser reads its stored login token and navigates to rocketchat://auth?host=...&token=<resume token>&userId=..., handing a 90-day session credential (already past the second factor) to whatever program on the device claims that scheme: on Android any app may register it, iOS custom schemes are not exclusive, and desktop handlers are registerable too. With ?resumeToken=<token the attacker owns>, the same page silently logs the victim's browser into the attacker's account, so whatever the victim types next, including files and messages they believe are private, lands in a room the attacker controls.

### Remediation

Bind the handoff to a flow the native client started: honour loginClient only together with a one-time state value the app generated and the SSO round-tripped, ask the user to confirm the handover, and give the app a single-use code (as loginCode already is) rather than the resume token itself (useShareSessionWithOtherClients.ts:13-33, buildAuthDeeplinkURL.ts:1-5); for the reverse direction, ignore resumeToken when a session already exists or require an explicit confirmation plus a flow-bound nonce (useLoginViaQuery.ts:8-17), and stop putting resume tokens in URLs at all (passportOAuthCallback.ts:47 does the same). Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md (login CSRF) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Mobile_Application_Security_Cheat_Sheet.md (custom URL schemes are not a trusted channel).

### Side effects of the fix

Keeps the desktop and mobile sign-in handoff and removes only the weakness: the user confirms the handover once per device and the native app receives a single-use code instead of the long-lived token, and a link carrying resumeToken no longer switches an already-signed-in browser (a user who genuinely wants to change account signs out first).

### Detail

see findings


[analysis](findings/VULN-034.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the browser legs need the Playwright drive this stage did not have time to write)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-034-url_parameter_session_handoff/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-034-url_parameter_session_handoff/writeup.md](exploits/VULN-034-url_parameter_session_handoff/writeup.md)

## VULN-035: Room invite links are not revocable by the room's owners, outlive their creator's rights, and their use limit is not consumed atomically

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (the room owner could neither list nor revoke a moderator's permanent link, and the kicked, demoted creator re-entered the private group with it) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N |
| **CWE** | CWE-863, CWE-367 |
| **Category** | Broken access control (share link not re-validated or revocable) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/rooms/invites/useInviteToken.ts:25` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-35: searched invite link maxUses race revoke removed member; adjacent only PR #41174 (atomic revoke, 8.7.0), PR #38290, PR #35821. |
| **Conditional** | no |
| **Finding key** | `cbc53329cf87ddeb` |

### Impact

Medium (CVSS 5.4): an invite link is a bearer capability that nobody in the room can take back. Listing and removing invites check create-invite-links with no room scope, which consults global roles only, so the owners and moderators of a room (whose roles are room-scoped) get not_authorized when they try to revoke their own room's link; only a workspace administrator can, from the global invites page. Redemption re-checks the token's expiry, its use count and the redeemer's ban, but never whether the creator still has any rights in the room, so a link made by a moderator who has since been kicked or demoted keeps letting people (including that moderator) into a private room. And the use count is read-then-incremented unconditionally, so parallel redemptions of a single-use link all pass, while registration in Secret URL mode validates an invite without consuming a use at all.

### Remediation

Scope the permission to the invite's room in listInvites.ts:11 and removeInvite.ts:12 and surface revocation in the room's own invite panel; on redemption verify the creator still holds create-invite-links in that room (or delete a member's invites when they are kicked, banned or demoted); and consume uses atomically with a conditional update, checking modifiedCount, in both useInviteToken and the Secret URL registration path. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request) and deploy/knowledge/payloads/PayloadsAllTheThings/Race Condition/README.md (limit overrun).

### Side effects of the fix

Keeps invite links and removes only the weakness: links created by a member who has since been removed or demoted stop working, room owners gain the ability to revoke, and a single-use link admits exactly one account (so a user who double-submits the join sees one success and one "expired"), while registration through an exhausted link is refused.

### Detail

see findings


[analysis](findings/VULN-035.md)


### Dynamic validation

- **Status**: CONFIRMED (the room owner could neither list nor revoke a moderator's permanent link, and the kicked, demoted creator re-entered the private group with it)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-035-invite_links_unrevocable/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-035-invite_links_unrevocable/writeup.md](exploits/VULN-035-invite_links_unrevocable/writeup.md)

## VULN-040: Second-factor codes are not single-use: a TOTP code is replayable inside the window and a backup code can be redeemed twice by concurrent requests

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (the TOTP code was replayed for 4 further sessions; the backup-code race gave 1 token(s)) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N |
| **CWE** | CWE-294, CWE-362 |
| **Category** | MFA one-time code replay and consumption race |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/2fa/lib/totp.ts:49` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-40: searched TOTP code replay backup code race 2FA; adjacent only PR #40734 (TOTP REST migration). |
| **Conditional** | no |
| **Finding key** | `a8ca3c699579b0a9` |

### Impact

Medium (CVSS 4.2): a one-time code stops being one-time. TOTP verification calls speakeasy.verifyDelta with the configured window and records nothing on success, so a code observed after its legitimate use (a shoulder-surfed screen, a screenshot in a ticket, an x-2fa-code header in a proxy log) is accepted again for the remainder of the window, about 90 seconds at the shipped MaxDelta of 1. Backup codes are consumed by loading the array, splicing the matched hash out in memory and writing the whole array back with an unconditional $set, so N concurrent logins presenting the same backup code all find it present, all succeed, and the final write leaves the other codes intact. An attacker with the password turns one glimpsed code into extra sessions and step-ups.

### Remediation

Record consumption atomically. For TOTP, store services.totp.lastUsedStep and accept a step only through a conditional update that requires lastUsedStep to be lower, so a replay of the same (or an earlier) step fails; for backup codes, consume with updateOne({ _id, 'services.totp.hashedBackup': hash }, { $pull: { 'services.totp.hashedBackup': hash } }) and require modifiedCount === 1 instead of splicing a loaded array and re-setting it (totp.ts:32-44, Users.ts:2326-2337). Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md (one-time codes must be invalidated on use) with deploy/knowledge/payloads/PayloadsAllTheThings/Race Condition/README.md (limit overrun) for the concurrent half.

### Side effects of the fix

Keeps TOTP and backup codes and removes only the weakness: a user who submits the same code twice (a double click, two tabs, a retried request) is told it is invalid the second time and waits for the next code, and a backup code works exactly once.

### Detail

see findings


[analysis](findings/VULN-040.md)


### Dynamic validation

- **Status**: CONFIRMED (the TOTP code was replayed for 4 further sessions; the backup-code race gave 1 token(s))
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-040-totp_code_replay/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-040-totp_code_replay/writeup.md](exploits/VULN-040-totp_code_replay/writeup.md)

## VULN-043: OAuth login skips the second factor for any account inside the registration grace window, even one that has enrolled TOTP

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an account with TOTP enrolled was signed in through OAuth with no second factor, inside the registration grace window, while its password login still demanded the code) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven: an account with TOTP enrolled was signed in through OAuth with no factor inside the registration window. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N |
| **CWE** | CWE-288, CWE-308 |
| **Category** | MFA skipped on an alternate login path (registration grace window) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/oauth/twoFactorAuth.ts:30` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-43: searched OAuth login skips 2FA newly registered account remember window; adjacent only issue #41394 (SAML 2FA with unverified email), PR #42099, PR #43029. |
| **Conditional** | yes: an OAuth login provider enabled |
| **Finding key** | `a67615a32a3a0a9b` |

### Impact

Medium (CVSS 4.2): the registration grace window exists so that a brand-new account with no second factor yet can finish setting the workspace up, and the step-up path implements it correctly, granting the grace only when the user has no 2FA method at all. The OAuth decision function re-implements the same idea and drops that condition: doesUserRequire2FA returns false for every account younger than Accounts_TwoFactorAuthentication_RememberFor (1800 seconds by default) before it ever looks for an enrolled method. So for 30 minutes after an account is created, an OAuth login completes with no second factor even though the owner has already enrolled TOTP, while a password login for the same account at the same instant demands the code.

### Remediation

Evaluate the method first and apply the grace only when there is none, exactly as the step-up path does at 2fa/code/index.ts:102-110: in doesUserRequire2FA (twoFactorAuth.ts:23-41), call getSecondFactorMethod(user) before the remember-window test and return it whenever a method exists. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md (once a factor is enrolled it applies to every authentication path) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authentication_Cheat_Sheet.md.

### Side effects of the fix

Keeps the grace for brand-new accounts that have not enrolled anything (so the setup wizard and first-run flows still work) and removes only the weakness: an account that enrolled a method inside its first 30 minutes is asked for it at its next OAuth login, which is what its owner expects.

### Detail

see findings


[analysis](findings/VULN-043.md)


### Dynamic validation

- **Status**: CONFIRMED (an account with TOTP enrolled was signed in through OAuth with no second factor, inside the registration grace window, while its password login still demanded the code)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-043-oauth_login_skips_2fa_grace/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-043-oauth_login_skips_2fa_grace/writeup.md](exploits/VULN-043-oauth_login_skips_2fa_grace/writeup.md)

## VULN-061: Integration updates and deletes trust the type the caller names, so one integration permission family reaches the other's objects, script included

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an account with only the incoming-integration permissions changed and removed an outgoing integration by naming the other type in the body) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:L |
| **CWE** | CWE-863 |
| **Category** | Broken function-level authorization (type confusion between permission families) |
| **Location** | `targets/rocket.chat/apps/meteor/server/meteor-methods/integrations/incoming/updateIncomingIntegration.ts:102` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-61: searched integrations.update type webhook-incoming outgoing permission bypass; adjacent only PR #43522 (tests) and issue #13262 (the split permissions). |
| **Conditional** | yes: an administrator delegated one integration permission family to a role that lacks the other |
| **Finding key** | `6ee7fd9daae5f3aa` |

### Impact

Medium (CVSS 6.0): Rocket.Chat splits integration management into two permission families, incoming (webhooks that post into rooms) and outgoing (webhooks that send room traffic to a URL), and the update path decides which object to act on from the type in the request body while loading the stored document by id alone. A holder of manage-incoming-integrations therefore calls integrations.update with type webhook-incoming and an outgoing integration's id, and rewrites that outgoing integration: its target URL, its watched rooms and its script. Because the compiled script is saved before validateChannelRecords runs, even a request that is rejected afterwards leaves the replaced script in place. The attacker gains the other family's capability, which for an outgoing integration is a continuous feed of the watched rooms' messages to a URL they choose, and the symmetric ability to delete the other family's integrations.

### Remediation

Load the stored document with its type in every query: { _id, type: 'webhook-incoming' } in the incoming updater and its delete, { _id, type: 'webhook-outgoing' } in the outgoing ones (updateIncomingIntegration.ts:101-110, updateOutgoingIntegration.ts:24-32, Integrations.ts:48-60), and move saveCompiledIntegrationScript after every validation so a rejected update cannot write the script. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md (resolve the object within what the caller may reach).

### Side effects of the fix

Keeps both integration features and removes only the weakness: a request naming the wrong type fails with an invalid-integration error (the admin UI never sends one), and a rejected update leaves the stored script untouched, so a client that relied on the partial write to stage a script must send a valid request.

### Detail

see findings


[analysis](findings/VULN-061.md)


### Dynamic validation

- **Status**: CONFIRMED (an account with only the incoming-integration permissions changed and removed an outgoing integration by naming the other type in the body)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-061-integration_type_confusion/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-061-integration_type_confusion/writeup.md](exploits/VULN-061-integration_type_confusion/writeup.md)

## VULN-067: channels.list sorts on client-chosen fields before projecting, so a join code is recoverable by bisection

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (recovered a 5-character join code exactly in 58 requests from the sort order alone, and joined the channel it protected) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-203 |
| **Category** | Sort oracle on a hidden field |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/channels.ts:1475` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-67: searched channels.list sort joinCode hidden field oracle; adjacent only PR #8420 (field and query restrictions that do not cover sort) and PR #41948. Stage 08 R-27 links it to the CVE-2022-32219 fix that removed client queries but left sort keys. |
| **Regression of** | CVE-2022-32219 |
| **Conditional** | no |
| **Finding key** | `e2167a77a63cc29c` |

### Impact

Medium (CVSS 4.3): the channel listing passes the caller's sort straight to MongoDB, which orders the matched documents before the projection removes non-public fields. joinCode, the plain-text code that gates joining a protected public channel, is one of those fields: it is withheld from the response and still sortable. A user who can create channels sets a join code on a probe channel of their own, asks for the list sorted by joinCode, and reads from the target's position relative to the probe whether the target's code sorts before or after theirs. Repeating with adjusted probe values recovers the target's code character by character, after which the attacker joins a channel whose owners deliberately gated membership.

### Remediation

Give parseJsonQuery a per-route allow-list of sortable fields (the ones each listing actually projects) and reject anything else with a 400 rather than passing it to Mongo, in parseJsonQuery.ts:16-37 and at the call site in channels.ts:1434. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Input_Validation_Cheat_Sheet.md (validate against an allow-list when the value space is known) with deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Error_Handling_Cheat_Sheet.md for not letting ordering answer questions the response does not.

### Side effects of the fix

Keeps sorting for the fields the listings return and removes only the weakness: an API client that sorted on a field outside the allow-list receives a 400 instead of a privileged ordering, so a custom client sorting on an internal field must change.

### Detail

see findings


[analysis](findings/VULN-067.md)


### Dynamic validation

- **Status**: CONFIRMED (recovered a 5-character join code exactly in 58 requests from the sort order alone, and joined the channel it protected)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-067-join_code_recovery_via_sort_oracle/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-067-join_code_recovery_via_sort_oracle/writeup.md](exploits/VULN-067-join_code_recovery_via_sort_oracle/writeup.md)
- **Detection**: [`detections/VULN-067.sigma.yml`](detections/VULN-067.sigma.yml) (medium, validated: fired on 60/60 of this exploit's own log lines, silent on 400 clean ones). It sees every oracle question, because the joinCode sort key is in the URL, so the recovery run is countable.

## VULN-069: Removing the admin role skips assign-admin-role: users.update replaces the role list with no last-admin guard

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a delegate refused the promotion guard still removed the admin role from an administrator through users.update, which the sibling route refuses) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H |
| **CWE** | CWE-269 |
| **Category** | Role hierarchy not enforced |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/users/saveUser/saveUser.ts:133` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-69: searched roles.removeUserFromRole admin assign-admin-role users.update roles last admin; adjacent only PR #22949 (last-admin deactivation guard; a reviewer asked for the same on role removal) and PR #42947. |
| **Conditional** | yes: an administrator delegated role management without assign-admin-role |
| **Finding key** | `d67565c6cc40e035` |

### Impact

Medium (CVSS 6.5): granting the admin role requires assign-admin-role (validateUserData refuses a roles array containing admin without it, and the add-to-role method does the same), but taking it away requires neither that permission nor any equivalent. users.update sets the whole roles array through updater.set('roles', userData.roles) behind assign-roles alone, with no admin-specific check and no last-admin guard, so a delegated role manager demotes administrators one by one and can leave the workspace with none. roles.removeUserFromRole is gated only on access-permissions; it does keep one admin, which is the guard the users.update path lacks entirely. The product's role hierarchy therefore holds for promotions and not for demotions.

### Remediation

Apply the same rule in both directions: require assign-admin-role whenever admin is removed from or absent in a submitted roles array (extend the check in validateUserData.ts:78 to compare the submitted list with the stored one), and add the last-admin guard that roles.removeUserFromRole has (roles.ts:299-304) to the saveUser path so no route can remove the final administrator. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Enforce Least Privileges; a role-management permission must not reach above itself).

### Side effects of the fix

Keeps delegated role management and removes only the weakness: a manager without assign-admin-role can no longer demote administrators (they can still manage every other role), and no path can remove the last administrator, so a workspace that deliberately demoted its final admin through the API must now use the console or keep one.

### Detail

see findings


[analysis](findings/VULN-069.md)


### Dynamic validation

- **Status**: CONFIRMED (a delegate refused the promotion guard still removed the admin role from an administrator through users.update, which the sibling route refuses)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-069-last_admin_removal/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-069-last_admin_removal/writeup.md](exploits/VULN-069-last_admin_removal/writeup.md)

## VULN-070: autotranslate.translateMessage omits the auto-translate permission its sibling routes and the client require

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an account without the auto-translate permission reached translateMessage, which its sibling route refuses it, and the handler ran to the provider) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, a non-default feature. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L |
| **CWE** | CWE-862 |
| **Category** | Missing permission check on one of three twin routes |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/autotranslate.ts:190` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-70: parent CVE-2026-32994 (HackerOne #3713682, the route returned any message by id; fixed 8.5.0 by PR #40508, which added only canAccessRoomAsync); also CVE-2026-32995 (DDP method). The missing permission is not reported. |
| **Regression of** | CVE-2026-32994 |
| **Conditional** | yes: AutoTranslate_Enabled with a translation provider configured |
| **Finding key** | `54ef5d37ffd90309` |

### Impact

Medium (CVSS 4.3): auto-translate is an administrator-held permission (it is created with roles ['admin']) and the other server functions in the feature check it: getSupportedLanguages and saveSettings both refuse a caller without it, and the web client checks it before using the feature at all. The on-demand translation route does not: it verifies the feature switch and the caller's access to the message's room, and then calls the configured provider. So any authenticated user makes the workspace's paid translation provider process any message they can open, as often as they like, which spends the organisation's per-character budget and sends that message's text to the third-party provider on the initiative of a user the administrator excluded from the feature.

### Remediation

Declare the permission on the route: add permissionsRequired: ['auto-translate'] to autotranslate.translateMessage (autotranslate.ts:156-172), or perform an explicit hasPermissionAsync(this.userId, 'auto-translate') check in the handler before calling translateMessage, matching getSupportedLanguages.ts:12 and saveSettings.ts:14. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request) with deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Denial_of_Service_Cheat_Sheet.md for the metered-resource angle.

### Side effects of the fix

Keeps translation for the users an administrator permitted and removes only the weakness: a user without auto-translate loses on-demand translation, which the client already hides from them, so no first-party flow changes.

### Detail

see findings


[analysis](findings/VULN-070.md)


### Dynamic validation

- **Status**: CONFIRMED (an account without the auto-translate permission reached translateMessage, which its sibling route refuses it, and the handler ran to the provider)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-070-autotranslate_missing_permission/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-070-autotranslate_missing_permission/writeup.md](exploits/VULN-070-autotranslate_missing_permission/writeup.md)

## VULN-075: Pending-file importer fetches export-supplied URLs with Node's raw HTTP client, bypassing the SSRF guard its sibling fetch now uses

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the pending-file record has to be seeded beside the run and that did not fit this stage's time budget) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N |
| **CWE** | CWE-918 |
| **Category** | Server-side request forgery (non-blind, privileged importer) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/import/pending-files/PendingFileImporter.ts:170` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 08 R-04: parent GHSA-6x96-99rg-wg67 (blind SSRF in downloadPublicImportFile; < 8.8.0 and backports; fixed by PR #41749, which changed only that file); vendor-tracker search 'PendingFileImporter' returned 16 items, none about SSRF. https://github.com/RocketChat/Rocket.Chat/security/advisories/GHSA-6x96-99rg-wg67 |
| **Regression of** | GHSA-6x96-99rg-wg67 |
| **Conditional** | no |
| **Manual reason** | other |
| **Finding key** | `b6b9a25baf562403` |

### Impact

Medium (CVSS 6.8): the Slack importer records each message attachment's url_private_download from the uploaded export as the pending file's download URL, and downloadPendingFiles fetches it with Node's own http/https client rather than @rocket.chat/server-fetch, so neither the SSRF guard nor SSRF_Allowlist applies. Whatever answers with a 2xx is stored through fileStore._doInsert, which the code comments note bypasses the file-store filters, and attached to the imported message as a downloadable file. So a holder of run-import who uploads a crafted export makes the server request arbitrary internal URLs from its own network position and reads the responses back out of the workspace: a non-blind SSRF, against exactly the hosts the guard and the allow-list exist to protect.

### Remediation

Fetch through the guarded client in PendingFileImporter.downloadFile (PendingFileImporter.ts:164-195): use fetch from @rocket.chat/server-fetch with ignoreSsrfValidation: false and allowList: settings.get('SSRF_Allowlist'), exactly as the sibling import fetch does after the GHSA-6x96 fix, and accept only http(s) URLs on the export's expected hosts. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md (validate the destination, use one guarded client) with deploy/knowledge/payloads/PayloadsAllTheThings/Server Side Request Forgery/README.md for the internal targets to test.

### Side effects of the fix

Keeps pending-file imports from public hosts and removes only the weakness: a file hosted on an internal address is no longer fetched unless an administrator allow-lists it, so an on-premises export whose attachments sit on an internal file server needs that host added to SSRF_Allowlist.

### Detail

see findings


[analysis](findings/VULN-075.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the pending-file record has to be seeded beside the run and that did not fit this stage's time budget)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-075-importer_ssrf_raw_http/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-075-importer_ssrf_raw_http/writeup.md](exploits/VULN-075-importer_ssrf_raw_http/writeup.md)

## VULN-078: The DDP-over-REST bridges key their rate limits on the caller's own X-Auth-Token header, so every header-less anonymous caller shares one bucket and a rotating header escapes it

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (one anonymous client exhausted the bucket every other anonymous client shares, and rotating the X-Auth-Token header escaped the limit entirely) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven: one anonymous client's burst had an unrelated anonymous client refused, and a rotated header escaped the limit. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L |
| **CWE** | CWE-799, CWE-400 |
| **Category** | Denial of service through a shared rate-limit key (and limit bypass) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/ApiClass.ts:792` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 08 R-06: residual of RCSA-2023-0004 (vendor security page; rate-limiter bypass by modifying User-Agent, fixed 6.5.1 with an IP fallback that is now dead code); vendor-tracker search 'method.callAnon rate limit' found nothing about the key. https://docs.rocket.chat/docs/security-fixes-and-updates |
| **Conditional** | no |
| **Finding key** | `a9f6121f307b6cca` |

### Impact

Medium (CVSS 5.3): ApiClass sets this.token = hashLoginToken(String(authToken)) on every REST request, so with no X-Auth-Token header it becomes the hash of the string null, a constant. Both method bridges then compute connectionId = this.token || sha256(ip), which means the IP fallback never runs and every header-less anonymous caller is counted as the same DDP connection. Meteor's default accounts rule allows five login, createUser, resetPassword or forgotPassword calls per connection per ten seconds, and the web client sends every password login through method.callAnon with no auth header, so five anonymous login calls every ten seconds make every logged-out user's web login fail with too-many-requests, workspace-wide. The same key, being caller-chosen, works the other way too: a fresh random X-Auth-Token per request gives each one its own bucket and lifts the per-connection limits on anonymous login and forgotPassword guessing.

### Remediation

Key the limiter on something the caller cannot choose. In ApiClass.ts:791-792 leave this.token undefined when the header is absent (hash only a header that is actually present), and in the two bridges (misc.ts:642-647 and :687-692) key anonymous calls on this.requestIp and authenticated calls on this.userId rather than on a header hash. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Denial_of_Service_Cheat_Sheet.md (Rate limiting: the key must identify the client, not be supplied by it) with deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authentication_Cheat_Sheet.md (Account Lockout).

### Side effects of the fix

Keeps both bridges and their limits, and removes only the weakness: limits become per client address for anonymous calls and per user for authenticated ones, so one client can no longer exhaust another's bucket, and a client can no longer reset its own by changing a header. A deployment behind a proxy that does not set a forwarded-for header would see all its users share an address, which is the standard reason to configure the proxy headers Rocket.Chat already documents.

### Detail

see findings


[analysis](findings/VULN-078.md)


### Dynamic validation

- **Status**: CONFIRMED (one anonymous client exhausted the bucket every other anonymous client shares, and rotating the X-Auth-Token header escaped the limit entirely)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-078-ddp_rest_shared_rate_limit_key/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-078-ddp_rest_shared_rate_limit_key/writeup.md](exploits/VULN-078-ddp_rest_shared_rate_limit_key/writeup.md)

## VULN-081: The Livechat webhook sender and its test route keep ignoreSsrfValidation on, for the same non-admin Omnichannel roles PR #42201 stopped from reaching internal hosts through triggers

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (a non-admin livechat-manager made the server fetch URLs of its choosing, including a host only the server can reach, and received the customer's conversation data at its own listener) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Proven: a non-admin role made the server fetch hosts only it can reach and received customer data at our listener. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N |
| **CWE** | CWE-918 |
| **Category** | Server-side request forgery (privileged Omnichannel role) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/omnichannel/webhooks.ts:31` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 08 R-05: sibling of PR #42201 'fix!: SSRF validation disabled in Livechat trigger external service' (merged 2026-10-26, 9.0.0), which has no CVE or GHSA id; tracker search 'webhook.test SSRF' not completed (GitHub search API limit). https://github.com/RocketChat/Rocket.Chat/pull/42201 |
| **Conditional** | yes: Livechat_enabled (Omnichannel on) with a livechat-manager or livechat-monitor account |
| **Finding key** | `f107bd98dc5862d6` |

### Impact

Medium (CVSS 4.1): a livechat-manager or livechat-monitor sets Livechat_webhookUrl through POST /api/v1/omnichannel/integrations, which requires view-livechat-manager and writes the value after a trim with no scheme or host validation. Both outbound calls that use it pass ignoreSsrfValidation: true to serverFetch, so the SSRF guard and SSRF_Allowlist are skipped: livechat/webhook.test (view-livechat-webhooks) posts sample data and distinguishes a 200 from everything else, which is a probe of any internal address and port the container can reach, and the event sender posts real conversation data to the same URL whenever an enabled Livechat event fires. The vendor removed exactly this opt-out from the Livechat trigger call in PR #42201 for a permission held by the same roles, which is what settles that non-admin Omnichannel roles reaching internal hosts is a bug rather than a feature.

### Remediation

Remove ignoreSsrfValidation: true from both Livechat webhook fetches (api/v1/omnichannel/webhooks.ts:60-70 and lib/omnichannel/webhooks.ts:23-33) and pass allowList: settings.get('SSRF_Allowlist') instead, exactly as PR #42201 did in ee/server/api/v1/omnichannel/lib/triggers.ts:19-26; validate the configured URL's scheme when it is set in integration.ts:28-32, and return one indistinguishable result from the test route so it cannot serve as a port oracle. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md (allow-list the destination; do not report the outcome back to the requester).

### Side effects of the fix

Keeps Livechat webhooks working for public receivers and removes only the weakness: a receiver on an internal address stops working until an administrator adds it to SSRF_Allowlist, which is a real behaviour change for on-premises deployments whose webhook consumer sits beside the app, and the test route's answer becomes less informative about why a receiver failed.

### Detail

see findings


[analysis](findings/VULN-081.md)


### Dynamic validation

- **Status**: CONFIRMED (a non-admin livechat-manager made the server fetch URLs of its choosing, including a host only the server can reach, and received the customer's conversation data at its own listener)
- **Confidence**: 6/10
- Exploit directory: `exploits/VULN-081-livechat_webhook_ssrf/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-081-livechat_webhook_ssrf/writeup.md](exploits/VULN-081-livechat_webhook_ssrf/writeup.md)
- **Detection**: [`detections/VULN-081.sigma.yml`](detections/VULN-081.sigma.yml) (medium, validated: fired on 3/3 of this exploit's own log lines, silent on 400 clean ones). It sees each Livechat webhook test, the request that performs the fetch; not the URL fetched, which is a workspace setting.

## VULN-013: Email Direct Reply takes the posting identity from the From header, so one spoofed email posts as any user under any message id

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the mail sink is in the lab but the poller interval could not be waited out inside this stage's time budget) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N |
| **CWE** | CWE-290 |
| **Category** | Authentication bypass by spoofing (message impersonation) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/notifications/processDirectEmail.ts:37` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-13: searched direct reply email spoofed From; adjacent only PR #43777 (tests of processDirectEmail), CVE-2024-46936 (impersonation via UpdateOTRAck, a different path). |
| **Conditional** | yes: Direct_Reply_Enable with an IMAP or POP reply mailbox configured |
| **Manual reason** | other |
| **Finding key** | `41fa48817e1782a5` |

### Impact

Medium (CVSS 5.9): an outsider with no account posts a message as any Rocket.Chat user, administrators included, into any room that user can post to, threaded under a real message of the attacker's choosing. The posting identity comes from the email's From header and the thread from the +<messageId> tag in the recipient address, neither of which is a secret: the identity is an address (the directory listing elsewhere in this report hands out every one) and the message id travels in permalinks and notification mails. The result is high-trust impersonation inside the conversation being discussed ("Approved, go ahead" from the finance lead, in the thread), with sentByEmail set but no visible warning.

### Remediation

Make the reply address itself the credential: generate replies+<mid>.<uid>.<exp>.<hmac>@domain when the notification is sent, verify the HMAC and expiry in processDirectEmail.ts before anything else, and post as the user named in the token while ignoring the From header entirely; optionally also require DKIM alignment for the sending domain. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authentication_Cheat_Sheet.md (an identity claim is only an authenticator when the server can verify its issuer) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.md.

### Side effects of the fix

Keeps Email Direct Reply and removes only the weakness: a reply sent from a different address than the one the notification went to, or to a notification older than the token's expiry, is no longer accepted, and users who forward a notification to a colleague to answer on their behalf lose that (undocumented) ability.

### Detail

see findings


[analysis](findings/VULN-013.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the mail sink is in the lab but the poller interval could not be waited out inside this stage's time budget)
- **Confidence**: 5/10
- Exploit directory: `exploits/VULN-013-email_direct_reply_spoofing/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-013-email_direct_reply_spoofing/writeup.md](exploits/VULN-013-email_direct_reply_spoofing/writeup.md)

## VULN-038: video-conference.share-chat creates a discussion without the membership and send checks regular discussion creation enforces

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the route needs a call created by a marketplace video-conference app, which a sealed lab cannot install) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N |
| **CWE** | CWE-863 |
| **Category** | Broken access control (secondary feature writing into a room; ban and mute bypass) |
| **Location** | `targets/rocket.chat/apps/meteor/server/services/video-conference/service.ts:1862` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-38: searched video-conference share-chat discussion non-member add-participants; adjacent only PRs #41934 and #41735 (feature design) and PR #43038 (9.0 membership check for discussions in public rooms). |
| **Conditional** | yes: a video-conference provider app installed and a call held in the target room |
| **Manual reason** | external-network |
| **Finding key** | `b22da5e50eeaf947` |

### Impact

Medium (CVSS 4.2): conference membership is a separate authorization axis from room membership (canAccessConference admits anyone listed in the call, because participants may legitimately have no access to the room the call started in), and the share-chat discussion branch acts on it without re-checking the room. Its own comment promises "the same rules regular discussion creation enforces", but it checks only the Discussion_enabled switch and start-discussion, which the default user role holds; the real path additionally requires canSendMessageAsync and a status-aware subscription. So an outsider a participant added to the call, or a member the room has banned or muted, creates a discussion under that private room, becomes its owner, pulls in every subscriber of the parent room (which discloses the private membership), and leaves a "started a discussion" notice inside the room they cannot otherwise write to.

### Remediation

In shareChatWithMembers (service.ts:1857-1870) apply the checks the primary path applies: canSendMessageAsync(rid, caller) and a non-banned, status-aware subscription for the caller, as createDiscussion.ts:99-112 does; refuse once the call has ended (endedAt set); and restrict add-participants to accounts that can access the call's room so conference membership cannot be used to manufacture room access. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request, and do not re-implement a rule partially on a secondary path).

### Side effects of the fix

Keeps chat sharing for room members and removes only the weakness: a participant who cannot write in the call's room can no longer move the call's chat into a discussion there (they can still use the call), ended calls no longer allow it, and banned or muted members are refused.

### Detail

see findings


[analysis](findings/VULN-038.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the route needs a call created by a marketplace video-conference app, which a sealed lab cannot install)
- **Confidence**: 5/10
- Exploit directory: `exploits/VULN-038-videoconf_share_chat_authorization/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-038-videoconf_share_chat_authorization/writeup.md](exploits/VULN-038-videoconf_share_chat_authorization/writeup.md)

## VULN-042: Attacker-chosen text in the workspace's own registration and reset emails, sent to any address

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (the workspace sent its own genuine mail, from its own address, to a third party's mailbox carrying a sentence the attacker chose) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, default configuration. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N |
| **CWE** | CWE-451 |
| **Category** | Trusted platform email carrying attacker-controlled text |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/auth/startup.js:129` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-42: searched registration email name hyperlink injection; adjacent only HackerOne #833470 'HTML Injection into Email via Signup' (markup, refused today by validateNameChars.ts:6), PR #11644, issue #35965, CVE-2026-65644. The plain-text and auto-link variant is not reported. |
| **Conditional** | no |
| **Finding key** | `1c90d182025f8084` |

### Impact

Medium by CVSS (4.3), realistically Low: an unauthenticated caller registers with somebody else's email address and a display name that is really a sentence, and the workspace sends that person its own genuine verification mail, from its own address, with the attacker's text in the greeting. The same name reaches the password-reset mail's subject and body, there inserted with no escaping and no dot-neutralisation at all. Name validation refuses only <, >, \ and /, so markup is blocked but sentences, phone numbers and bare domains (which mail clients auto-link) pass. The result is phishing content carried by mail that passes SPF, DKIM and DMARC for the organisation, which is exactly the trust that makes it effective; no markup and no credential theft happen directly, which is why the realistic severity is lower than the band.

### Remediation

Do not put an unverified registrant's display name into mail sent to an address they have not proven they own: greet by the address (or by nothing) in verifyEmail until the address is verified, and pass the name through safeHtmlDots and HTML escaping in the reset template as the verification template already half-does (startup.js:104-141). Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.md (ownership verification before acting on an address) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Error_Handling_Cheat_Sheet.md for not reflecting unvalidated input into trusted output.

### Side effects of the fix

Keeps both mails and removes only the weakness: the greeting shows the address rather than the registrant's chosen name until the address is verified, so a legitimate new user sees a slightly less personal first email, and the reset mail renders a name containing dots as text.

### Detail

see findings


[analysis](findings/VULN-042.md)


### Dynamic validation

- **Status**: CONFIRMED (the workspace sent its own genuine mail, from its own address, to a third party's mailbox carrying a sentence the attacker chose)
- **Confidence**: 5/10
- Exploit directory: `exploits/VULN-042-attacker_text_in_platform_email/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-042-attacker_text_in_platform_email/writeup.md](exploits/VULN-042-attacker_text_in_platform_email/writeup.md)

## VULN-052: Smarsh compliance export interpolates message text and sender names into the archived HTML unescaped, so a member forges or hides archive entries

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the Smarsh compliance export is a licensed enterprise module and is not present on this workspace) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L |
| **CWE** | CWE-116, CWE-117 |
| **Category** | Integrity of compliance records (HTML injection into archived email) |
| **Location** | `targets/rocket.chat/apps/meteor/server/bridges/smarsh/functions/generateEml.ts:113` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-52: searched Smarsh connector HTML injection compliance archive; adjacent only PR #4130 (the connector) and HackerOne #3779690 (HTML room export XSS). |
| **Conditional** | yes: Smarsh_Enabled with Smarsh_Email set |
| **Manual reason** | config-flag |
| **Finding key** | `9c342a36c4e149b5` |

### Impact

Medium (CVSS 5.4): the Smarsh connector builds the regulatory archive as an HTML table and pushes raw values into it: rows.push(message.msg) for the text and rows.push(`${sender.name} &lt;...&gt;`) for the author, with no escaping, and the table is mailed as the HTML body to the archive address. A member who posts table markup therefore writes rows of their own into the record (attributed to whomever they like, with any timestamp) and, by opening an HTML comment, hides the genuine rows that follow. Separately, the loop returns out of the whole job when a message's author no longer exists, so one message from a deleted user stops archiving for every room processed after it. The archive is what an organisation produces to a regulator, so its integrity is the point of the feature.

### Remediation

Escape every interpolated value in generateEml.ts (the message text at :110-114 and the sender name at :78-82, through escapeHTML as the surrounding code already does for the angle brackets) and replace the return at :71 with continue, falling back to message.u.username when the author record is gone so a deleted user cannot halt the export. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md (output encoding for the HTML context) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Logging_Cheat_Sheet.md (never let logged content alter the record's structure).

### Side effects of the fix

Keeps the export and removes only the weakness: markup typed in a message is archived as literal text, exactly as the chat client displays it, and a message whose author has been deleted is archived under the stored username instead of ending the run.

### Detail

see findings


[analysis](findings/VULN-052.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the Smarsh compliance export is a licensed enterprise module and is not present on this workspace)
- **Confidence**: 5/10
- Exploit directory: `exploits/VULN-052-smarsh_export_html_injection/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-052-smarsh_export_html_injection/writeup.md](exploits/VULN-052-smarsh_export_html_injection/writeup.md)

## VULN-056: postMessage command channels accept any origin: iframe login never checks it, and the iframe integration ships with origin

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the two-document browser drive did not fit this stage's time budget; the shipped origin settings are checked here) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N |
| **CWE** | CWE-346 |
| **Category** | Origin validation error (cross-window command injection) |
| **Location** | `targets/rocket.chat/apps/meteor/client/views/root/hooks/useIframeLoginListener.ts:21` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-56: searched iframe login postMessage login-with-token origin check; adjacent only open issue #42490 (IframeModal listener without checks, a different listener) and issue #9530 (2018); the docs describe the * default. |
| **Conditional** | yes: Accounts_iframe_enabled, or Iframe_Integration_receive_enable with its origin left at the shipped * |
| **Manual reason** | browser |
| **Finding key** | `6dfe5d5dbf592904` |

### Impact

Medium (CVSS 4.3): both embedding features listen for window messages and act on them without establishing who sent them. The iframe-login listener checks only that the message data is an object and then switches on data.event, so any window holding a reference to the workspace tab can send login-with-token and move that tab into an account of the attacker's choosing, or trigger try-iframe-login. The iframe-integration listener does compare origins, but skips the comparison when Iframe_Integration_receive_origin is *, which is the value the setting ships with, so enabling the feature without editing that field accepts commands from everywhere: logout, go to a room, and the rest of the command table. One click on an attacker page (window.open plus a postMessage) is enough, and a victim who does not notice the account switch keeps typing into rooms the attacker controls.

### Remediation

Establish the sender before acting: in useIframeLoginListener.ts:21-26 and useIframeCommands.ts:112-120 require event.source === window.parent and event.origin to be on a non-wildcard allow-list, and ship Iframe_Integration_receive_origin empty (general.ts:316) so enabling the feature without configuring an origin accepts nothing rather than everything. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/HTML5_Security_Cheat_Sheet.md (Web Messaging: always verify the origin and, where possible, the source of a received message).

### Side effects of the fix

Keeps both embedding features and removes only the weakness: a portal must list its origin explicitly before its commands are honoured, and commands from opener windows (as opposed to the embedding parent) are refused, so an integration that relied on the wildcard must set its origin.

### Detail

see findings


[analysis](findings/VULN-056.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the two-document browser drive did not fit this stage's time budget; the shipped origin settings are checked here)
- **Confidence**: 5/10
- Exploit directory: `exploits/VULN-056-postmessage_any_origin/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-056-postmessage_any_origin/writeup.md](exploits/VULN-056-postmessage_any_origin/writeup.md)

## VULN-064: Apps marketplace REST routes have no manage-apps check, so any user obtains a workspace Cloud token with purchase scope

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the marketplace routes need a Cloud-registered workspace, which a sealed unlicensed lab does not have) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N |
| **CWE** | CWE-862, CWE-522 |
| **Category** | Missing authorization (server credential exposed) |
| **Location** | `targets/rocket.chat/apps/meteor/ee/server/api/apps/rest.ts:225` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-64: searched buildExternalUrl marketplace token manage-apps; adjacent CVE-2026-55762 (fingerprint without authorization, fixed 8.5.1) and CVE-2026-23477. Stage 08 R-22: residual of CVE-2026-29197 (GHSA-37hj-44gj-w9gc), whose fix put manage-apps on the log routes only. |
| **Regression of** | CVE-2026-29197 |
| **Conditional** | yes: the workspace registered with Rocket.Chat Cloud |
| **Manual reason** | external-network |
| **Finding key** | `51ef9c74a013f4b6` |

### Impact

Medium (CVSS 5.4): buildExternalUrl is declared with authRequired only, and it mints a workspace Cloud access token through the client_credentials grant using the workspace's Cloud client id and secret, with scope marketplace:purchase, then returns it inside a URL in the response body. Any signed-in user therefore extracts a bearer token that speaks for the whole workspace to Rocket.Chat Cloud, together with the workspace id and the active-user count. The app-request routes beside it proxy with the same credential, so the same caller reads which apps colleagues asked administrators to install, with requester details, and can mark those requests seen, which corrupts an administrator workflow. What the token is worth on the Cloud side cannot be established from the lab, which is why this needs a registered workspace to settle.

### Remediation

Add permissionsRequired: ['manage-apps'] to buildExternalUrl, app-request, app-request/stats and app-request/markAsSeen in ee/server/api/apps/rest.ts; and stop returning the token at all: have the server open the purchase session (or issue a short-lived, single-use redirect) so a workspace credential never reaches a browser or a response body. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Enforce Least Privileges) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Secrets_Management_Cheat_Sheet.md (a server credential is never handed to a client).

### Side effects of the fix

Keeps the marketplace flow and removes only the weakness: non-administrators lose two routes the admin UI never offers them, the request flow (buildExternalAppRequest and the notify-admins path) is unchanged, and an administrator's purchase journey gains one server-side redirect instead of a token-bearing URL.

### Detail

see findings


[analysis](findings/VULN-064.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the marketplace routes need a Cloud-registered workspace, which a sealed unlicensed lab does not have)
- **Confidence**: 5/10
- Exploit directory: `exploits/VULN-064-marketplace_cloud_token_exposure/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-064-marketplace_cloud_token_exposure/writeup.md](exploits/VULN-064-marketplace_cloud_token_exposure/writeup.md)

## VULN-028: Indirect prompt injection in AI Search: other users' messages become instructions, and the answer renders as markdown that fetches attacker URLs

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (AI Search needs a licensed AI module and a model provider, neither of which exists in this workspace) |
| **Confidence** | 4/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N |
| **CWE** | CWE-1427, CWE-1426 |
| **Category** | LLM prompt injection (indirect, through retrieved content) with a rendering sink |
| **Location** | `targets/rocket.chat/packages/ai-search/src/llm.ts:64` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-28: searched AI search prompt injection answer markdown image exfiltration; adjacent only CVE-2026-47733 (ImageElement javascript: URLs, fixed 8.5.0). |
| **Conditional** | yes: the AI licence module with AI Search enabled and an OpenAI-compatible provider configured |
| **Manual reason** | config-flag |
| **Finding key** | `cb886b56a40c621a` |

### Impact

Medium (CVSS 4.4): the AI Search answer is built by concatenating the bodies of other users' messages into one user turn behind a plain "Source messages (untrusted):" label, with nothing escaping the per-source block structure, so a planted message can close its own block and address the model directly. The answer is then rendered through MarkdownText with DOMPurify allowing http(s) URIs, and the workspace CSP sets img-src * data: blob:, so a markdown image in the answer is fetched by the victim's browser on render. An attacker therefore steers what a colleague's AI answer says (fabricated statements with citations, phishing links) and can exfiltrate the text of the other retrieved sources, which may come from rooms the attacker cannot read, through the image URL.

### Remediation

Neutralise retrieved content before it enters the prompt in buildSearchAnswerPrompt (llm.ts:51-67): fence each source in delimiters that are escaped inside the text, and strip markdown image and link syntax from the source bodies; and validate the output, rendering the answer in SearchAnswerPanel with a renderer that drops images and external links (or allows only the cited message permalinks). Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.md (treat retrieved content as data, constrain the output surface) with deploy/knowledge/payloads/PayloadsAllTheThings/Prompt Injection/README.md for the injection shapes.

### Side effects of the fix

Keeps AI answers and their citations and removes only the weakness: images and arbitrary external links no longer render inside an answer (citations still link to the cited messages), and source text reaches the model without markdown formatting, which does not change its meaning.

### Detail

see findings


[analysis](findings/VULN-028.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (AI Search needs a licensed AI module and a model provider, neither of which exists in this workspace)
- **Confidence**: 4/10
- Exploit directory: `exploits/VULN-028-ai_search_prompt_injection/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-028-ai_search_prompt_injection/writeup.md](exploits/VULN-028-ai_search_prompt_injection/writeup.md)

## VULN-039: Apple identity tokens are replayable across workspaces, because the audience list always includes the shared official iOS app and no nonce is checked

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the finding needs Apple-signed identity tokens, which a sealed lab cannot obtain or forge) |
| **Confidence** | 4/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N |
| **CWE** | CWE-345, CWE-294 |
| **Category** | Authentication (identity token accepted across relying parties) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/auth-providers/apple/handleIdentityToken.ts:95` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-39: parent GHSA-c75c-5hc7-j4vp / CVE-2026-55759 (Apple Sign-In skipped aud, exp, nbf, nonce; fixed 8.5.1 and backports) is fixed here (handleIdentityToken.ts:78-100), but the fix always adds DEFAULT_APPLE_AUDIENCES = ['chat.rocket.ios'] and checks no nonce; the cross-workspace replay is not reported. |
| **Regression of** | CVE-2026-55759 |
| **Conditional** | yes: Apple login enabled (Accounts_OAuth_Apple) |
| **Manual reason** | external-network |
| **Finding key** | `3150333ed4c4b81f` |

### Impact

Medium (CVSS 6.8): every Rocket.Chat workspace with Apple login accepts an identity token whose audience is chat.rocket.ios, the identifier of the official iOS app, because DEFAULT_APPLE_AUDIENCES is merged into the allowed audiences unconditionally. That identifier is shared by every workspace the app can connect to, so a token the victim's phone produced for workspace A is equally valid at workspace B, and no nonce ties a token to the login attempt that asked for it. Any workspace operator therefore collects replayable credentials from their own users: within the token's lifetime they can log in as those users on any other workspace with Apple login enabled, limited only by whether the victim's account there has an applicable second factor.

### Remediation

Stop trusting a shared audience and bind the token to the attempt: remove DEFAULT_APPLE_APPLE_AUDIENCES from the merge at handleIdentityToken.ts:95 (make the official app's identifier an explicit per-workspace opt-in setting rather than an implicit default) and require a nonce claim that this server issued for this login, rejecting a token that carries none. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/OAuth2_Cheat_Sheet.md (an identity token is bound to one relying party and one request) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authentication_Cheat_Sheet.md.

### Side effects of the fix

Keeps Apple login and removes only the weakness: a workspace that relies on the official iOS app must list its audience explicitly (a one-line setting change), and app builds that do not send a nonce stop authenticating until they are updated, so the rollout needs the mobile release to land first.

### Detail

see findings


[analysis](findings/VULN-039.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the finding needs Apple-signed identity tokens, which a sealed lab cannot obtain or forge)
- **Confidence**: 4/10
- Exploit directory: `exploits/VULN-039-apple_identity_token_replay/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-039-apple_identity_token_replay/writeup.md](exploits/VULN-039-apple_identity_token_replay/writeup.md)

## VULN-050: Slack bridge binds channels and users by name, so a Slack member posts into a same-named private group as a same-named local user

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the Slack bridge needs a real Slack workspace and outbound access, neither available in a sealed lab) |
| **Confidence** | 4/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N |
| **CWE** | CWE-639, CWE-290 |
| **Category** | Broken access control (room and identity binding by a user-controlled name) |
| **Location** | `targets/rocket.chat/apps/meteor/server/bridges/slack/RocketAdapter.ts:283` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-50: searched Slack bridge private group same name channel mapping security; adjacent only functional name-mapping issues #22218, #28400, #11854, #15361 and the #14273 fix. |
| **Conditional** | yes: SlackBridge_Enabled with a Slack bot token (read leg also SlackBridge_Out_Enabled and SlackBridge_Out_All) |
| **Manual reason** | external-network |
| **Finding key** | `c18193097c2594e7` |

### Impact

Medium (CVSS 4.8): the bridge decides which local room a Slack channel is and which local account a Slack user is by matching names it does not control. An unknown Slack channel is bound to whatever local room shares its name, of any type, so creating a Slack channel called after a private group links the two; an unknown Slack user is bound to the local account with the same email address or, failing that, the same username (bots by username alone), so a Slack bot named admin is attributed to the workspace's administrator. The relay then posts through the library sendMessage, which performs no membership or permission check of its own. A member of the bridged Slack workspace therefore injects messages into Rocket.Chat private groups as colliding local users, and with the broad outbound relay enabled receives those groups' traffic in Slack.

### Remediation

Link only what an administrator mapped: in RocketAdapter.ts bind a Slack channel to a local room through an explicit mapping (refusing p and d rooms unless mapped), link a Slack user only to an account an administrator or that user confirmed (creating a separate bridged account otherwise, never matching on username for bots), and call canSendMessageAsync for the mapped account before relaying a message. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md (resolve objects through what the caller owns, not through an attacker-chosen key) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md.

### Side effects of the fix

Keeps bridging and removes only the weakness: administrators map channels explicitly, Slack users who share a handle with a local account appear as separate bridged accounts rather than being merged, and a bridged post into a room the mapped account may not write to is dropped; existing mappings keep working because they are stored as import ids.

### Detail

see findings


[analysis](findings/VULN-050.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the Slack bridge needs a real Slack workspace and outbound access, neither available in a sealed lab)
- **Confidence**: 4/10
- Exploit directory: `exploits/VULN-050-slack_bridge_name_binding/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-050-slack_bridge_name_binding/writeup.md](exploits/VULN-050-slack_bridge_name_binding/writeup.md)

## VULN-053: IRC bridge mirrors every room, private groups included, to the IRC network and joins any IRC user into the local room of the same name

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | NEEDS_MANUAL (the IRC bridge needs an IRC server to peer with, which this sealed lab does not provide) |
| **Confidence** | 4/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | medium |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N |
| **CWE** | CWE-668, CWE-862 |
| **Category** | Exposure of private rooms to an external network |
| **Location** | `targets/rocket.chat/apps/meteor/server/bridges/irc/irc-bridge/localHandlers/onSaveMessage.js:30` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-53: searched IRC bridge private rooms relayed join channel; no report. The vendor's setting alert ('IRC support is a work in progress. Use on a production system is not recommended at this time.') and the bridge README warn against production use. |
| **Conditional** | yes: IRC_Enabled with a linked IRC server (the vendor marks the bridge not for production) |
| **Manual reason** | external-network |
| **Finding key** | `8aec0eca8ce8396e` |

### Impact

Medium (CVSS 6.5): the bridge treats the IRC side as a peer with the same rights as the workspace. onSaveMessage relays every saved message in a non-direct room to #<room name> on IRC, with no distinction between public channels and private groups, so a private group's traffic is published to the IRC network as it is written. In the other direction, a peer JOIN resolves the local room with Rooms.findOneByName and calls addUserToRoom with no room-type or permission check (creating a public channel if none exists), and a peer PRIVMSG resolves the room the same way and posts through the library sendMessage, which performs no authorization. An IRC user who joins a channel named after a private group therefore reads it and writes into it, with no Rocket.Chat account. The vendor marks the bridge not recommended for production, which is why a human must decide whether this is a vulnerability or an unsupported feature.

### Remediation

Relay only rooms an administrator mapped (public channels by default), never p or d rooms, in onSaveMessage.js:29-36; in joinedChannel.js and sentMessage.js resolve the room through that mapping rather than by name, add an IRC account to a mapped public channel only after canAccessRoom, and require membership before accepting a PRIVMSG. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Deny by Default) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md (never resolve an object by a name the other side controls).

### Side effects of the fix

Keeps IRC bridging of the channels an administrator chooses and removes only the weakness: private groups and direct messages stop being relayed, IRC users can join only mapped public channels, and a peer message naming an unmapped room is dropped, so a deployment that relied on implicit name mirroring must declare its mappings.

### Detail

see findings


[analysis](findings/VULN-053.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the IRC bridge needs an IRC server to peer with, which this sealed lab does not provide)
- **Confidence**: 4/10
- Exploit directory: `exploits/VULN-053-irc_bridge_room_exposure/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-053-irc_bridge_room_exposure/writeup.md](exploits/VULN-053-irc_bridge_room_exposure/writeup.md)

## VULN-008: Room-message stream authorization is never re-evaluated, so a previewer keeps receiving a channel's messages after it is made private

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an open stream subscription kept delivering a room's messages after the room was made private and every new read by the same user was refused) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, default configuration. |
| **Severity** | low |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-863 |
| **Category** | Broken access control (authorization not re-evaluated after revocation) |
| **Location** | `targets/rocket.chat/packages/streamer/src/notifications.module.ts:141` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-08: searched stream subscription persisting after a channel turns private; adjacent only open PR #43528 (delivery-time check for private discussions only) and merged PRs #34922 and #35194 (subscribe-time preview check). |
| **Conditional** | no |
| **Finding key** | `f99dc1bbbe0f53a3` |

### Impact

Low (CVSS 3.1): making a public channel private is the owner's way to shut non-members out, and it does not shut out anyone already subscribed. A previewer who held a stream-room-messages subscription when the change happened keeps receiving every new message in that room for as long as the socket lives, while a fresh subscription from the same account is refused; the same holds when the channel's team becomes private or an administrator revokes preview-c-room from the role. What leaks is live message content of one room, bounded by the socket's lifetime (a reconnect ends it).

### Remediation

Re-evaluate existing room-messages, notify-room and room-data subscriptions when the inputs to canReadRoom change (room type, team type, ABAC attributes, role permissions) and remove those that no longer pass, extending the _afterPublish revocation hook in notifications.module.ts:86-112 beyond the subscriber's own subscription document; or give streamRoomMessage an allowEmit rule that re-checks canReadRoom per delivery with a short per-connection cache instead of leaving it at the default allowEmit('all'). Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Authorization_Cheat_Sheet.md (Validate the Permissions on Every Request) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/WebSocket_Security_Cheat_Sheet.md (message-level authorization).

### Side effects of the fix

Keeps realtime delivery and removes only the weakness: previewers lose the live feed at the moment their access changes rather than at their next reconnect, and a per-delivery check costs one cached permission lookup per message and subscriber (the subscription-removal variant costs nothing per message).

### Detail

see findings


[analysis](findings/VULN-008.md)


### Dynamic validation

- **Status**: CONFIRMED (an open stream subscription kept delivering a room's messages after the room was made private and every new read by the same user was refused)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-008-stale_stream_subscription_after_revocation/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-008-stale_stream_subscription_after_revocation/writeup.md](exploits/VULN-008-stale_stream_subscription_after_revocation/writeup.md)

## VULN-018: /oauth/userinfo accepts expired access tokens for 30 days, because only the REST bearer path checks expires

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an access token past its expiry still returned the account's identity from /oauth/userinfo, while the REST bearer path refused the same token) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, a non-default feature. |
| **Severity** | low |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-672 |
| **Category** | Session management (credential used after expiry) |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/auth/oauth2-server/oauth2-server.ts:61` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-18: searched /oauth/userinfo expired token; adjacent only GHSA-39hg-492f-3c4f / CVE-2026-49277 (tokens surviving deactivation, fixed 8.5.0 by PR #40524, which added findOneActiveById to userinfo but no expiry check). |
| **Conditional** | yes: an administrator-created OAuth app with a relying party that signs users in from /oauth/userinfo |
| **Finding key** | `2f697361c7e96bf4` |

### Impact

Low (CVSS 3.7): a Rocket.Chat-issued OAuth access token keeps identifying its user at /oauth/userinfo after it has expired, until a TTL index removes the record 30 days later. The endpoint returns sub, name, email, email_verified, preferred username and avatar URL, so a leaked expired token (from a log, a browser history, a proxy cache, a mobile app's storage) still yields that user's identity; and a relying party that signs users in from userinfo alone, which is a common pattern, accepts a credential Rocket.Chat itself would refuse on its REST API. The same token is correctly rejected by /api/v1/*, which is what makes this an inconsistency rather than a design choice.

### Remediation

Factor the expiry test out of oAuth2ServerAuth (oauth2-server.ts:41-43) into a shared helper and call it in the /oauth/userinfo handler before resolving the user, so both paths read the same rule; the TTL index on expires should also not be read as a validity window (OAuthAccessTokens.ts:17 keeps records 30 days past expiry for audit, not for use). Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/OAuth2_Cheat_Sheet.md (validate the token, including its lifetime, at every resource server endpoint) and deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Session_Management_Cheat_Sheet.md.

### Side effects of the fix

No change for valid tokens and no feature is removed: a client presenting an expired token gets 401 from userinfo exactly as it already does from the REST API, and must refresh, which every OAuth client already implements.

### Detail

see findings


[analysis](findings/VULN-018.md)


### Dynamic validation

- **Status**: CONFIRMED (an access token past its expiry still returned the account's identity from /oauth/userinfo, while the REST bearer path refused the same token)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-018-oauth_userinfo_expired_token/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-018-oauth_userinfo_expired_token/writeup.md](exploits/VULN-018-oauth_userinfo_expired_token/writeup.md)

## VULN-071: e2e.fetchUsersWaitingForGroupKey takes room ids from the caller without authorizing them, disclosing private rooms' members

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | CONFIRMED (a non-member listed an encrypted private group's waiting members and their keys through a route that authorises no room id) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; needs an account, a non-default feature. |
| **Severity** | low |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-639 |
| **Category** | Object reference not authorized (membership disclosure) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/e2e.ts:368` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | yes |
| **Known status** | known-unpatched |
| **Known evidence** | Fix PR #41953 'fix: check room access in e2e.fetchUsersWaitingForGroupKey' (opened 2026-08-26, open, unmerged) describes this endpoint and root cause; e2e.ts:363-368 unchanged at 9f3d6c8c. No advisory. https://github.com/RocketChat/Rocket.Chat/pull/41953 |
| **Known confidence** | 9/10 |
| **Conditional** | yes: E2E_Enable (end-to-end encryption) enabled |
| **Finding key** | `3f9da425c01cab03` |

### Impact

Low (CVSS 3.1): the route reads roomIds straight from the query string and passes them to an aggregation that matches any subscription whose rid is in that list, excluding only the caller's own. So a user who knows a private room's id receives up to fifty of its members' user ids and end-to-end public keys, without being in the room. Its twin method, e2e.getUsersOfRoomWithoutKey, authorizes the room first with canAccessRoomIdAsync, which shows the intended rule. The disclosure is partial membership (the members still waiting for the room key) rather than content, and it needs the room id, which is why this is Low.

### Remediation

Authorize each requested room before the aggregation: keep only the ids where the caller holds a subscription carrying the room key (or call canAccessRoomIdAsync per id, as getUsersOfRoomWithoutKey.ts:11 does) in e2e.ts:362-370, and let the model method keep its current shape. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md (resolve objects within what the caller may reach).

### Side effects of the fix

Keeps end-to-end key distribution working and removes only the weakness: no first-party client behaviour changes, because the client only ever sends the ids of rooms the user is in; a caller asking about a room it cannot access gets that room omitted from the response.

### Detail

see findings


[analysis](findings/VULN-071.md)


### Dynamic validation

- **Status**: CONFIRMED (a non-member listed an encrypted private group's waiting members and their keys through a route that authorises no room id)
- **Confidence**: 7/10
- Exploit directory: `exploits/VULN-071-e2e_waiting_users_membership_disclosure/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-071-e2e_waiting_users_membership_disclosure/writeup.md](exploits/VULN-071-e2e_waiting_users_membership_disclosure/writeup.md)

## VULN-082: CVE-2025-5892's IRC parser ReDoS is unfixed in this build: the quadratic whitespace expression is unchanged and the proposed fix was never merged

| Field | Value |
|-------|-------|
| **Type** | Known issue |
| **Status** | NEEDS_MANUAL (the IRC parser is only reachable from an IRC peer, which this sealed lab does not provide) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | The mechanism is clear in source; the lab could not complete the trigger, so a person has to finish it. |
| **Severity** | low |
| **CVSS** | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L |
| **CWE** | CWE-1333 |
| **Category** | Denial of service (regular expression complexity, ReDoS) |
| **Location** | `targets/rocket.chat/apps/meteor/server/bridges/irc/servers/RFC2813/parseMessage.js:53` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | known-unpatched |
| **Known evidence** | GHSA-prxp-75xx-3cxw / CVE-2025-5892 (moderate; 'RocketChat up to 7.6.1 ... parseMessage ... inefficient regular expression complexity'); no patched version published; the proposed fix PR #35711 is open and unmerged (GitHub API: state open, merged false); parseMessage.js:52-53 in 9.1.0-develop at 9f3d6c8c still holds the vulnerable expressions, so this version is affected. https://github.com/advisories/GHSA-prxp-75xx-3cxw |
| **Known confidence** | 9/10 |
| **Conditional** | yes: IRC_Enabled with a linked IRC server (the vendor marks the bridge not for production) |
| **Manual reason** | external-network |
| **Finding key** | `8e0d045da53b6a0c` |

### Impact

Low (CVSS 3.7): parseMessage tests each peer line with /^:|\s+:/ and then matches /(.*?)(?:^:|\s+:)(.*)/, and on a line that holds a long run of whitespace with no colon after it the \s+: alternative is retried from every position in the run, which is quadratic in the line's length. The receive loop puts no bound on either the buffer or a line: onReceiveFromPeer appends every chunk, splits on the line terminators, and parses each line, so one line of tens of thousands of spaces blocks Node's single thread for the duration of the backtracking and a stream of them keeps the event loop stalled, stopping the whole workspace rather than only the bridge. This is CVE-2025-5892, for which no patched version exists: the fix PR is still open.

### Remediation

Parse linearly and bound the input. Replace the two expressions at parseMessage.js:52-53 with an indexOf(' :') (plus a leading-colon test) so the trailing parameter is split without backtracking, and enforce RFC 2813's 512-byte limit on both this.receiveBuffer and each line in onReceiveFromPeer (index.js:138-150), discarding anything longer. Grounding: deploy/knowledge/owasp/CheatSheetSeries/cheatsheets/Denial_of_Service_Cheat_Sheet.md (Input validation: bound the size of what a parser is given) with the analysis technique in deploy/knowledge/payloads/PayloadsAllTheThings/Regular Expression/README.md.

### Side effects of the fix

Keeps the IRC bridge and removes only the weakness: a peer line longer than the protocol's own 512-byte limit is dropped instead of parsed, which is what RFC 2813 requires of a conforming implementation, so a non-conforming peer that sends over-long lines would lose those messages. The parser change is behaviour-preserving for every line within the limit.

### Detail

see findings


[analysis](findings/VULN-082.md)


### Dynamic validation

- **Status**: NEEDS_MANUAL (the IRC parser is only reachable from an IRC peer, which this sealed lab does not provide)
- **Confidence**: 5/10
- Exploit directory: `exploits/VULN-082-irc_parser_redos/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`)
- Writeup: [exploits/VULN-082-irc_parser_redos/writeup.md](exploits/VULN-082-irc_parser_redos/writeup.md)

## VULN-063: On a fresh install the REST API has no per-route rate limiting until the server restarts, and changes to the default limit never apply

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (4 ordinary GET routes accepted 25 calls each with the documented limit at 10 per 60000 ms, and lowering the default to 2 changed nothing: the default rule is never registered) |
| **Confidence** | 4/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, default configuration. |
| **Severity** | informational |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N |
| **CWE** | CWE-799 |
| **Category** | Missing rate limiting |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/ApiClass.ts:151` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-63: adjacent PR #13451 ('Restart required to apply changes in API Rate Limiter settings', 2019: the second leg regresses it), issue #13441, open issue #43048 / PR #43050. |
| **Conditional** | no |
| **Finding key** | `b20c417c96a4d6b5` |

### Impact

While it lasts, nothing at the REST layer bounds attempts on any route; administrators' changes to the default limit are ignored.

### Remediation

Read the default limits when a rule is created or checked, keep one shared options object, and store the HTTP method so reloads re-register <route><verb>.

### Side effects of the fix

Keeps the limiter and makes it work as documented; clients over a route's limit get 429 on a fresh install too.

### Detail

Filtered (rate limiting): route limiters are built from a module-load snapshot of the default settings (ApiClass.ts:151-154) and re-registered under '<route>action' names (:504-518), so a fresh install has no per-route REST limits until it restarts and an administrator's change to the default never applies: a regression of PR #13451 (stage 08 R-18). Missing rate limiting is out of scope by policy, but a human may override that here because the product documents the protection as present.


### Dynamic validation

- **Status**: CONFIRMED (4 ordinary GET routes accepted 25 calls each with the documented limit at 10 per 60000 ms, and lowering the default to 2 changed nothing: the default rule is never registered)
- **Confidence**: 4/10
- Exploit directory: `exploits/VULN-063-missing_rest_rate_limiting/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-063-missing_rest_rate_limiting/writeup.md](exploits/VULN-063-missing_rest_rate_limiting/writeup.md)

## VULN-005: Anonymous callers can read the permission-to-role map through the permissions/get method

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (an unauthenticated DDP caller read the whole permission table (993 entries) with the roles that hold each permission) |
| **Confidence** | 3/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, default configuration. |
| **Severity** | informational |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N |
| **CWE** | CWE-200 |
| **Category** | Unauthenticated information disclosure |
| **Location** | `targets/rocket.chat/apps/meteor/server/lib/authorization/streamer/permissions/index.ts:31` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 07 F-05: searched permissions/get unauthenticated disclosure; adjacent only CVE-2022-35247 (getRoomRoles ACL) and CVE-2025-7974 (unspecified unauthenticated disclosure, fixed 7.8.0). |
| **Conditional** | no |
| **Finding key** | `5559c6ee16e04a1c` |

### Impact

An anonymous caller learns which roles hold which permissions and the names of custom roles; no account, data or capability is exposed.

### Remediation

Return an empty list from permissions/get when this.userId is unset, as subscriptions/get does.

### Side effects of the fix

Keeps the method for logged-in clients; anonymous-read clients lose a map they cannot use.

### Detail

Filtered (informational): permissions/get (permissions/index.ts:31-41) answers anonymous DDP and method.callAnon with the whole permission-to-role map, including custom role names, but it names no account, discloses no data and grants no capability, so there is no boundary to cross; subscriptions/get returns an empty list to an anonymous caller, which is the shape this method should have. Kept as a hardening note; a human may re-open it where custom role names are themselves sensitive.


### Dynamic validation

- **Status**: CONFIRMED (an unauthenticated DDP caller read the whole permission table (993 entries) with the roles that hold each permission)
- **Confidence**: 3/10
- Exploit directory: `exploits/VULN-005-anonymous_permission_map/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-005-anonymous_permission_map/writeup.md](exploits/VULN-005-anonymous_permission_map/writeup.md)

## VULN-084: users.register answers Email already exists before it checks whether registration is open, a sibling of the enumeration CVE-2021-22892 closed

| Field | Value |
|-------|-------|
| **Type** | Unique finding |
| **Status** | CONFIRMED (on a workspace with self-registration closed, an anonymous caller distinguishes an address that has an account from one that does not) |
| **Confidence** | 3/10 |
| **Confidence reasoning** | Proven by our own run against the pinned build; unauthenticated, default configuration. |
| **Severity** | informational |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N |
| **CWE** | CWE-204 |
| **Category** | Account enumeration (existence oracle) |
| **Location** | `targets/rocket.chat/apps/meteor/server/api/v1/users.ts:995` |
| **Confirmed** | 2026-11-24 |
| **Auth required** | no |
| **Known status** | novel |
| **Known evidence** | Stage 08 R-10: sibling of GHSA-7v8v-3xwh-j47p / CVE-2021-22892 (HackerOne #1089116; email enumeration, fixed < 3.12.2, 3.11.3, 3.13); no advisory or issue found for the register route. https://github.com/advisories/GHSA-7v8v-3xwh-j47p |
| **Regression of** | CVE-2021-22892 |
| **Conditional** | no |
| **Finding key** | `5331c50de811f2fa` |

### Impact

On deployments that closed self-registration, an anonymous caller learns whether an email or username has an account, at one probe per minute per address.

### Remediation

Check whether registration is open before the availability checks and return one generic answer when it is closed.

### Side effects of the fix

Keeps registration; closed workspaces stop answering availability questions.

### Detail

Filtered (enumeration): users.ts:984-997 answers 'Email already exists' or 'Username is already in use' before registerUser (:1011) refuses a Disabled or Secret URL registration form, so a closed-registration workspace still answers whether an address has an account, at one probe per minute per address. Sibling of CVE-2021-22892; a human may re-open it for SSO-only intranets, where the member list is the sensitive asset.


### Dynamic validation

- **Status**: CONFIRMED (on a workspace with self-registration closed, an anonymous caller distinguishes an address that has an account from one that does not)
- **Confidence**: 3/10
- Exploit directory: `exploits/VULN-084-register_account_enumeration/` (`automation.py`, `request.http`, `response.txt`, `evidence/`, `run.log`, `escalation/`)
- Writeup: [exploits/VULN-084-register_account_enumeration/writeup.md](exploits/VULN-084-register_account_enumeration/writeup.md)
- **Detection**: [`detections/VULN-084.sigma.yml`](detections/VULN-084.sigma.yml) (informational, validated: fired on 2/2 of this exploit's own log lines, silent on 400 clean ones). It sees every refused users.register attempt and its source; not the email address probed, which is in the body.

## Edge cases: real, but only in a particular configuration

- **VULN-002** OAuth account linking by unverified email claim, so an IdP identity melds into any local account with that address: needs `an OAuth login provider enabled (GitHub, Google, GitLab, Apple, or Custom OAuth with the oauth-enterprise module)`
- **VULN-001** IDOR in anonymous Livechat visitor registration: a customer's phone number returns their visitor token, their email rebinds it: needs `Omnichannel in use, so that real visitors with phone numbers or emails exist (the endpoint itself answers with Livechat_enabled off)`
- **VULN-030** Deactivated and pending-approval accounts get working tokens through the OAuth login-code path, which bypasses validateLoginAttempt, and REST never re-checks active: needs `an OAuth login provider enabled (GitHub, Google, GitLab, Apple web, or Custom OAuth with the EE module)`
- **VULN-044** CAS session fixation: the credential token is chosen in the service URL, so a crafted link to the real CAS server hands the victim's account to the attacker: needs `CAS_enabled with CAS_base_url and CAS_login_url pointing at the organisation's CAS server`
- **VULN-048** Omnichannel external frame puts the agent's plaintext session token in the frame URL, and the encryption key the setting promises is a public setting: needs `Omnichannel_External_Frame_Enabled with Omnichannel_External_Frame_URL and _Encryption_JWK set`
- **VULN-031** SAML assertions are not bound to this service provider: no Audience, Recipient, Destination or InResponseTo check, so another SP's assertion logs in: needs `the EE saml-enterprise licence with a SAML provider configured, and an IdP that signs assertions for several service providers with one key`
- **VULN-045** Profanity filter is a per-token, per-word regex scan on the request path, so one member stalls the whole server for seconds per message: needs `Message_AllowBadWordsFilter (the profanity filter) enabled`
- **VULN-046** Anonymous write into any room through livechat/page.visited, which resolves neither the visitor token nor the room: needs `Livechat_Visitor_navigation_as_a_message enabled (with it off, the same request still writes a hidden message into any room)`
- **VULN-047** channels.anonymousread serves Omnichannel conversations and hidden messages to unauthenticated callers, and getRoomRoles skips its access check for them: needs `Accounts_AllowAnonymousRead enabled (main leg also needs Omnichannel in use)`
- **VULN-051** Livechat transcript relays visitor-written HTML from the workspace's own mail address to any recipient the caller names: needs `Livechat_enabled (Omnichannel on) with a room that can be opened`
- **VULN-054** Omnichannel offline form mails visitor fields unescaped to the support mailbox, and the host field lands inside an href: needs `an offline message recipient configured (Livechat_offline_email or a department email)`
- **VULN-055** Missing permission check on retentionOverrideGlobal lets any room owner exempt their room from the retention policy: needs `RetentionPolicy_Enabled for the room's type`
- **VULN-076** Livechat stream access is decided against the room the client names in extraData, so a visitor with one open chat of its own reads any other Livechat room's live messages: needs `Livechat_enabled (Omnichannel on), with the attacker able to open one chat of its own`
- **VULN-077** livechat/visitors.pagesVisited returns navigation messages whole, handing any agent the visitor tokens the GHSA-cqj7 fix stopped visitors.info from disclosing: needs `Livechat_enabled (Omnichannel on)`
- **VULN-019** Improper authentication on /hooks: any integration id and token authenticate, and the add and remove sub-routes skip the enabled and impersonation checks: needs `integrations exist, and the integration's post-as user holds manage-outgoing-integrations or manage-own-outgoing-integrations`
- **VULN-036** Mandatory 2FA for a role is enforced only by the web client, so its members keep single-factor access over REST and DDP: needs `an administrator enabled mandatory 2FA on a role (a security control that is switched on but not enforced server-side)`
- **VULN-037** Pre-registration squatting survives the owner's OAuth claim: the email meld resets the password but keeps the squatter's sessions and personal access tokens: needs `an OAuth login provider enabled, with the victim signing in through it after the attacker registered their address`
- **VULN-049** With message edit history on, deleted and edited-away content stays readable: personal exports include the hidden copies and their files, and chat.getMessage returns them by id: needs `Message_KeepHistory (keep per-message editing history) enabled`
- **VULN-062** Revoking preview-c-room only closes the history and the live stream: ten other message, file and thread routes still serve non-members: needs `an administrator removed preview-c-room from a role (a hardening control switched on but enforced on two read paths only)`
- **VULN-066** Disabling password reset closes only the REST route: Meteor's forgotPassword still mails reset links anonymously and outside the REST limiter: needs `Accounts_PasswordReset turned off (self-service reset disabled, a switch that is then not fully enforced)`
- **VULN-006** stream-apps and stream-importers accept anonymous subscriptions, and the app setting-changed event carries the new value (secrets included): needs `an Apps-Engine app with settings installed, and an administrator changing one of its settings while the attacker is subscribed`
- **VULN-024** Protected file downloads and personal data exports are marked publicly cacheable for a year, so a shared cache serves them to other people: needs `a shared HTTP cache (CDN or caching reverse proxy) in front of the whole workspace that honours Cache-Control`
- **VULN-043** OAuth login skips the second factor for any account inside the registration grace window, even one that has enrolled TOTP: needs `an OAuth login provider enabled`
- **VULN-061** Integration updates and deletes trust the type the caller names, so one integration permission family reaches the other's objects, script included: needs `an administrator delegated one integration permission family to a role that lacks the other`
- **VULN-069** Removing the admin role skips assign-admin-role: users.update replaces the role list with no last-admin guard: needs `an administrator delegated role management without assign-admin-role`
- **VULN-070** autotranslate.translateMessage omits the auto-translate permission its sibling routes and the client require: needs `AutoTranslate_Enabled with a translation provider configured`
- **VULN-081** The Livechat webhook sender and its test route keep ignoreSsrfValidation on, for the same non-admin Omnichannel roles PR #42201 stopped from reaching internal hosts through triggers: needs `Livechat_enabled (Omnichannel on) with a livechat-manager or livechat-monitor account`
- **VULN-013** Email Direct Reply takes the posting identity from the From header, so one spoofed email posts as any user under any message id: needs `Direct_Reply_Enable with an IMAP or POP reply mailbox configured`
- **VULN-038** video-conference.share-chat creates a discussion without the membership and send checks regular discussion creation enforces: needs `a video-conference provider app installed and a call held in the target room`
- **VULN-052** Smarsh compliance export interpolates message text and sender names into the archived HTML unescaped, so a member forges or hides archive entries: needs `Smarsh_Enabled with Smarsh_Email set`
- **VULN-056** postMessage command channels accept any origin: iframe login never checks it, and the iframe integration ships with origin *: needs `Accounts_iframe_enabled, or Iframe_Integration_receive_enable with its origin left at the shipped *`
- **VULN-064** Apps marketplace REST routes have no manage-apps check, so any user obtains a workspace Cloud token with purchase scope: needs `the workspace registered with Rocket.Chat Cloud`
- **VULN-028** Indirect prompt injection in AI Search: other users' messages become instructions, and the answer renders as markdown that fetches attacker URLs: needs `the AI licence module with AI Search enabled and an OpenAI-compatible provider configured`
- **VULN-039** Apple identity tokens are replayable across workspaces, because the audience list always includes the shared official iOS app and no nonce is checked: needs `Apple login enabled (Accounts_OAuth_Apple)`
- **VULN-050** Slack bridge binds channels and users by name, so a Slack member posts into a same-named private group as a same-named local user: needs `SlackBridge_Enabled with a Slack bot token (read leg also SlackBridge_Out_Enabled and SlackBridge_Out_All)`
- **VULN-053** IRC bridge mirrors every room, private groups included, to the IRC network and joins any IRC user into the local room of the same name: needs `IRC_Enabled with a linked IRC server (the vendor marks the bridge not for production)`
- **VULN-018** /oauth/userinfo accepts expired access tokens for 30 days, because only the REST bearer path checks expires: needs `an administrator-created OAuth app with a relying party that signs users in from /oauth/userinfo`
- **VULN-071** e2e.fetchUsersWaitingForGroupKey takes room ids from the caller without authorizing them, disclosing private rooms' members: needs `E2E_Enable (end-to-end encryption) enabled`
- **VULN-082** CVE-2025-5892's IRC parser ReDoS is unfixed in this build: the quadratic whitespace expression is unchanged and the proposed fix was never merged: needs `IRC_Enabled with a linked IRC server (the vendor marks the bridge not for production)`

## Attack chain candidates

Unproven: stage 13 proves each one end to end in `chains/`, or drops it with the reason.

- **Anonymous takeover of Omnichannel customer conversations** (VULN-001 + VULN-076 + VULN-051): Register a visitor with a known customer's phone number to receive that customer's visitor token (VULN-001); or open one chat of your own and subscribe to any other Livechat room's message stream by naming your own room in extraData (VULN-076); with a stolen token, request the victim conversation's transcript to an attacker address (VULN-051). Impact: Unauthenticated read of customer conversations and impersonation of customers, plus delivery of their transcripts to the attacker, wherever Omnichannel is used.
- **Delegated integration role to server code execution** (VULN-061 + VULN-027): A role holding only manage-incoming-integrations rewrites an existing outgoing integration's script through integrations.update type confusion, even via a request that fails validation (VULN-061); the script climbs from the serverFetch Reference to the host Function constructor (VULN-027). Impact: Code execution as the Rocket.Chat server process from a role that was meant to manage webhooks only.
- **Any user weakens the second factor, then guesses into accounts** (VULN-057 + VULN-032 + VULN-007 + VULN-040): Harvest every address and role from users.listByStatus (VULN-007); raise AccountsTwoFactorAuthenticationMaxDelta and the lockout thresholds through statistics.telemetry (VULN-057); guess passwords by email address, which skips the per-user lockout (VULN-032); a wide TOTP window then accepts most codes, and replayed codes stay valid (VULN-040). Impact: Account takeover of password-and-TOTP users, administrators included, starting from an ordinary account.
- **One leaked token becomes permanent account control** (VULN-034 + VULN-004 + VULN-033): Export a victim's resume token through ?loginClient=mobile to a program owning rocketchat:// (VULN-034); read the TOTP seed and backup-code hashes through users.info (VULN-004); keep a DDP socket open so the victim's password change or an admin reset does not end it, and receive the admin-set password in clear (VULN-033). Impact: A one-click token leak turns into durable account control that survives the standard remediation.
- **OAuth email meld into the env-created administrator** (VULN-002 + VULN-043 + VULN-030): With GitLab or a custom OAuth provider enabled, assert the administrator's address from an IdP account without verification (VULN-002); the env-created admin has no second factor, and young accounts skip 2FA on OAuth (VULN-043); a deactivated target is revived because the Passport path mints tokens without checking active (VULN-030). Impact: Administrator takeover of a fresh install that enabled an OAuth provider with unverified addresses.
- **CAS session fixation to persistent takeover** (VULN-044 + VULN-004 + VULN-033): Send a CAS user a link to the genuine CAS server carrying an attacker-chosen credential token and redeem it (VULN-044); read the TOTP seed with the new session (VULN-004); keep the socket alive across the victim's remediation (VULN-033). Impact: Takeover of any CAS user with one click, past Rocket.Chat's second factor, that persists.
- **Unauthenticated workspace outage** (VULN-073 + VULN-074 + VULN-078): Send long brace-led offline-form messages that drive the mailer's quadratic regex (VULN-073), grow the metrics registry with unique method.callAnon paths (VULN-074), and exhaust the shared anonymous rate-limit bucket so nobody can log in through the web client (VULN-078). Impact: A denial of service against every user from an anonymous client, combining CPU, memory and login availability.
- **Same-origin phishing with system authority** (VULN-012 + VULN-021 + VULN-046): Upload an HTML credential form and share its inline link on the workspace origin (VULN-021); announce it with a forged system notice through rooms.mediaConfirm (VULN-012) or, with visitor navigation messages on, a rocket.cat notice posted anonymously into any room (VULN-046). Impact: Credential phishing hosted on, and announced by, the workspace itself.
- **Pre-registered squat survives the owner's arrival** (VULN-042 + VULN-037): Register a future colleague's address with a lure in the display name; the genuine verification mail carries it (VULN-042); after the owner signs in through OAuth, the attacker's sessions and PATs survive the meld (VULN-037). Impact: Hidden, persistent access to a colleague's account from the day they join.
- **Deleted content stays recoverable** (VULN-059 + VULN-049 + VULN-047): Read deleted thread roots through chat.syncThreadsList in the shipped configuration (VULN-059); with message history on, read every deleted and edited-away message through exports and chat.getMessage (VULN-049); with anonymous read on, serve those hidden messages to unauthenticated callers (VULN-047). Impact: Content users deliberately deleted, including credentials pasted by mistake, remains readable by members and, in some configurations, by anyone.
- **A banned member keeps the room** (VULN-009 + VULN-035 + VULN-003): After a ban, keep receiving the room's new messages as notifications and downloading its files (VULN-009); re-enter through a never-expiring invite created while a moderator (VULN-035); keep pushing forged userData and call events to the room's members (VULN-003). Impact: The ban, the moderators' tool to close a room to one person, does not close it.
- **A delegated Omnichannel role becomes the customer, then a standing export channel** (VULN-077 + VULN-081 + VULN-051): An agent holding only view-l-room reads another department's visitor tokens out of the navigation-history endpoint (VULN-077) and uses one to read and post in that conversation as the customer; a livechat-manager points the Livechat webhook at a listener with the SSRF guard still off, so every future conversation is posted there automatically (VULN-081); the transcript route then mails a chosen conversation to an attacker address (VULN-051). Impact: Customer impersonation across departments plus a retrying, log-legitimate export of every future Omnichannel conversation, from two non-admin Omnichannel roles.

## Quick wins

- **VULN-057**: Allow-list the telemetry counter ids in updateStatsCounter.ts (the four the client sends): closes any-user writes to security settings.
- **VULN-001**: Create a new visitor on a token miss instead of merging by phone or email, and project token out of the livechat/visitor response.
- **VULN-027**: Drop jail.setSync('ivm', ivm) and expose serverFetch as a copy-only callback in buildSandbox.ts: closes the sandbox escape.
- **VULN-010**: Add canAccessRoomIdAsync to chat.getDeletedMessages before the trash query.
- **VULN-051**: Assign the escapeHtml result in sendTranscript.ts:164 and enforce Livechatenabletranscript on the route.
- **VULN-055**: Add the missing retentionOverrideGlobal validator (edit-room-retention-policy) to saveRoomSettings.
- **VULN-059**: Add hidden: { $ne: true } to the update queries of chat.syncThreadsList and chat.syncThreadMessages.
- **VULN-076**: Stop validator 3 from swapping the requested room for extraData.rid in roomAccessValidator.compatibility.ts.
- **VULN-004**: Build the self view of services in getFullUserData with the same allow-list /me uses.
- **VULN-026**: Apply the parse-length cap and MessageMaxAllowedSize to attachment descriptions.
- **VULN-078**: Key anonymous method-bridge limits on the client address and leave this.token unset without a header.
- **VULN-012**: Refuse system message types in sendFileMessage as chat.sendMessage already does.
- **VULN-077**: Call canAccessRoomAsync in findVisitedPages and pass projection: { 'navigation.token': 0 }, as findChatHistory already does.
- **VULN-081**: Set ignoreSsrfValidation: false and pass allowList: settings.get('SSRFAllowlist') on both Livechat webhook fetches, as PR #42201 did for triggers.
- **VULN-079**: check(type, String) and check(name, String) at the top of getRoomByTypeAndName, and return error-invalid-room for both no match and no access.
- **VULN-080**: Assign el.textContent instead of el.innerHTML in the composer's componentDidUpdate, and compare against innerText.
- **VULN-075**: Fetch through serverFetch with the guard on in PendingFileImporter.downloadFile, as the sibling import fetch now does.

## Intended behaviour & false positives

| ID | Title | Type | Status | Confidence | Why it is not a vulnerability |
|----|-------|------|--------|------------|-------------------------------|
| VULN-027 | isolated-vm sandbox escape in integration scripts: the isolate is handed the ivm module and a host-function Reference, giving code execution as the server | Unique finding | FAILED (the handles are exposed as the source says, but isolated-vm 6.2.0 refuses every navigation step (get on a function reference, deref, cross-isolate deref, result references), so no host-realm execution is reachable) | 2/10 | see findings |
| VULN-022 | Unintended proxy in /avatar: the decoded request path is interpolated into the provider URL and every upstream header is relayed on the workspace origin | Unique finding | FAILED (the traversal answered HTTP 200 with content-type 'image/svg+xml' and our marker absent) | 3/10 | see findings |
| VULN-080 | The Livechat widget composer writes pasted text back into the page as HTML: DOMPurify guards the emoji path but not componentDidUpdate | Unique finding | FAILED (the paste did not execute (pasted=False, dialogs=[]); the composer path was exercised in a real browser) | 3/10 | see findings |
| VULN-021 | Uploads render inline on the workspace origin under a CSP without sandbox or form-action, and the type deny list matches only the declared string | Unique finding | FAILED (content-type 'text/html', collector hit=False) | 2/10 | see findings |
| VULN-017 | REST takes the client address from a client-supplied X-Real-IP when X-Forwarded-For is absent or HTTP_FORWARDED_COUNT is 0, so per-IP rate limits and the failed-login IP block follow the header | Known issue | INTENDED (behind the reverse proxy the vendor's guide prescribes, the client address comes from the proxy's X-Forwarded-For and a spoofed X-Real-IP does not move the limiter; the vendor documents stripping that header as the proxy's job) | 5/10 | Intended (documented): the vendor's security guidelines state that Rocket.Chat prioritises X-Real-Ip when determining clientAddress and that proxies must ignore that header from end users, so a deployment where it reaches remoteAddressMiddleware.ts:17-40 from a client is a proxy misconfiguration, not a product flaw. One residual for a human: the direct, proxy-less deployment that docs/features/oauth2-server.md:57 recommends has nobody to strip the header. |
| VULN-025 | Integration script functions run with no timeout on the server's main thread | Known issue | FAILED (the script ran for 7.46s with no server-side bound (bystander latency up to 6.63s), but its author is the integration manager who wrote it: filtered as administrator-authored code, as the report has it) | 3/10 | Filtered (administrator-authored code): applySync with no timeout (isolated-vm.ts:17-25) freezes the server on the next webhook call, but only for a script an integration manager wrote, so the actor and the author are the same person; publicly known as issue #18542, open since 2020. The boundary-crossing finding for that same role, the integration sandbox escape, is filed separately. |
| VULN-065 | HEAD requests run the GET handler but are counted under a limiter name that is never registered, so every GET route's rate limit, and per-method parameter validation, is skipped | Unique finding | FAILED (HEAD took 20 calls with 0 refusals against 0 for GET, so the limiter key does ignore HEAD; filtered under the rate-limit rule, and the per-verb validation leg needs a human route by route) | 3/10 | Filtered (rate-limit bypass), with one leg left open: the limiter key is built from the request verb (ApiClass.ts:794-797), so a HEAD request, which Hono routes to the GET handler, matches no rule and escapes every GET route's declared limit. The leg for a human is that per-verb validateParams is looked up by the same verb (:809-819), so a GET handler whose schema is declared per method (livechat/message/:_id, for one) runs on unvalidated query input under HEAD; a HEAD response has no body, so the impact depends on each handler's side effects, route by route. |
| VULN-072 | Turning off personal data export (UserData_EnableDownload) only blocks the download link: users.requestDataDownload and the export cron still build and mail archives | Known issue | FAILED (the archive was built and its link mailed with exports switched off, but the download is refused, so nothing leaves the server: filtered as informational, exactly as the report has it) | 3/10 | Filtered (informational): with UserData_EnableDownload off, users.requestDataDownload and the export cron still build the archive and mail the link, because userDataDownload.ts:57-62 is the only place the switch is read, but that route then refuses the download, so storage and CPU are spent and no data leaves the server. Publicly known as issue #17199, closed by a stale bot without a fix. |
| VULN-083 | The email OTP attempt cap of RCSA-2023-0003 is read before the guess and written after it, so parallel guesses overrun it | Unique finding | FAILED (the race is real in shape (0 parallel guesses evaluated against 0 sequential before the cap), but it needs the victim's password first and widens a five-guess cap on a six-digit code: filtered under the brute-force rule, as the report has i) | 3/10 | Filtered (brute force): EmailCheck.ts:71-101 reads the attempt count, compares the code and runs bcrypt before incrementing, so a parallel burst evaluates more than the five guesses RCSA-2023-0003's cap intends; it still needs the victim's password first and still leaves a six-digit space per issued code. A human may re-open it together with the telemetry-settings increment, which can raise the cap outright. |
| VULN-016 | mailer.unsubscribe accepts any user id together with that user's creation time in milliseconds as the only secret | Unique finding | FAILED (the capability exists but is not reachable: the response is identical for a right and a wrong value, the only secret is a millisecond out of 86,400,000, and the route allowed 40 blind attempts before refusing) | 2/10 | Filtered (brute force): mailer.unsubscribe (mailer.ts:54-72, Users.ts:2250-2262) accepts any user id with that user's createdAt in milliseconds as the only secret, but the guess is blind (the route answers the same either way), capped at one call per minute, and worth only opting a victim out of administrator announcements. Re-open it if createdAt turns out to be exposed by another endpoint, which would make the secret known rather than guessed. |
| VULN-023 | /livechat is served with no CSP even while Omnichannel is disabled, and its embed allowlist is enforced only when a Referer arrives | Unique finding | FAILED (the CSP is genuinely absent from /livechat, but nothing exploitable follows on a default install: X-Frame-Options still blocks cross-origin framing and no parameter of the page is reflected, so there is no injection for the missing policy t) | 2/10 | Filtered (hardening without an exploitable path): livechat.ts:46-75 omits the CSP on a Referer-less request to /livechat and serves the page even while Omnichannel is off, but X-Frame-Options sameorigin still blocks cross-origin framing in the shipped configuration, and the missing CSP needs an injection to matter. Kept as the mitigating control the widget self-XSS finding is missing; the embed-allowlist leg needs Iframe_Restrict_Access turned off, which is a security control and so not a finding. |
| VULN-029 | SAML assertion decryption re-enables the insecure algorithms xml-encryption 4 disables | Unique finding | FAILED (the SAML module is not present on this unlicensed workspace and every malformed assertion answers identically (1 distinct answer(s)), so the re-enabled algorithms expose no oracle: hardening, as the report has it) | 2/10 | Filtered (theoretical, no oracle): Response.ts:245-247 sets disallowDecryptionWithInsecureAlgorithm false, so the SP decrypts the AES-CBC, 3DES and RSA-1_5 payloads xml-encryption 4 refuses by default, but every SAML validation failure ends in the same redirect to / (SAML.ts:515-520, 576-579), so no padding or decryption oracle is exposed and the feature needs the enterprise saml licence. A hardening fix; re-open it if an error-distinguishing path is found. |

## Methodology & scope notes

**Scope.** Source analysed: `targets/rocket.chat/` at commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190` (9.1.0-develop), the Meteor app, its packages (`packages/*`, `ee/packages/*`) and the Livechat widget. Library code in the lab image (Meteor accounts, isolated-vm, bad-words, prom-client) was read only to establish reachability and semantics. Inputs read in full: the manifest and `02_features.md` to `08_cve_regression.md` with the stage 02 feature-class files; stage 07's known-issue cross-check supplied every `known_status` and `known_evidence`.

**What was re-verified, and when.** On 2026-11-24 every finding's cited path was re-read at the pinned commit; where an earlier stage's line range was off, the corrected range is the one in `location` and in `findings/`. Every excerpt in `findings/VULN-NNN.md` is copied from the target by line range and checked against an anchor string, so a stale range fails the build. No request was sent to the lab in this stage.

**How to read statuses.** `CONFIRMED (source-traced: confirmed vulnerability; ...)` means the whole path is unambiguous in source; `CONFIRMED (source-traced: likely vulnerability; ...)` means the code path is clear but the effect depends on runtime behaviour (timing, a browser, a third party, a model) that stage 11 must observe. `NEEDS_MANUAL (...)` means the lab cannot provide the precondition; `manual_reason` names it (`other` is an Enterprise licence module: AI Search, SAML). `FAILED (filtered: ...)` is a Phase 2 filter with its reason in `detail`, overridable by a human; `INTENDED` cites the vendor document. `confirmed_at` stays blank until stage 11 reaches a verdict. Severity is always the CVSS 3.1 band of the vector (the engine enforces it), so several findings an earlier stage called Low are Medium here; where the realistic severity is lower, the finding's Impact says so. Confidence (1-10) scores whether it is a real, reportable vulnerability that matters; conditional findings are real for every deployment that enabled the feature.

**Filters applied (Phase 2).** Admin-only findings were filtered unless they reach code execution or a boundary the vendor treats as one: VULN-027 (sandbox escape), VULN-014 and VULN-075 (run-import file read and SSRF, matching the vendor's own GHSA-6x96 for that permission) and VULN-061/VULN-069 (delegated roles) were kept; VULN-025 was filtered. Brute force and rate limiting: VULN-016, VULN-063, VULN-065 (rate-limit leg) and VULN-083 filtered; VULN-032 kept because it defeats a documented per-account lockout, VULN-078 because the shared bucket is a denial of service. Enumeration: VULN-084 filtered; VULN-079 kept (operator injection that extracts private names without guessing). Theoretical: VULN-029 (no oracle: every SAML failure ends in the same redirect). Informational: VULN-005, VULN-072. Hardening: VULN-023.

**What stage 11 should validate first** (live, no lab change): VULN-057, VULN-001 (disclosure leg), VULN-078, VULN-004, VULN-033, VULN-026, VULN-010, VULN-059, VULN-009, VULN-032, VULN-012, VULN-020, VULN-067, VULN-068. Then the switch-gated ones the console can flip: VULN-045, VULN-046, VULN-047, VULN-049, VULN-051, VULN-054, VULN-055, VULN-062, VULN-066, VULN-036, VULN-076, VULN-077. VULN-073 needs `Livechat_validate_offline_email` off in the sealed lab (no DNS for the MX check) and a V8 timing; VULN-074 needs a memory measurement; VULN-027 should be run early because it decides the only critical. The OAuth-dependent findings (VULN-002, VULN-030, VULN-037, VULN-043) need a GitLab-compatible stand-in IdP served from the attacker container.

**Lab notes.** The workspace is air-gap restricted unless its 10-day grace token is current (manifest, Known issues): after ten days `chat.sendMessage`, `chat.postMessage`, `rooms.mediaConfirm` and `rooms.createDiscussion` refuse with `restricted-workspace` until `rebuild.sh` resets it. Mail goes to Mailpit. Every exploit must restore the settings it changes.

**Expansion (stage 10).** Every one of the 73 real findings was rewritten in place from `report.json`, which is the source the markdown is rendered from: title with the vulnerability class named, severity with its justification, `file:line` under `targets/rocket.chat/` with a 5 to 15 line excerpt, a description of what the code does and what it should do, numbered reproduction steps with the exact URLs, methods, payloads and auth state for the instance in the manifest's Runtime section, the boundary crossed and the trust assumption broken, impact with the CVSS vector read metric by metric, prerequisites, the known-or-novel tier with its evidence, and a fix grounded in the class's OWASP Cheat Sheet with its side effects stated as either removing a feature or removing only the weakness. Every excerpt is copied from the target by line range at build time and the builder fails on a missing file or an out-of-range span, so no excerpt in this report is retyped or paraphrased. Each `findings/` file is checked against the engine's own format and schema checks, and every `deploy/knowledge/` path cited anywhere in the report is checked to exist on disk. The 11 filtered and documented entries were left as one-line `detail` statements in the trailing table and deliberately given no writeup; conditional findings were kept out of that table, because a finding that needs a business feature is real for everyone who enabled it.

**Corrections made during expansion.** Re-reading each cited site changed three things. VULN-080's claim that the CVE-2022-21830 sanitiser was gone was wrong: DOMPurify is still imported in the composer and used on the emoji-insertion path, so the finding is that one of the component's two innerHTML writes skips it; and `shouldComponentUpdate` only allows an update when the value's emptiness flips, which makes a paste into an empty composer the trigger rather than typing, so the reproduction steps were rewritten and the confidence raised from 4 to 5. VULN-081's permissions were pinned down to the two that actually apply (`view-livechat-manager` for setting the URL, held by livechat-manager and livechat-monitor; `view-livechat-webhooks` for the test route, held by livechat-manager), which is what makes the comparison with PR #42201 exact. Several line ranges were narrowed where an earlier stage's span ran past the code that matters.

**Read policy for very large files.** A few of the target's files (the Rooms, Users, Messages and Subscriptions models, `api.ts`, `users.ts`) run to thousands of lines. Those were read by cited method and by caller rather than end to end; every other file behind a finding was read in full, and every excerpt was taken from the file on disk. This is recorded as a `[~]` in the stage checklist rather than claimed as a complete read.

**Execution note.** No sub-agent (`Task`) tool was available in this session, so the 73 rewrites were done serially by one lead rather than one worker per finding, as the operating rules require when the tool is absent. Scratch notes, the per-finding drafts and the builder that produced `report.json`, `findings/` and the rendered markdown are under `audit/rocket.chat/work/10/lead/`; stage 09's are under `work/09/lead/`.

## Human review checklist (triage notes from the report stage)

- **VULN-027**: Run the isolated-vm escape in the lab first: it is the only critical, scored 9.1 on a source reading of isolated-vm's Reference semantics.
- **VULN-073**: Decide High versus Medium from V8 timings of the mailer regex at 50k to 400k characters; the sealed lab needs Livechatvalidateofflineemail turned off for the test (no DNS), which must be stated in the writeup.
- **VULN-074**: Promoted from stage 05's unfiled pointer; measure memory per unique method.callAnon path before confirming, and confirm the promotion itself.
- **VULN-080**: Title and knownevidence were corrected at expansion: DOMPurify is still imported and used on the emoji path, so the defect is the unsanitised componentDidUpdate write; confirm the paste trigger in a real browser (typing does not fire it) before accepting the Medium band.
- **VULN-002**: Needs a GitLab-compatible stand-in IdP in the attacker container; confirm the env-created admin has no second factor at the time of the run.
- **VULN-030**: The REST half can be proven by inserting a stamped token for a deactivated user from the console; the Passport half needs the stand-in IdP.
- **VULN-044**: NEEDSMANUAL (oauth-provider): needs a CAS stand-in over HTTPS with a certificate the app trusts; decide whether to add one to the lab.
- **VULN-053**: Rule on the vendor's not-for-production warning for the IRC bridge: keep as a conditional finding or move to INTENDED.
- **VULN-017**: INTENDED per the vendor's security guidelines; decide whether the direct deployment the OAuth2 server doc recommends (HTTPFORWARDEDCOUNT=0, no proxy) deserves a separate report.
- **VULN-065**: Rate-limit leg filtered; judge the validation-skip leg route by route (GET handlers with object-form validateParams that run on unvalidated input under HEAD).
- **VULN-063**: Filtered as rate limiting; override if a documented protection silently absent on a fresh install should be reported.
- **VULN-014**: Kept over the admin-only filter (run-import, vendor-tracked as issue #42355); confirm the deprioritisation.
- **VULN-075**: Kept over the admin-only filter because the vendor fixed the sibling SSRF for the same permission (GHSA-6x96-99rg-wg67); confirm.
- **VULN-015**: Stage 12 should read the resolution of HackerOne #1701378; if it was closed as informative, the tier becomes known-wontfix.
- **VULN-028**: NEEDSMANUAL (other: AI licence and a model provider); an attacker-container stub can stand in for the provider, not for the licence.
- **VULN-031**: NEEDSMANUAL (other: saml-enterprise licence and a Keycloak realm with two clients sharing the realm key).
- **VULN-039**: NEEDSMANUAL (oauth-provider): Apple-signed identity tokens cannot be produced in the lab.
- **VULN-038**: NEEDSMANUAL (external-network): needs a video-conference provider app from the marketplace.
- **VULN-050**: NEEDSMANUAL (external-network): needs a real Slack workspace.
- **VULN-064**: NEEDSMANUAL (external-network): needs a Cloud-registered workspace to see what the token is worth.
- **VULN-082**: NEEDSMANUAL (external-network): needs an RFC 2813 peer; known-unpatched CVE-2025-5892.
- **VULN-029**: Filtered as theoretical (no decryption oracle); reopen if any SAML error path turns out to be distinguishable.
- **VULN-042**: Content injection into trusted mail without markup: CVSS bands it Medium, realistic severity is Low; decide whether to report.
- **VULN-079**: The vendor-tracker query for getRoomByTypeAndName was cut short by the GitHub search API rate limit; stage 12 should finish it before the novel tier is relied on.
- **VULN-081**: The vendor-tracker query for webhook.test SSRF was cut short by the same rate limit; stage 12 should finish it, and rule on whether a livechat-monitor (who can set the URL but not call the test route) belongs in the finding's auth line.

## Notes

Triage math. Candidates in: 72 provisional ids from stages 02 to 06 (VULN-001 to VULN-072); 28 stage 08 regression items (R-01 to R-28); 3 live legs stage 05 left for this stage; 8 stage 03 candidates (C-1 to C-8); stage 06 register items and stage 04 and 02 pointers. Out: 84 report ids = 72 kept with their provisional numbers + 11 new ids for R-01 to R-11 + 1 new id for the stage 05 metrics leg. Real findings: 73 (1 critical, 10 high, 58 medium, 4 low; 41 conditional). Trailing table: 10 FAILED (filters) and 1 INTENDED. Statuses among real findings: 46 source-traced confirmed, 18 likely, 9 NEEDS_MANUAL.

Ids. The provisional ids from the analysis files are kept unchanged (renumbering would change every id a reader has seen; the format spec says stage 09 re-numbers nothing). Only new candidates received new ids, in severity order: VULN-073 (R-03 mailer ReDoS), VULN-074 (stage 05 metrics label growth), VULN-075 (R-04 pending-file importer SSRF), VULN-076 (R-01 Livechat stream access, CVE-2026-48616), VULN-077 (R-02 pagesVisited tokens, CVE-2026-49278), VULN-078 (R-06 DDP bridge rate-limit key), VULN-079 (R-09 getRoomByTypeAndName, CVE-2022-32226), VULN-080 (R-11 widget composer, CVE-2022-21830), VULN-081 (R-05 Livechat webhook SSRF, PR #42201), VULN-082 (R-08 IRC ReDoS, CVE-2025-5892), VULN-083 (R-07 email OTP race, filtered), VULN-084 (R-10 register enumeration, filtered).

Stage 08 R-12 to R-28 are regressions of existing findings, recorded as regression_of where the parent has a CVE or GHSA: R-12 -> VULN-003 (GHSA-r3v3-v742-55j5), R-13 -> VULN-012 (CVE-2026-106075), R-14 -> VULN-026 (CVE-2024-46935), R-15 -> VULN-039 (CVE-2026-55759), R-16 -> VULN-047 (CVE-2022-35247), R-17 -> VULN-058 (HackerOne #1132202, no CVE: not set), R-18 -> VULN-063 (PR #13451, not set), R-19 -> VULN-070 (CVE-2026-32994), R-20 -> VULN-030 (CVE-2026-45757), R-21 -> VULN-033 (CVE-2023-28316), R-22 -> VULN-064 (CVE-2026-29197), R-23 -> VULN-066 (CVE-2026-75575), R-24 -> VULN-054 (CVE-2026-65644), R-25 -> VULN-051 (PR #36016, not set), R-26 -> VULN-004 (PR #35549, not set), R-27 -> VULN-007 and VULN-067 (CVE-2022-32219), R-28 -> VULN-021 (PR #38106, not set). R-05, R-06, R-07 and R-08 carry regression_of null: their parents (PR #42201, RCSA-2023-0004, RCSA-2023-0003) have no CVE or GHSA, and R-08 is the unfixed CVE-2025-5892 itself (known-unpatched).

Merged or folded (no separate id): stage 03 C-3 (import file name joined unnormalised, getImportFileData.ts:58-62) into VULN-014, same permission and impact; stage 03 C-4 (35-bit invite ids with an anonymous validity oracle) recorded as context in VULN-035 (brute force on its own); stage 05's live thread-root export leg into VULN-059; stage 05's live hidden page.visited write into VULN-046; stage 04's directory workspace=all email oracle into VULN-007's scope. VULN-049 and VULN-059 share a root (soft-deleted copies) but are kept separate: one is conditional on Message_KeepHistory, the other live, and their fixes differ. VULN-060 and VULN-066 share a channel (Meteor's account methods) and one remediation can cover both, but they break different controls. No candidate was marked duplicate.

Candidates not promoted, with the reason: stage 03 C-1 (message search regex passed to Mongo $regex) is the documented Regex search feature, evaluated by MongoDB with its own match limits, no impact shown; C-2 (users.list customFields operator injection) is gated on view-full-other-user-info (admin-level) and filters only user documents; C-5 (Force_SSL redirect to the client-supplied Host) needs Force_SSL plus a plain-HTTP request whose Host the attacker chose, off-path only; C-6 (SAML message ids from Math.random) is theoretical, the login-authorising credentialToken uses Random.id; C-7 (CSV formula injection in the EE app-log export) is app-authored content behind manage-apps; C-8 (validateEmail accepts CR/LF) is neutralised by nodemailer today. Stage 06 register: D17 (experimental login twin, the failed-login block covers both), D20/D21 (admin-level divergences), D22 (room owners set favorite and roomCustomFields, low, matters only with default), D23 (outgoing post-as without message-impersonate, admin-delegated), the push-token update by client-chosen _id, the emoji upload buffered before the permission check, the integrations.remove target_url oracle (admin-level) and the unescaped $regex filename filters (C-1 family) are recorded, not filed. Stage 04 pointers: the E2E updateGroupKey write by a banned member and the notification-level change by a banned member widen VULN-009's family (named there), the room-avatar note and the email-code counter race (filed as VULN-083, filtered) were weighed. Stage 02 lead: the anonymous users.2fa.sendEmailCode mailer (one code per minute per user) is a nuisance, not filed. Stage 08 note on debug-log redaction: logging levels are an operator setting, not filed.

Conditional versus security control. Where a finding needs an administrator to switch a security control on (VULN-036 mandatory 2FA, VULN-062 preview-c-room revoked, VULN-066 password reset turned off), the control is broken, not mis-set, so the finding stays real and conditional. Where a finding needed a security control switched off (VULN-023's framing leg needs Iframe_Restrict_Access off), it was filtered.

Known versus novel among real findings: 61 novel, 12 known-unpatched. Known-wontfix: VULN-017 (INTENDED). Evidence for every known tier is in known_evidence; novel tiers name the searches stage 07 ran.

Expansion (stage 10). No id was added, dropped, renumbered or re-keyed: the 84 entries and their finding keys are stage 09's. What changed: every real finding's `title`, `impact`, `remediation` and `remediation_side_effects` were rewritten, each gained or replaced its `findings/VULN-NNN.md` with `detail` left as the sentinel `see findings`, and the 11 filtered entries' one-line `detail` statements were tightened. Two fields moved on evidence rather than style: VULN-080's `confidence` went from 4 to 5 and its `known_evidence` was corrected (DOMPurify present on the emoji path, absent on the write at issue). Severity, CVSS vector, score, CWE list, `known_status`, `regression_of`, `conditional` and `conditional_on` are unchanged from triage, and the engine re-checks that each severity equals its vector's band. One attack-chain candidate was added (the delegated Omnichannel role chain) and five quick wins; the chains remain hypotheses for stage 13 to prove or drop. Cross-finding links live in the chains and in each writeup's Chain potential section, which describes partner findings by behaviour rather than by id, because a `findings/` file naming another VULN id fails the stage.

## Dynamic validation summary

Every finding in this report was run against the live workspace; the table is the same one in `exploits/README.md`, which links each finding's exploit directory.

| ID | Title | CWE | Severity | Type | Dynamic status | Confidence | Auth required | Writeup |
|----|-------|-----|----------|------|----------------|------------|---------------|---------|
| VULN-027 | isolated-vm sandbox escape in integration scripts: the isolate is handed the ivm module and a host-function Reference, giving code execution as the se | CWE-668, CWE-94 | Critical | Unique finding | FAILED | 2/10 | user | [dir](exploits/VULN-027-isolated_vm_sandbox_escape/) |
| VULN-002 | OAuth account linking by unverified email claim, so an IdP identity melds into any local account with that address | CWE-287, CWE-345 | High | Known issue | CONFIRMED | 9/10 | none | [writeup](exploits/VULN-002-oauth_unverified_email_meld/writeup.md) |
| VULN-057 | statistics.telemetry lets any signed-in user increment any numeric workspace setting, weakening 2FA, lockouts and rate limits | CWE-862, CWE-915 | High | Known issue | CONFIRMED | 9/10 | user | [writeup](exploits/VULN-057-settings_write_via_telemetry/writeup.md) |
| VULN-001 | IDOR in anonymous Livechat visitor registration: a customer's phone number returns their visitor token, their email rebinds it | CWE-639, CWE-200 | High | Unique finding | CONFIRMED | 8/10 | none | [writeup](exploits/VULN-001-livechat_visitor_token_idor/writeup.md) |
| VULN-015 | MFA bypass through the recovery flow: resetPassword and verifyEmail are exempted from the second factor and return a session | CWE-308, CWE-640 | High | Known issue | CONFIRMED | 8/10 | none | [writeup](exploits/VULN-015-mfa_bypass_via_password_reset/writeup.md) |
| VULN-030 | Deactivated and pending-approval accounts get working tokens through the OAuth login-code path, which bypasses validateLoginAttempt, and REST never re | CWE-288, CWE-863 | High | Unique finding | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-030-deactivated_account_oauth_login_code/writeup.md) |
| VULN-073 | Mailer placeholder regex is still quadratic after the CVE-2021-32832 fix, and the anonymous offline form feeds it unbounded text | CWE-1333, CWE-400 | High | Unique finding | CONFIRMED | 8/10 | none | [writeup](exploits/VULN-073-mailer_placeholder_redos/writeup.md) |
| VULN-044 | CAS session fixation: the credential token is chosen in the service URL, so a crafted link to the real CAS server hands the victim's account to the at | CWE-384, CWE-352 | High | Unique finding | NEEDS_MANUAL | 7/10 | none | [writeup](exploits/VULN-044-cas_session_fixation/writeup.md) |
| VULN-048 | Omnichannel external frame puts the agent's plaintext session token in the frame URL, and the encryption key the setting promises is a public setting | CWE-598, CWE-311 | High | Unique finding | NEEDS_MANUAL | 7/10 | none | [writeup](exploits/VULN-048-external_frame_token_in_url/writeup.md) |
| VULN-074 | Unbounded metric label cardinality: method.call samples are labelled with the raw request path, so anonymous requests grow the registry until memory r | CWE-770, CWE-400 | High | Unique finding | CONFIRMED | 7/10 | none | [writeup](exploits/VULN-074-metric_label_cardinality/writeup.md) |
| VULN-031 | SAML assertions are not bound to this service provider: no Audience, Recipient, Destination or InResponseTo check, so another SP's assertion logs in | CWE-345, CWE-287 | High | Unique finding | NEEDS_MANUAL | 5/10 | none | [writeup](exploits/VULN-031-saml_assertion_not_bound_to_sp/writeup.md) |
| VULN-010 | Missing authorization on chat.getDeletedMessages: any user lists the deleted-message ids and timing of any room | CWE-862 | Medium | Known issue | CONFIRMED | 9/10 | user | [writeup](exploits/VULN-010-deleted_message_metadata_disclosure/writeup.md) |
| VULN-003 | Cross-user event injection on notify-room-users: any member forges userData and video-conference events into every other member's private stream | CWE-345, CWE-862 | Medium | Known issue | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-003-realtime_event_injection_notify_room_users/writeup.md) |
| VULN-007 | users.listByStatus leaks every account's email, roles and last login to any ordinary user, and sorts on client-chosen fields before projecting | CWE-359, CWE-203 | Medium | Unique finding | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-007-workspace_pii_disclosure_to_any_user/writeup.md) |
| VULN-009 | Room ban not enforced on the notification and file-download paths, because both match the banned subscription | CWE-863 | Medium | Unique finding | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-009-ban_bypass_notifications_and_files/writeup.md) |
| VULN-012 | Mass assignment in rooms.mediaConfirm: a member sets any message type t, forging system notices that chat.sendMessage refuses | CWE-915, CWE-451 | Medium | Unique finding | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-012-forged_system_messages_via_mediaconfirm/writeup.md) |
| VULN-026 | Workspace-wide denial of service from one message: the markdown parser is super-quadratic and the attachment-description parse has no length cap | CWE-407, CWE-400 | Medium | Unique finding | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-026-markdown_parser_dos/writeup.md) |
| VULN-045 | Profanity filter is a per-token, per-word regex scan on the request path, so one member stalls the whole server for seconds per message | CWE-407, CWE-400 | Medium | Unique finding | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-045-profanity_filter_dos/writeup.md) |
| VULN-046 | Anonymous write into any room through livechat/page.visited, which resolves neither the visitor token nor the room | CWE-862 | Medium | Unique finding | CONFIRMED | 8/10 | none | [writeup](exploits/VULN-046-livechat_page_visited_anonymous_write/writeup.md) |
| VULN-047 | channels.anonymousread serves Omnichannel conversations and hidden messages to unauthenticated callers, and getRoomRoles skips its access check for th | CWE-863 | Medium | Unique finding | CONFIRMED | 8/10 | none | [writeup](exploits/VULN-047-anonymous_read_omnichannel_rooms/writeup.md) |
| VULN-051 | Livechat transcript relays visitor-written HTML from the workspace's own mail address to any recipient the caller names | CWE-116, CWE-441 | Medium | Known issue | CONFIRMED | 8/10 | none | [writeup](exploits/VULN-051-livechat_transcript_html_relay/writeup.md) |
| VULN-054 | Omnichannel offline form mails visitor fields unescaped to the support mailbox, and the host field lands inside an href | CWE-116 | Medium | Unique finding | CONFIRMED | 8/10 | none | [writeup](exploits/VULN-054-offline_form_html_injection/writeup.md) |
| VULN-055 | Missing permission check on retentionOverrideGlobal lets any room owner exempt their room from the retention policy | CWE-862 | Medium | Known issue | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-055-retention_override_without_permission/writeup.md) |
| VULN-058 | Mass assignment in teams.create: the caller's room.extraData is spread into the new room, setting default, featured and other administrative flags | CWE-915 | Medium | Unique finding | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-058-team_room_mass_assignment/writeup.md) |
| VULN-059 | chat.syncThreadsList returns the hidden full copy of a deleted thread root, so members read deleted content on a default install | CWE-212 | Medium | Unique finding | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-059-deleted_thread_root_disclosure/writeup.md) |
| VULN-076 | Livechat stream access is decided against the room the client names in extraData, so a visitor with one open chat of its own reads any other Livechat  | CWE-639, CWE-863 | Medium | Unique finding | CONFIRMED | 8/10 | none | [writeup](exploits/VULN-076-livechat_stream_room_confusion/writeup.md) |
| VULN-077 | livechat/visitors.pagesVisited returns navigation messages whole, handing any agent the visitor tokens the GHSA-cqj7 fix stopped visitors.info from di | CWE-200, CWE-862 | Medium | Unique finding | CONFIRMED | 8/10 | user | [writeup](exploits/VULN-077-visitor_tokens_in_pages_visited/writeup.md) |
| VULN-004 | users.info returns the caller's raw services document, disclosing the TOTP seed and backup-code hashes to any holder of the session | CWE-522, CWE-200 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-004-totp_seed_disclosed_to_session/writeup.md) |
| VULN-011 | Typing indicators accept a room the caller cannot access, because the user-activity write rule only checks the claimed name | CWE-862 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-011-typing_write_into_inaccessible_room/writeup.md) |
| VULN-019 | Improper authentication on /hooks: any integration id and token authenticate, and the add and remove sub-routes skip the enabled and impersonation che | CWE-287, CWE-863 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-019-hooks_integration_token_confusion/writeup.md) |
| VULN-020 | Authorization oracle in roles.addUserToRole: the already-in-role answer precedes the permission check, revealing any user's roles in any room | CWE-203 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-020-role_membership_authorization_oracle/writeup.md) |
| VULN-033 | Password change, reset and remove-other-tokens leave open realtime sessions alive, and an admin-set password is broadcast in clear to them | CWE-1466, CWE-201 | Medium | Unique finding | CONFIRMED | 7/10 | none | [writeup](exploits/VULN-033-realtime_session_survives_revocation/writeup.md) |
| VULN-036 | Mandatory 2FA for a role is enforced only by the web client, so its members keep single-factor access over REST and DDP | CWE-602, CWE-308 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-036-role_mandatory_2fa_client_side/writeup.md) |
| VULN-037 | Pre-registration squatting survives the owner's OAuth claim: the email meld resets the password but keeps the squatter's sessions and personal access  | CWE-283, CWE-1464 | Medium | Unique finding | CONFIRMED | 7/10 | none | [writeup](exploits/VULN-037-pre_registration_squatting_survives_meld/writeup.md) |
| VULN-041 | Star privacy is enforced only in the REST serializer, so the message query and the realtime broadcast disclose who starred what | CWE-359 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-041-star_privacy_bypass/writeup.md) |
| VULN-049 | With message edit history on, deleted and edited-away content stays readable: personal exports include the hidden copies and their files, and chat.get | CWE-212 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-049-deleted_content_via_edit_history/writeup.md) |
| VULN-060 | Meteor's resetPassword and changePassword set any password: the policy is enforced in the browser and on one REST path only | CWE-602, CWE-521 | Medium | Known issue | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-060-password_policy_bypass_via_ddp/writeup.md) |
| VULN-062 | Revoking preview-c-room only closes the history and the live stream: ten other message, file and thread routes still serve non-members | CWE-863 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-062-preview_revocation_alternate_routes/writeup.md) |
| VULN-066 | Disabling password reset closes only the REST route: Meteor's forgotPassword still mails reset links anonymously and outside the REST limiter | CWE-424, CWE-640 | Medium | Unique finding | CONFIRMED | 7/10 | none | [writeup](exploits/VULN-066-forgot_password_ddp_when_disabled/writeup.md) |
| VULN-068 | rooms.bannedUsers returns a room's ban list to any member, while the client shows it only to holders of ban-user | CWE-862 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-068-ban_list_disclosure_to_any_member/writeup.md) |
| VULN-079 | getRoomByTypeAndName passes an untyped method parameter into a Mongo filter, so any user enumerates private-room names by regular expression through i | CWE-943, CWE-204 | Medium | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-079-nosql_operator_room_name_oracle/writeup.md) |
| VULN-006 | stream-apps and stream-importers accept anonymous subscriptions, and the app setting-changed event carries the new value (secrets included) | CWE-200, CWE-862 | Medium | Unique finding | CONFIRMED | 6/10 | none | [writeup](exploits/VULN-006-anonymous_apps_stream_subscription/writeup.md) |
| VULN-014 | External control of a file path in downloadPublicImportFile: any local path is read into the importer, and the error is an existence oracle | CWE-73, CWE-22 | Medium | Known issue | CONFIRMED | 6/10 | user | [writeup](exploits/VULN-014-import_file_path_control/writeup.md) |
| VULN-024 | Protected file downloads and personal data exports are marked publicly cacheable for a year, so a shared cache serves them to other people | CWE-524 | Medium | Unique finding | CONFIRMED | 6/10 | none | [writeup](exploits/VULN-024-protected_files_public_cache/writeup.md) |
| VULN-032 | Account lockout bypass: the per-user failed-login block reads the username as typed, so logins by email or inside a totp envelope are never locked | CWE-307 | Medium | Known issue | CONFIRMED | 6/10 | none | [writeup](exploits/VULN-032-lockout_bypass_by_email/writeup.md) |
| VULN-034 | URL-parameter session handoff: ?loginClient=mobile exports the resume token to the rocketchat:// scheme and ?resumeToken= logs the browser into anothe | CWE-352, CWE-939 | Medium | Unique finding | NEEDS_MANUAL | 6/10 | none | [writeup](exploits/VULN-034-url_parameter_session_handoff/writeup.md) |
| VULN-035 | Room invite links are not revocable by the room's owners, outlive their creator's rights, and their use limit is not consumed atomically | CWE-863, CWE-367 | Medium | Unique finding | CONFIRMED | 6/10 | user | [writeup](exploits/VULN-035-invite_links_unrevocable/writeup.md) |
| VULN-040 | Second-factor codes are not single-use: a TOTP code is replayable inside the window and a backup code can be redeemed twice by concurrent requests | CWE-294, CWE-362 | Medium | Unique finding | CONFIRMED | 6/10 | user | [writeup](exploits/VULN-040-totp_code_replay/writeup.md) |
| VULN-043 | OAuth login skips the second factor for any account inside the registration grace window, even one that has enrolled TOTP | CWE-288, CWE-308 | Medium | Unique finding | CONFIRMED | 6/10 | user | [writeup](exploits/VULN-043-oauth_login_skips_2fa_grace/writeup.md) |
| VULN-061 | Integration updates and deletes trust the type the caller names, so one integration permission family reaches the other's objects, script included | CWE-863 | Medium | Unique finding | CONFIRMED | 6/10 | user | [writeup](exploits/VULN-061-integration_type_confusion/writeup.md) |
| VULN-067 | channels.list sorts on client-chosen fields before projecting, so a join code is recoverable by bisection | CWE-203 | Medium | Unique finding | CONFIRMED | 6/10 | user | [writeup](exploits/VULN-067-join_code_recovery_via_sort_oracle/writeup.md) |
| VULN-069 | Removing the admin role skips assign-admin-role: users.update replaces the role list with no last-admin guard | CWE-269 | Medium | Unique finding | CONFIRMED | 6/10 | user | [writeup](exploits/VULN-069-last_admin_removal/writeup.md) |
| VULN-070 | autotranslate.translateMessage omits the auto-translate permission its sibling routes and the client require | CWE-862 | Medium | Unique finding | CONFIRMED | 6/10 | user | [writeup](exploits/VULN-070-autotranslate_missing_permission/writeup.md) |
| VULN-075 | Pending-file importer fetches export-supplied URLs with Node's raw HTTP client, bypassing the SSRF guard its sibling fetch now uses | CWE-918 | Medium | Unique finding | NEEDS_MANUAL | 6/10 | user | [writeup](exploits/VULN-075-importer_ssrf_raw_http/writeup.md) |
| VULN-078 | The DDP-over-REST bridges key their rate limits on the caller's own X-Auth-Token header, so every header-less anonymous caller shares one bucket and a | CWE-799, CWE-400 | Medium | Unique finding | CONFIRMED | 6/10 | none | [writeup](exploits/VULN-078-ddp_rest_shared_rate_limit_key/writeup.md) |
| VULN-081 | The Livechat webhook sender and its test route keep ignoreSsrfValidation on, for the same non-admin Omnichannel roles PR #42201 stopped from reaching  | CWE-918 | Medium | Unique finding | CONFIRMED | 6/10 | user | [writeup](exploits/VULN-081-livechat_webhook_ssrf/writeup.md) |
| VULN-013 | Email Direct Reply takes the posting identity from the From header, so one spoofed email posts as any user under any message id | CWE-290 | Medium | Unique finding | NEEDS_MANUAL | 5/10 | none | [writeup](exploits/VULN-013-email_direct_reply_spoofing/writeup.md) |
| VULN-038 | video-conference.share-chat creates a discussion without the membership and send checks regular discussion creation enforces | CWE-863 | Medium | Unique finding | NEEDS_MANUAL | 5/10 | user | [writeup](exploits/VULN-038-videoconf_share_chat_authorization/writeup.md) |
| VULN-042 | Attacker-chosen text in the workspace's own registration and reset emails, sent to any address | CWE-451 | Medium | Unique finding | CONFIRMED | 5/10 | none | [writeup](exploits/VULN-042-attacker_text_in_platform_email/writeup.md) |
| VULN-052 | Smarsh compliance export interpolates message text and sender names into the archived HTML unescaped, so a member forges or hides archive entries | CWE-116, CWE-117 | Medium | Unique finding | NEEDS_MANUAL | 5/10 | user | [writeup](exploits/VULN-052-smarsh_export_html_injection/writeup.md) |
| VULN-056 | postMessage command channels accept any origin: iframe login never checks it, and the iframe integration ships with origin * | CWE-346 | Medium | Unique finding | NEEDS_MANUAL | 5/10 | none | [writeup](exploits/VULN-056-postmessage_any_origin/writeup.md) |
| VULN-064 | Apps marketplace REST routes have no manage-apps check, so any user obtains a workspace Cloud token with purchase scope | CWE-862, CWE-522 | Medium | Unique finding | NEEDS_MANUAL | 5/10 | user | [writeup](exploits/VULN-064-marketplace_cloud_token_exposure/writeup.md) |
| VULN-028 | Indirect prompt injection in AI Search: other users' messages become instructions, and the answer renders as markdown that fetches attacker URLs | CWE-1427, CWE-1426 | Medium | Unique finding | NEEDS_MANUAL | 4/10 | user | [writeup](exploits/VULN-028-ai_search_prompt_injection/writeup.md) |
| VULN-039 | Apple identity tokens are replayable across workspaces, because the audience list always includes the shared official iOS app and no nonce is checked | CWE-345, CWE-294 | Medium | Unique finding | NEEDS_MANUAL | 4/10 | none | [writeup](exploits/VULN-039-apple_identity_token_replay/writeup.md) |
| VULN-050 | Slack bridge binds channels and users by name, so a Slack member posts into a same-named private group as a same-named local user | CWE-639, CWE-290 | Medium | Unique finding | NEEDS_MANUAL | 4/10 | none | [writeup](exploits/VULN-050-slack_bridge_name_binding/writeup.md) |
| VULN-053 | IRC bridge mirrors every room, private groups included, to the IRC network and joins any IRC user into the local room of the same name | CWE-668, CWE-862 | Medium | Unique finding | NEEDS_MANUAL | 4/10 | none | [writeup](exploits/VULN-053-irc_bridge_room_exposure/writeup.md) |
| VULN-022 | Unintended proxy in /avatar: the decoded request path is interpolated into the provider URL and every upstream header is relayed on the workspace orig | CWE-441, CWE-116 | Medium | Unique finding | FAILED | 3/10 | none | [dir](exploits/VULN-022-avatar_unintended_proxy/) |
| VULN-080 | The Livechat widget composer writes pasted text back into the page as HTML: DOMPurify guards the emoji path but not componentDidUpdate | CWE-79 | Medium | Unique finding | FAILED | 3/10 | none | [dir](exploits/VULN-080-livechat_widget_paste_xss/) |
| VULN-021 | Uploads render inline on the workspace origin under a CSP without sandbox or form-action, and the type deny list matches only the declared string | CWE-693, CWE-184 | Medium | Unique finding | FAILED | 2/10 | user | [dir](exploits/VULN-021-uploads_inline_same_origin/) |
| VULN-008 | Room-message stream authorization is never re-evaluated, so a previewer keeps receiving a channel's messages after it is made private | CWE-863 | Low | Unique finding | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-008-stale_stream_subscription_after_revocation/writeup.md) |
| VULN-018 | /oauth/userinfo accepts expired access tokens for 30 days, because only the REST bearer path checks expires | CWE-672 | Low | Unique finding | CONFIRMED | 7/10 | none | [writeup](exploits/VULN-018-oauth_userinfo_expired_token/writeup.md) |
| VULN-071 | e2e.fetchUsersWaitingForGroupKey takes room ids from the caller without authorizing them, disclosing private rooms' members | CWE-639 | Low | Known issue | CONFIRMED | 7/10 | user | [writeup](exploits/VULN-071-e2e_waiting_users_membership_disclosure/writeup.md) |
| VULN-082 | CVE-2025-5892's IRC parser ReDoS is unfixed in this build: the quadratic whitespace expression is unchanged and the proposed fix was never merged | CWE-1333 | Low | Known issue | NEEDS_MANUAL | 5/10 | none | [writeup](exploits/VULN-082-irc_parser_redos/writeup.md) |
| VULN-017 | REST takes the client address from a client-supplied X-Real-IP when X-Forwarded-For is absent or HTTP_FORWARDED_COUNT is 0, so per-IP rate limits and  | CWE-348 | Info | Known issue | INTENDED | 5/10 | none | [writeup](exploits/VULN-017-client_address_from_x_real_ip/writeup.md) |
| VULN-063 | On a fresh install the REST API has no per-route rate limiting until the server restarts, and changes to the default limit never apply | CWE-799 | Info | Unique finding | CONFIRMED | 4/10 | none | [writeup](exploits/VULN-063-missing_rest_rate_limiting/writeup.md) |
| VULN-005 | Anonymous callers can read the permission-to-role map through the permissions/get method | CWE-200 | Info | Unique finding | CONFIRMED | 3/10 | none | [writeup](exploits/VULN-005-anonymous_permission_map/writeup.md) |
| VULN-025 | Integration script functions run with no timeout on the server's main thread | CWE-400 | Info | Known issue | FAILED | 3/10 | user | [dir](exploits/VULN-025-integration_script_no_timeout/) |
| VULN-065 | HEAD requests run the GET handler but are counted under a limiter name that is never registered, so every GET route's rate limit, and per-method param | CWE-799, CWE-650 | Info | Unique finding | FAILED | 3/10 | none | [dir](exploits/VULN-065-head_request_rate_limit_bypass/) |
| VULN-072 | Turning off personal data export (UserData_EnableDownload) only blocks the download link: users.requestDataDownload and the export cron still build an | CWE-424 | Info | Known issue | FAILED | 3/10 | user | [dir](exploits/VULN-072-data_export_switch_bypass/) |
| VULN-083 | The email OTP attempt cap of RCSA-2023-0003 is read before the guess and written after it, so parallel guesses overrun it | CWE-367, CWE-307 | Info | Unique finding | FAILED | 3/10 | none | [dir](exploits/VULN-083-email_otp_attempt_race/) |
| VULN-084 | users.register answers Email already exists before it checks whether registration is open, a sibling of the enumeration CVE-2021-22892 closed | CWE-204 | Info | Unique finding | CONFIRMED | 3/10 | none | [writeup](exploits/VULN-084-register_account_enumeration/writeup.md) |
| VULN-016 | mailer.unsubscribe accepts any user id together with that user's creation time in milliseconds as the only secret | CWE-340 | Info | Unique finding | FAILED | 2/10 | user | [dir](exploits/VULN-016-mailer_unsubscribe_timestamp_token/) |
| VULN-023 | /livechat is served with no CSP even while Omnichannel is disabled, and its embed allowlist is enforced only when a Referer arrives | CWE-693 | Info | Unique finding | FAILED | 2/10 | none | [dir](exploits/VULN-023-livechat_missing_csp/) |
| VULN-029 | SAML assertion decryption re-enables the insecure algorithms xml-encryption 4 disables | CWE-327 | Info | Unique finding | FAILED | 2/10 | none | [dir](exploits/VULN-029-saml_insecure_decryption_algorithms/) |

## Detection

Blue Spider wrote a Sigma rule for every CONFIRMED finding whose attack is visible in an access log, and validated each against the log lines the lab wrote while the exploit ran and against 400 lines of the same workspace used legitimately. The rules, their positive and clean sets and the verbatim verdicts are in [`detections/`](detections/README.md); the log source is the lab's reverse-proxy access log (the application writes no per-request line at its shipped `Log_Level` of 0).

| Finding | Rule | Level | Verdict | Positives | Clean set | pySigma |
|---------|------|-------|---------|-----------|-----------|---------|
| VULN-001 | [`VULN-001.sigma.yml`](detections/VULN-001.sigma.yml) | high | **CONFIRMED** | 6/6 fired | 0/400 fired | valid |
| VULN-007 | [`VULN-007.sigma.yml`](detections/VULN-007.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| VULN-010 | [`VULN-010.sigma.yml`](detections/VULN-010.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| VULN-014 | [`VULN-014.sigma.yml`](detections/VULN-014.sigma.yml) | medium | **CONFIRMED** | 6/6 fired | 0/400 fired | valid |
| VULN-019 | [`VULN-019.sigma.yml`](detections/VULN-019.sigma.yml) | medium | **CONFIRMED** | 3/3 fired | 0/400 fired | valid |
| VULN-020 | [`VULN-020.sigma.yml`](detections/VULN-020.sigma.yml) | medium | **CONFIRMED** | 4/4 fired | 0/400 fired | valid |
| VULN-041 | [`VULN-041.sigma.yml`](detections/VULN-041.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| VULN-046 | [`VULN-046.sigma.yml`](detections/VULN-046.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| VULN-047 | [`VULN-047.sigma.yml`](detections/VULN-047.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| VULN-051 | [`VULN-051.sigma.yml`](detections/VULN-051.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| VULN-054 | [`VULN-054.sigma.yml`](detections/VULN-054.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| VULN-059 | [`VULN-059.sigma.yml`](detections/VULN-059.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| VULN-060 | [`VULN-060.sigma.yml`](detections/VULN-060.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| VULN-066 | [`VULN-066.sigma.yml`](detections/VULN-066.sigma.yml) | medium | **CONFIRMED** | 9/9 fired | 0/400 fired | valid |
| VULN-067 | [`VULN-067.sigma.yml`](detections/VULN-067.sigma.yml) | medium | **CONFIRMED** | 60/60 fired | 0/400 fired | valid |
| VULN-073 | [`VULN-073.sigma.yml`](detections/VULN-073.sigma.yml) | high | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| VULN-074 | [`VULN-074.sigma.yml`](detections/VULN-074.sigma.yml) | high | **CONFIRMED** | 300/300 fired | 0/400 fired | valid |
| VULN-077 | [`VULN-077.sigma.yml`](detections/VULN-077.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| VULN-081 | [`VULN-081.sigma.yml`](detections/VULN-081.sigma.yml) | medium | **CONFIRMED** | 3/3 fired | 0/400 fired | valid |
| VULN-084 | [`VULN-084.sigma.yml`](detections/VULN-084.sigma.yml) | informational | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |

The other 37 CONFIRMED findings get no rule: the request they send is identical to what this workspace's own client sends, and what distinguishes the attack is in the JSON body, in a header, in the response, or inside a `/websocket` session. [`detections/index.json`](detections/index.json) lists each one with the line the lab logged and the log source that would see it; `Log_Level 1`, `LOG_REST_PAYLOAD=true` and `Log_Trace_Methods` would cover most of them and none is on by default.

## Counts
- Confirmed: 57
- Needs manual: 15
- Failed: 11
- Intended: 1
- Total findings validated: 84

### Chain leads noticed while validating (for the chaining stage)

These crossed my path while each finding was being proven on its own; none is written into a
single finding's writeup, where cross-references do not belong.

- VULN-007 hands any account every address in the workspace, which is the input VULN-032's
  lockout bypass and VULN-042's platform mail both need (a victim's address), and VULN-002's
  meld needs (the address to assert).
- VULN-002 produces an administrator session; VULN-057 produces a security-setting write from an
  ordinary one. Either one reaching the other's starting point is worth composing.
- VULN-015 and VULN-066 are the same recovery flow from two ends: VULN-066 gets reset mail sent on
  a workspace that disabled resets, VULN-015 turns a reset into a session with no second factor.
- VULN-001 and VULN-077 both end in a customer's Livechat token; VULN-076 reads the conversation
  without one. A chain through any of the three ends in the same impersonation.
- VULN-010 and VULN-079 are id and name oracles for rooms the caller cannot see, which is what
  VULN-062, VULN-059 and VULN-071 need to be pointed at a specific private room.
- VULN-019 installs an exfiltration channel from a revoked credential, and VULN-061 reaches
  another permission family's integrations: both end at an integration an operator believes is gone.

## Human review checklist

- [VULN-001](exploits/VULN-001-livechat_visitor_token_idor/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-002](exploits/VULN-002-oauth_unverified_email_meld/writeup.md) - CONFIRMED, 9/10, `automation.py` runnable
- [VULN-003](exploits/VULN-003-realtime_event_injection_notify_room_users/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-004](exploits/VULN-004-totp_seed_disclosed_to_session/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-005](exploits/VULN-005-anonymous_permission_map/writeup.md) - CONFIRMED, 3/10, `automation.py` runnable
- [VULN-006](exploits/VULN-006-anonymous_apps_stream_subscription/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-007](exploits/VULN-007-workspace_pii_disclosure_to_any_user/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-008](exploits/VULN-008-stale_stream_subscription_after_revocation/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-009](exploits/VULN-009-ban_bypass_notifications_and_files/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-010](exploits/VULN-010-deleted_message_metadata_disclosure/writeup.md) - CONFIRMED, 9/10, `automation.py` runnable
- [VULN-011](exploits/VULN-011-typing_write_into_inaccessible_room/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-012](exploits/VULN-012-forged_system_messages_via_mediaconfirm/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-013](exploits/VULN-013-email_direct_reply_spoofing/writeup.md) - NEEDS_MANUAL, 5/10, needs a person
- [VULN-014](exploits/VULN-014-import_file_path_control/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-015](exploits/VULN-015-mfa_bypass_via_password_reset/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-016](exploits/VULN-016-mailer_unsubscribe_timestamp_token/writeup.md) - FAILED, 2/10, disproved in the lab
- [VULN-017](exploits/VULN-017-client_address_from_x_real_ip/writeup.md) - INTENDED, 5/10, documented behaviour
- [VULN-018](exploits/VULN-018-oauth_userinfo_expired_token/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-019](exploits/VULN-019-hooks_integration_token_confusion/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-020](exploits/VULN-020-role_membership_authorization_oracle/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-021](exploits/VULN-021-uploads_inline_same_origin/writeup.md) - FAILED, 2/10, disproved in the lab
- [VULN-022](exploits/VULN-022-avatar_unintended_proxy/writeup.md) - FAILED, 3/10, disproved in the lab
- [VULN-023](exploits/VULN-023-livechat_missing_csp/writeup.md) - FAILED, 2/10, disproved in the lab
- [VULN-024](exploits/VULN-024-protected_files_public_cache/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-025](exploits/VULN-025-integration_script_no_timeout/writeup.md) - FAILED, 3/10, disproved in the lab
- [VULN-026](exploits/VULN-026-markdown_parser_dos/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-027](exploits/VULN-027-isolated_vm_sandbox_escape/writeup.md) - FAILED, 2/10, disproved in the lab
- [VULN-028](exploits/VULN-028-ai_search_prompt_injection/writeup.md) - NEEDS_MANUAL, 4/10, needs a person
- [VULN-029](exploits/VULN-029-saml_insecure_decryption_algorithms/writeup.md) - FAILED, 2/10, disproved in the lab
- [VULN-030](exploits/VULN-030-deactivated_account_oauth_login_code/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-031](exploits/VULN-031-saml_assertion_not_bound_to_sp/writeup.md) - NEEDS_MANUAL, 5/10, needs a person
- [VULN-032](exploits/VULN-032-lockout_bypass_by_email/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-033](exploits/VULN-033-realtime_session_survives_revocation/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-034](exploits/VULN-034-url_parameter_session_handoff/writeup.md) - NEEDS_MANUAL, 6/10, needs a person
- [VULN-035](exploits/VULN-035-invite_links_unrevocable/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-036](exploits/VULN-036-role_mandatory_2fa_client_side/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-037](exploits/VULN-037-pre_registration_squatting_survives_meld/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-038](exploits/VULN-038-videoconf_share_chat_authorization/writeup.md) - NEEDS_MANUAL, 5/10, needs a person
- [VULN-039](exploits/VULN-039-apple_identity_token_replay/writeup.md) - NEEDS_MANUAL, 4/10, needs a person
- [VULN-040](exploits/VULN-040-totp_code_replay/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-041](exploits/VULN-041-star_privacy_bypass/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-042](exploits/VULN-042-attacker_text_in_platform_email/writeup.md) - CONFIRMED, 5/10, `automation.py` runnable
- [VULN-043](exploits/VULN-043-oauth_login_skips_2fa_grace/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-044](exploits/VULN-044-cas_session_fixation/writeup.md) - NEEDS_MANUAL, 7/10, needs a person
- [VULN-045](exploits/VULN-045-profanity_filter_dos/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-046](exploits/VULN-046-livechat_page_visited_anonymous_write/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-047](exploits/VULN-047-anonymous_read_omnichannel_rooms/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-048](exploits/VULN-048-external_frame_token_in_url/writeup.md) - NEEDS_MANUAL, 7/10, needs a person
- [VULN-049](exploits/VULN-049-deleted_content_via_edit_history/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-050](exploits/VULN-050-slack_bridge_name_binding/writeup.md) - NEEDS_MANUAL, 4/10, needs a person
- [VULN-051](exploits/VULN-051-livechat_transcript_html_relay/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-052](exploits/VULN-052-smarsh_export_html_injection/writeup.md) - NEEDS_MANUAL, 5/10, needs a person
- [VULN-053](exploits/VULN-053-irc_bridge_room_exposure/writeup.md) - NEEDS_MANUAL, 4/10, needs a person
- [VULN-054](exploits/VULN-054-offline_form_html_injection/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-055](exploits/VULN-055-retention_override_without_permission/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-056](exploits/VULN-056-postmessage_any_origin/writeup.md) - NEEDS_MANUAL, 5/10, needs a person
- [VULN-057](exploits/VULN-057-settings_write_via_telemetry/writeup.md) - CONFIRMED, 9/10, `automation.py` runnable
- [VULN-058](exploits/VULN-058-team_room_mass_assignment/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-059](exploits/VULN-059-deleted_thread_root_disclosure/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-060](exploits/VULN-060-password_policy_bypass_via_ddp/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-061](exploits/VULN-061-integration_type_confusion/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-062](exploits/VULN-062-preview_revocation_alternate_routes/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-063](exploits/VULN-063-missing_rest_rate_limiting/writeup.md) - CONFIRMED, 4/10, `automation.py` runnable
- [VULN-064](exploits/VULN-064-marketplace_cloud_token_exposure/writeup.md) - NEEDS_MANUAL, 5/10, needs a person
- [VULN-065](exploits/VULN-065-head_request_rate_limit_bypass/writeup.md) - FAILED, 3/10, disproved in the lab
- [VULN-066](exploits/VULN-066-forgot_password_ddp_when_disabled/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-067](exploits/VULN-067-join_code_recovery_via_sort_oracle/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-068](exploits/VULN-068-ban_list_disclosure_to_any_member/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-069](exploits/VULN-069-last_admin_removal/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-070](exploits/VULN-070-autotranslate_missing_permission/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-071](exploits/VULN-071-e2e_waiting_users_membership_disclosure/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-072](exploits/VULN-072-data_export_switch_bypass/writeup.md) - FAILED, 3/10, disproved in the lab
- [VULN-073](exploits/VULN-073-mailer_placeholder_redos/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-074](exploits/VULN-074-metric_label_cardinality/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-075](exploits/VULN-075-importer_ssrf_raw_http/writeup.md) - NEEDS_MANUAL, 6/10, needs a person
- [VULN-076](exploits/VULN-076-livechat_stream_room_confusion/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-077](exploits/VULN-077-visitor_tokens_in_pages_visited/writeup.md) - CONFIRMED, 8/10, `automation.py` runnable
- [VULN-078](exploits/VULN-078-ddp_rest_shared_rate_limit_key/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-079](exploits/VULN-079-nosql_operator_room_name_oracle/writeup.md) - CONFIRMED, 7/10, `automation.py` runnable
- [VULN-080](exploits/VULN-080-livechat_widget_paste_xss/writeup.md) - FAILED, 3/10, disproved in the lab
- [VULN-081](exploits/VULN-081-livechat_webhook_ssrf/writeup.md) - CONFIRMED, 6/10, `automation.py` runnable
- [VULN-082](exploits/VULN-082-irc_parser_redos/writeup.md) - NEEDS_MANUAL, 5/10, needs a person
- [VULN-083](exploits/VULN-083-email_otp_attempt_race/writeup.md) - FAILED, 3/10, disproved in the lab
- [VULN-084](exploits/VULN-084-register_account_enumeration/writeup.md) - CONFIRMED, 3/10, `automation.py` runnable

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
