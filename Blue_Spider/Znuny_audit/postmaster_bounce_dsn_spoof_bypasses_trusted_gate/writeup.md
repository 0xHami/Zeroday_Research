# VULN-019 — Bounce-detection spoofing bypasses the trusted gate

| | |
|---|---|
| **ID** | VULN-019 (raw ZN-034) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **5.3** — `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L` |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: none (email) |
| **Attacker gains** | Forges a "failed to send" transmission-error (with attacker text) on any agent article whose Message-ID is known, from untrusted mail. |

## Summary
Znuny's bounce detector runs as a PreFilterModule — *after* the Trusted header strip — so the
`X-OTRS-Bounce-*` values it derives from an attacker-controlled DSN body are honoured even for
untrusted mail. The bounce follow-up then targets a ticket/article by the attacker-supplied
*original* Message-ID with no sender check. Confirmed: a synthetic, untrusted DSN forged a
transmission send-error (with attacker error text) on a legitimately-sent agent article.

## How it works (mechanism & code trace)
**Ordering (the crux).** `Kernel/System/PostMaster.pm` strips `X-OTRS-*` at `:581` (when
untrusted) *before* running PreFilterModules (`:153/:161`). The bounce detector is a PreFilter, so
it runs after the strip and re-introduces `X-OTRS-Bounce-*`:
```perl
# Kernel/System/PostMaster/Filter/DetectBounceEmail.pm
59-68:  # Sisimai parses the DSN; on a bounce it sets in %GetParam:
#   X-OTRS-Bounce=1, X-OTRS-Bounce-OriginalMessageID=<from embedded message/rfc822>,
#   X-OTRS-Bounce-ErrorMessage=<raw body text>
```
**Follow-up targeting trusts the attacker Message-ID:**
```perl
# Kernel/System/PostMaster/FollowUpCheck/BounceEmail.pm
55-57:  my %Article = ...->ArticleGetByMessageID( MessageID => $X-OTRS-Bounce-OriginalMessageID );  # no sender check
68-73:  ...->_SetArticleTransmissionSendError( ArticleID => $Article{ArticleID}, ... );  return $Article{TicketID};
```
Both `DetectBounceEmail` (PreFilter) and `BounceEmail` (follow-up, order `0000`) ship `Valid=1`.
Dynamic proof: an untrusted DSN bouncing `<sent-…@localhost>` produced a row in
`article_data_mime_send_error` for that article with the attacker's error text.

## Why it is a vulnerability
A delivery-status notification is meant to reflect a *real* delivery failure of a message the
system actually sent. Here the system accepts a forged DSN from anyone: it does not verify that the
DSN corresponds to a message it emitted to that bounce sender, and it takes the "original
message-id" and error text straight from attacker-controlled content. This lets an attacker (1)
mark a genuine agent reply as failed-to-send (misleading agents into thinking a customer never
received a reply, or hiding correspondence) and (2) reach arbitrary tickets even from untrusted
accounts, because the bounce path re-introduces `X-OTRS-*` semantics past the trust strip. The
`AC:H` reflects that the DSN must be crafted so the vendored Sisimai classifies it as a bounce.
It is a spoofing/authenticity defect, not intended behaviour.

## Reproduction
1. Create a ticket with an outbound (agent, Email channel) article carrying a known Message-ID.
2. Feed a synthetic multipart/report DSN whose `message/rfc822` part has that Message-ID and whose
text part is attacker error text, via `Maint::PostMaster::Read --untrusted`. 3. `./run.sh`:
```
[PROOF] forged send-error record on the victim article: [[102, '<sent-…@localhost>', 'ATTACKER-ERROR-… …']]
```

## Impact
Untrusted-origin forgery of transmission-status (integrity), attacker-controlled error text stored
against a real article, and arbitrary-ticket reach past the trust gate. Lower impact than VULN-006
(status write, not article-body injection); chains with VULN-003/006 for mail-borne ticket abuse.

## Suggested fix
Verify the DSN corresponds to a message the system actually sent to the bounce sender (e.g. a
signed bounce token / VERP return-path the system controls); never accept original-message-id or
error text from body content alone; and ensure bounce-derived `X-OTRS-*` values are subject to the
same trust decision as other `X-OTRS-*` headers.

## References
- OWASP authenticity/spoofing guidance. CWE-345 (Insufficient Verification of Data Authenticity).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Web search `OTRS "X-OTRS-" headers trusted email spoofing vulnerability CVE postmaster` and `OTRS security advisory X-OTRS header injection ... OSA` — nothing on bounce/DSN handling; only CVE-2020-1765, CVE-2021-36093, CVE-2023-38060
2. NVD API keyword pull for "Znuny"/"OTRS" grepped for bounce / DSN / Sisimai — only CVE-2020-1765 (From spoofing in the agent *AgentTicketBounce* screen)
3. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB, Debian tracker reviewed — no bounce-detection advisory
4. `gh search issues --repo znuny/Znuny "Bounce"` — only functional/performance issues (#391 Sisimai too slow, #24 Update Sisimai, #440, #764)
5. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2020-1765 / OSA-2020-01 — spoofable From fields in agent compose/forward/bounce screens; agent-side, not inbound DSN parsing
- CVE-2021-36093 / OSA-2021-16 — crafted e-mail stalls PostMaster filter processing (DoS); same pipeline, different defect

**Reasoning:** `DetectBounceEmail` (Sisimai-based PreFilter) and the `BounceEmail` follow-up check are Znuny-specific additions with no OTRS/OSA lineage, and no ZSA, CVE, GHSA or issue describes the PreFilter re-introducing `X-OTRS-Bounce-*` after the untrusted-header strip or the unauthenticated `ArticleGetByMessageID` targeting. The mail-ingestion area is actively researched (two Znuny e-mail advisories in 2024), so a private report is possible, but nothing public matches.
