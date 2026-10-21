# VULN-031 — Extra PostMaster follow-up detectors broaden the unauth arbitrary-ticket injection

| | |
|---|---|
| **ID** | VULN-031 (raw ZN-045) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium (when enabled) · CVSS 3.1 **6.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: none (email) · off by default |
| **Attacker gains** | Removes VULN-006's subject-tag constraint — the ticket number may appear anywhere in the body/raw message/attachment. |

## Summary
Enabling any of the optional follow-up detectors (Body / RawEmail / Attachments /
ExternalTicketNumberRecognition) lets the ticket number match beyond the subject. With the Body
detector on, an unauthenticated email whose subject does **not** reference the ticket still gets
appended to it by mentioning the number in the body. Confirmed live.

## How it works (mechanism & code trace)
The Body detector scans the message body for a ticket number:
```perl
# Kernel/System/PostMaster/FollowUpCheck/Body.pm
46:  my $Tn = ...->GetTNByString( $Self->{ParserObject}->GetMessageBody() );
```
and feeds the same missing-sender-authz append sink as VULN-006 (`FollowUp.pm:585-599`,
`TicketCheckNumber` existence-only). Registrations `Ticket.xml:12478-12513` ship all four extra
detectors `Valid=0`. `GetTNByString` (DateChecksum) requires the hook form `Ticket#<tn>`. Dynamic
proof: with `PostMaster::CheckFollowUpModule###0300-Body` enabled, an email with an unrelated
subject but `Ticket#<victim tn>` in the body appended the attacker's article (count 1→2).

## Why it is a vulnerability
Same defect class as VULN-006 (follow-up authorises the ticket number, not the sender). The extra
detectors widen the attacker's control: they no longer need to shape the subject, and the
Attachments/RawEmail variants match content the sender fully controls, so a benign-looking email
can smuggle the target ticket number. Each detector is one SysConfig flip an admin might enable for
convenience (e.g. matching numbers quoted in replies), unknowingly broadening the unauthenticated
injection surface.

## Reproduction
1. `Admin::Config::Update --setting-name 'PostMaster::CheckFollowUpModule###0300-Body' --valid 1`.
2. Feed an unauthenticated email with `Ticket#<tn>` only in the body. `./run.sh` proof:
```
[PROOF] body-matched injected article on victim: True (count 1->2)
```

## Impact
Broadens VULN-006 to body/raw/attachment matching (integrity/availability on arbitrary tickets),
lowering the bar for the unauthenticated injection. Conditional on the non-default detector(s).

## Suggested fix
The sender-authorisation fix for VULN-006 closes all of these at once; independently, treat
body/attachment-derived ticket numbers as even lower-trust and never as authorisation.

## References
- Same as VULN-006 (CWE-862).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 40 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Web search `OTRS Znuny follow-up email ticket number subject unauthenticated append article arbitrary ticket vulnerability CVE` — no CVE; community threads and unrelated ZSA-2021-09 / CVE-2025-26842
2. Web search `OTRS "follow-up" sender not verified ticket number spoofing security advisory reopen closed ticket email` — only CVE-2020-1765/1767
3. NVD API keyword pull for "Znuny"/"OTRS" grepped for follow / FollowUp / body / attachment — only CVE-2021-36093 (filter DoS), CVE-2024-48938 (ReDoS), CVE-2026-48208 (SVG DoS); nothing on follow-up detectors
4. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB, Debian tracker reviewed — no entry; `gh search issues "FollowUpCheck"` — functional only
5. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- Znuny/OTRS documentation of `PostMaster::CheckFollowUpModule###0200-References/0300-Body/0400-Attachments/0500-RawEmail` and ExternalTicketNumberRecognition — describe these detectors as opt-in convenience features; no security caveat about sender authorisation
- CVE-2021-36093 / OSA-2021-16 — PostMaster filter DoS; same subsystem, different defect

**Reasoning:** No public disclosure treats the optional Body/RawEmail/Attachments follow-up detectors as broadening an unauthenticated arbitrary-ticket injection. As with VULN-006, the underlying follow-up-by-ticket-number behaviour is documented, intended design, and these detectors are off by default and explicitly described in vendor docs, so a vendor is likely to classify this as by-design/configuration; the low score reflects that rather than any matching advisory.
