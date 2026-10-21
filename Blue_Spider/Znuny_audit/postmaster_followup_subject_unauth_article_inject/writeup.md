# VULN-006 — Unauthenticated article injection into arbitrary tickets via e-mail follow-up

| | |
|---|---|
| **ID** | VULN-006 (raw ZN-033) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **6.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: none (email) |
| **Attacker gains** | Appends an article to (and reopens) any ticket by number, with a spoofed From, unauthenticated. |

## Summary
Follow-up matching authenticates the ticket *number* (or Message-ID), never the *sender*. An
unauthenticated emailer who puts `[Ticket#<number>]` in the subject has their message appended to
that ticket. Confirmed: an email tagged with a victim ticket's number appended the attacker's
article to it and reopened the closed ticket — with no account and no access to it.

## How it works (mechanism & code trace)
The subject follow-up detector resolves the ticket number and returns its ID with no sender check:
```perl
# Kernel/System/PostMaster/FollowUpCheck/Subject.pm
46:  my $Tn = ...->GetTNByString( $Subject );                    # extract Ticket#<tn>
# Kernel/System/Ticket.pm  (TicketCheckNumber)
311-324:  # SELECT id FROM ticket WHERE tn = ?    -> existence only, no owner/customer check
```
The matched `TicketID` is then written to:
```perl
# Kernel/System/PostMaster/FollowUp.pm
585-599:  ...->ArticleCreate( TicketID => $Param{TicketID}, From => <attacker>, Subject/Body => <attacker>, ... )
```
The default `###0100-Subject` follow-up detector is `Valid=1`, and the flow is trust-independent
(works even `--untrusted` — no `X-OTRS-*` needed). Ticket numbers use the enumerable DateChecksum
scheme (`YYYYMMDD` + SystemID `10` + counter + a publicly-computable checksum). Dynamic proof: the
attacker's `a_from=attacker_…@evil.example` article appears on the victim ticket; article count
1→2; state `closed successful` → `open`.

## Why it is a vulnerability
The trust boundary is anonymous sender → an existing, access-controlled ticket. Correct follow-up
handling must verify that the sender is a participant of the ticket (its customer, or an
authorised agent). Here the *only* check is that the ticket number exists, so anyone who can guess/
compute a ticket number injects content into that conversation and reopens it — spoofing support
correspondence, defacing the thread, or re-opening resolved tickets en masse. It is a
long-standing OTRS design weakness (no sender authorisation on follow-up), not an intended feature.

## Reproduction
1. Create a victim ticket, note its number. 2. Feed an unauthenticated email
`Subject: Re: [Ticket#<tn>] …` to `Maint::PostMaster::Read --untrusted`. 3. `./run.sh`:
```
[PROOF] injected article on victim ticket: [['attacker_…@evil.example', 'UNAUTH-INJECTED-…']]
[PROOF] victim article count 1 -> 2; state now: open
```

## Impact
Unauthenticated content injection into and reopening of arbitrary tickets (integrity/availability),
with a spoofed sender — abuse of the support thread, mass ticket reopening (DoS on triage), and
social engineering. Broadened by VULN-031 (match anywhere in body/attachment) and chained after
VULN-003 (which also re-routes via `X-OTRS-FollowUp-*`).

## Suggested fix
On follow-up, require that the sender be an authorised participant of the matched ticket (its
customer user / a permitted agent); reject or quarantine follow-ups from unrelated senders. Do not
treat "the ticket number exists" as authorisation.

## References
- OWASP Broken Access Control (missing sender authorisation). CWE-862.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 40 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `OTRS Znuny follow-up email ticket number subject unauthenticated append article arbitrary ticket vulnerability CVE` — no CVE; only community threads about follow-ups *not* attaching, ZSA-2021-09, CVE-2025-26842
2. `OTRS "follow-up" sender not verified ticket number spoofing security advisory reopen closed ticket email` — only CVE-2020-1765/1767 (agent-side From spoofing / drafts)
3. `Znuny PostMaster Trusted default X-OTRS headers github issue security untrusted` — vendor docs on trusted mail only; nothing on follow-up sender authorisation
4. NVD API keyword pull for "Znuny"/"OTRS" grepped for follow/FollowUp/postmaster — only CVE-2021-36093 (filter DoS) and CVE-2024-48938 (ReDoS via e-mail)
5. Znuny advisory index, GitHub advisory DB, Debian tracker reviewed — no entry; `gh search issues "FollowUpCheck"` / `"FollowUp sender"` — functional bugs only (#440, #585, #186)

**Related but distinct public references** (same class or component, not this bug):
- OTRS/Znuny queue "Follow up Option" (possible / reject / new ticket) and `PostMaster::CheckFollowUpModule` documentation — describe follow-up matching by ticket number as the designed behaviour; no sender-authorisation control is offered or discussed as a security issue
- CVE-2021-36093 / OSA-2021-16 — crafted e-mail stalls PostMaster filters (DoS); same subsystem, different defect

**Reasoning:** No CVE/ZSA/OSA describes follow-up-by-ticket-number without any sender-to-ticket authorisation as a vulnerability. The behaviour is, however, the long-standing documented design of OTRS-family helpdesks (and of most e-mail ticketing systems), and DateChecksum ticket numbers are a documented format, so the vendor is likely to treat this as by-design; confidence that it is "not publicly known" is accordingly low even though no formal disclosure exists.
