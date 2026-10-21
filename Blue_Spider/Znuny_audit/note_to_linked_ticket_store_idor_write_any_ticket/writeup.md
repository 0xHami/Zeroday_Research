# VULN-001 — `AgentTicketNoteToLinkedTicket;Store` writes articles + changes state on ANY ticket

| | |
|---|---|
| **ID** | VULN-001 (raw ZN-023) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | High · CVSS 3.1 **7.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | any agent with `note` on a single ticket (default `users` group provides it) |
| **Attacker gains** | Injects forged **agent**-sender articles into, and changes the state of, **any** ticket system-wide — bypassing the queue/group ACL model. |

## Summary
The note-to-linked-ticket Store action verifies the caller's permission only on the *source*
ticket, then loops over an attacker-supplied `LinkedTicketIDs` list and writes an agent-sender
article + state change to **each** target with no per-target permission check. A low-privileged
agent who can note one ticket can therefore forge internal staff notes on, and reopen/close,
tickets in queues they cannot access. Confirmed live: an agent with `note=1` on its own ticket
and `ro/note/rw=0` on the victim planted an `agent`-sender article on the victim ticket.

## How it works (mechanism & code trace)
**Entry** — `POST index.pl?Action=AgentTicketNoteToLinkedTicket;Subaction=Store`. Parameters
are read in `Kernel/Modules/AgentTicketNoteToLinkedTicket.pm`:
```perl
120:  @{ $Param{LinkedTicketIDs} } = $ParamObject->GetArray( Param => 'LinkedTicketIDs' );
```
`LinkedTicketIDs` is a caller-controlled array of target ticket IDs.

**The single permission check (source only)** — `:134-146`:
```perl
134:  my $Access = $TicketObject->TicketPermission(
135:      Type => $Config->{Permission}, TicketID => $Self->{TicketID}, UserID => $Self->{UserID} );
141:  if ( !$Access ) { return $LayoutObject->NoPermission(...); }
```
Note the `TicketID` is `$Self->{TicketID}` — the **source** ticket only. Store is also
`ChallengeTokenCheck`-guarded (`:456`).

**The unchecked write loop (targets)** — `:1208-1236`:
```perl
1209:  for my $LinkedTicketID ( @{ $Param{LinkedTicketIDs} } ) {
1211:      ...Article::Backend::Internal->ArticleCreate(
1212:          TicketID => $LinkedTicketID, SenderType => 'agent', From => $From,
1213:          Subject => $Subject, Body => $Body, ... );
1231:      $TicketObject->TicketStateSet(
1232:          State => $Config->{LinkedTicketStateDefault}, TicketID => $LinkedTicketID, ... );
1236:  }
```
There is **no** `TicketPermission(TicketID => $LinkedTicketID)` anywhere in this loop. The
`SenderType` is hard-coded `agent`, so the injected content is presented as staff correspondence.

**Confirmed at the boundary.** The exploit reads the app's own permission engine:
`TicketPermission(attacker, source) = {ro:1,note:1,rw:1}` but `TicketPermission(attacker,
victim) = {0,0,0}`. After the request, the victim ticket has a new `article` row with
`article_sender_type='agent'` and the attacker's marker body — a write the ACL forbids.

## Why it is a vulnerability
Znuny's authorization model is per-queue/group: an agent may act only on tickets in queues whose
group they belong to. The invariant for a write action is "the caller holds the write permission
**on the ticket being written**." Here the code checks that permission on a *different* ticket
(the source the attacker legitimately holds) and then writes to attacker-named targets — a
textbook Broken Object-Level Authorization. The internal contrast proves it is an oversight, not
design: the standalone `AgentLinkObject.pm` enforces `ObjectPermission` on **both** the source
and every target before linking (recorded as FP-10). Impact is integrity-high: an attacker forges
authentic-looking agent notes across the whole ticket base and drives state transitions
(reopen/close) on tickets they cannot even read.

## Reproduction
1. Create agent `att001` in `users`; create a source ticket in `Raw` (attacker can note it).
2. Create group `vgrp001` + queue `vq001`; create the victim ticket there (attacker has no
   rights — confirmed via `TicketPermission`).
3. `POST …Action=AgentTicketNoteToLinkedTicket;Subaction=Store;TicketID=<source>;
   LinkedTicketIDs=<victim>;Subject=…;Body=<marker>;ChallengeToken=<attacker token>`.
4. `./run.sh`:
   ```
   [PROOF] attacker TicketPermission on SOURCE 66: {'ro':1,'note':1,'rw':1}
   [PROOF] attacker TicketPermission on VICTIM 67: {'ro':0,'note':0,'rw':0}
   [PROOF] victim ticket articles matching marker: [['82','agent','forged …','PWNED-VULN001-…']]
   [OK] exploit confirmed ...
   ```

## Impact
- **Cross-queue/team forged agent notes**: plant internal staff messages (SenderType=agent) into
  any ticket by ID — misinformation, social engineering, evidence tampering in support/ITSM.
- **State manipulation**: reopen closed tickets or force them into `LinkedTicketStateDefault`.
- **Chain**: with VULN-005 (read any ticket) a single low-priv agent gains full read+write control
  of the entire ticket base (see report "Any-agent ticket takeover"). VULN-002 is the sibling
  merge/link variant.
- Requires only `note` on one ticket (the default `users` group grants it), so essentially any
  agent.

## Suggested fix
Inside the `LinkedTicketIDs` loop, before `ArticleCreate`/`TicketStateSet`, add
`next unless $TicketObject->TicketPermission(Type => 'note', TicketID => $LinkedTicketID,
UserID => $Self->{UserID});` (mirror `AgentLinkObject.pm`). Enforce the write permission on the
object actually being written, not on an unrelated source ticket.

## References
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization. OWASP WSTG-ATHZ-04
  (IDOR). CWE-639, CWE-862.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `Znuny AgentTicketNoteToLinkedTicket vulnerability permission LinkedTicketIDs` — only CVE-2025-26846 (Generic Interface) and ZSA-2021-05 (FAQ link display) came back; nothing on this module
2. `Znuny CVE missing permission check linked ticket note article injection any ticket` — only CVE-2025-26846 / ZSA-2025-02 (GI TicketUpdate with `ro`); no linked-ticket note module
3. `Znuny security advisory 2026 privilege escalation agent ticket IDOR` — 2026 ZSAs are XSS/SQLi/BasicAuth/FormID; no agent-ticket IDOR advisory
4. `"NoteToLinkedTicket" Znuny github issue permission check linked tickets` — only the add-on marketing page and community thread; no security issue
5. Full Znuny advisory index (znuny.org/en/advisories, ZSA-2021-01 … ZSA-2026-16) reviewed — no entry for AgentTicketNoteToLinkedTicket
6. `gh search issues --repo znuny/Znuny "NoteToLinkedTicket"` — one unrelated migration issue (#452)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-26846 / ZSA-2025-02 — missing permission check in the Generic Interface `TicketUpdate` (ticket attributes changeable with `ro`); different module/entry point, not the agent note-to-linked-ticket Store loop
- ZSA-2021-05 / CVE-2021-21438 — FAQ content shown via linked objects without permission (read-side, LinkObject display), not article write/state change

**Reasoning:** `AgentTicketNoteToLinkedTicket` is a Znuny-only module (originally the Znuny "note to linked tickets" add-on, merged into core), so it has no OTRS/OSA history. No ZSA, CVE, GHSA, or GitHub issue references a missing per-target `TicketPermission` check in its Store loop. The authorization-bypass class is common in this codebase (ZSA-2025-02, ZSA-2021-10) so a private report could exist, hence not 90+.
