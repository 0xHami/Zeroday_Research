# VULN-002 — `AgentTicketBulk;Do` merges/links into an unchecked target ticket (any agent)

| | |
|---|---|
| **ID** | VULN-002 (raw ZN-025) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | High · CVSS 3.1 **7.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | any agent reaching the bulk screen with rw on one ticket (default `users`) |
| **Attacker gains** | Re-parents/merges their own tickets into any victim ticket by number (integrity), and a ticket-number existence oracle. |

## Summary
The bulk-action handler checks the caller's permission on every *selected source* ticket but not
on the **merge target** (`MergeTo`) or **link parent** (`LinkTogetherParent`), which are resolved
from an attacker-supplied ticket number. An agent can therefore create ParentChild links onto —
or merge into — a ticket they cannot access. Confirmed: an agent with `rw` only on `Raw` and
`{0,0,0}` on the victim created a `link_relation` row with the off-limits victim as parent of its
own ticket.

## How it works (mechanism & code trace)
**Entry** — `POST index.pl?Action=AgentTicketBulk;Subaction=Do` (ChallengeToken-guarded at `:590`).
Selected tickets are permission-filtered (`Kernel/Modules/AgentTicketBulk.pm`):
```perl
1474:  my $UserHasTicketPermission = $TicketObject->TicketPermission( Type => 'rw', TicketID => $TicketID, ... );
1480:  next TICKETID if !$UserHasTicketPermission;         # sources are checked
```
**The unchecked target** — the link parent is looked up from an attacker number and used with no
check:
```perl
1214:  if ( $GetParam{'LinkTogetherParent'} ) {
1215:      my $MainTicketID = $TicketObject->TicketIDLookup( TicketNumber => $GetParam{'LinkTogetherParent'} );
1223:      $LinkObject->LinkAdd( SourceKey => $MainTicketID, TargetKey => $TicketID, Type => 'ParentChild', ... );
```
The merge path is identical (`:766-767` resolves `MergeTo` → `$MainTicketID`; `:806` checks the
*source* `$TicketID`, never `$MainTicketID`, before `TicketMerge`). No `TicketPermission(TicketID
=> $MainTicketID)` exists on either path.

**Confirmed at the boundary.** `TicketPermission(attacker, victim) = {0,0,0}`, yet after the
request `link_relation` contains `(source_key=<victim>, target_key=<source>)`.

## Why it is a vulnerability
The invariant "you may only link/merge tickets you can access" is enforced on the sources but not
the target. Because the target is chosen by *ticket number*, an attacker reaches any ticket
system-wide. The internal contrast is decisive: `AgentTicketMerge.pm:296-300` performs
`TicketPermission(Type => …, TicketID => $MainTicketID)` on its target before merging (recorded
as FP-10 for `AgentLinkObject`), so the bulk path's omission is an oversight, not design. Beyond
the link/merge write (integrity), `TicketIDLookup` returning undef for non-existent numbers turns
this into a ticket-number existence/enumeration oracle.

## Reproduction
1. Agent `att002` in `users` + a source ticket in `Raw`. 2. Victim ticket in a fresh
group/queue. 3. `POST …AgentTicketBulk;Subaction=Do;TicketID=<source>;LinkTogetherParent=<victim
number>;ChallengeToken=<attacker>`. 4. `./run.sh`:
```
[PROOF] attacker perm on source 68={ro:1,note:1,rw:1}; on victim 69={ro:0,note:0,rw:0}
[PROOF] link_relation rows referencing victim 69 as parent of source 68: [['69','68']]
```

## Impact
- **Integrity:** re-parent/merge attacker tickets into any victim ticket — the MergeTo variant
  moves the attacker's articles into the victim and sets the source to `merged`, injecting content
  into a ticket the attacker cannot read.
- **Ticket-number oracle:** distinguish existing vs. non-existing ticket numbers.
- Pairs with VULN-001 (write) and VULN-005 (read) for full any-agent ticket takeover.

## Suggested fix
Before `LinkAdd`/`TicketMerge`, add `TicketPermission(Type => 'rw', TicketID => $MainTicketID,
UserID => $Self->{UserID})` and abort if denied (mirror `AgentTicketMerge.pm:296-300`).

## References
- OWASP API1:2023 BOLA, WSTG-ATHZ-04. CWE-639, CWE-862.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `OTRS Znuny AgentTicketBulk merge link permission target ticket vulnerability CVE` — only CVE-2021-21443 (bulk screen customer-email listing), CVE-2008-7277 (single-ticket merge permission type), CVE-2025-26846 (GI)
2. `OTRS bulk action "LinkTogetherParent" OR "MergeTo" permission check missing advisory` — no advisory names these parameters; same three CVEs returned
3. `OTRS "AgentTicketBulk" vulnerability advisory merge OR link ticket number unauthorized` — CVE-2021-21443 only (information disclosure, not merge/link)
4. NVD API keyword pull for "Znuny" (17 CVEs) and "OTRS" (120 CVEs), grepped for bulk/merge/link — nothing on unchecked merge/link targets
5. Znuny advisory index ZSA-2021-01 … ZSA-2026-16 and GitHub advisory DB (19 entries) reviewed — no bulk-action authorization advisory
6. `gh search issues --repo znuny/Znuny "AgentTicketBulk"` — two unrelated functional bugs (#859, #685)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2021-21443 / OSA-2021-13 / ZSA-2021-09 — same screen (AgentTicketBulk) but an information disclosure of customer e-mails, not the unchecked `MergeTo` / `LinkTogetherParent` target
- CVE-2008-7277 — OTRS < 2.3.0 merge checked `rw` instead of the configured merge permission (single-ticket AgentTicketMerge, 2008); different module and root cause
- CVE-2025-26846 / ZSA-2025-02 — Generic Interface TicketUpdate permission check; different entry point

**Reasoning:** No CVE, ZSA, OSA, GHSA or GitHub issue describes the bulk-action handler resolving the merge target / link parent from an attacker-supplied ticket number without a `TicketPermission` check on that target. The bulk screen has one prior advisory (CVE-2021-21443) but for a different defect, and the sibling `AgentTicketMerge` enforces the target check, which is why this is judged an unreported oversight. Authorization bugs are a recurring class in this codebase, so an undisclosed private report cannot be excluded.
