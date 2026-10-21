# VULN-029 — `AgentTicketToUnitTest` no ticket authz + no CSRF → dump/exfil any ticket

| | |
|---|---|
| **ID** | VULN-029 (raw ZN-001) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **5.3** — `AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | agent in the `admin` frontend group (no per-queue ticket rights needed) |
| **Attacker gains** | Full dump of any ticket by numeric ID (history, articles, dynamic fields, customer identity); a CSRF-driven exfil channel via the SendEmail variant. |

## Summary
`AgentTicketToUnitTest` serialises a ticket named by `TicketID` and returns it as a downloadable
unit-test file (or emails it), with no per-ticket permission check and no CSRF token. Its only
gate is `admin`-frontend-group membership, which in the OTRS model governs admin *screens*, not
per-queue ticket ACLs. Confirmed: an admin-group agent with `{ro:0,note:0,rw:0}` on the victim
downloaded the victim ticket's confidential content.

## How it works (mechanism & code trace)
Entry — `GET index.pl?Action=AgentTicketToUnitTest;Subaction=CreateFile` (registered
`Group=>['admin']` in `Znuny.xml`). In `Kernel/Modules/AgentTicketToUnitTest.pm` the handler:
```perl
# reads TicketID (presence-checked only), then:
CreateUnitTest( TicketID => $Param{TicketID} );   # serialises the whole ticket
... return $LayoutObject->Attachment( ... )        # CreateFile: download
... EmailObject->Send( To => 'support@znuny.com', Attachment => [dump] )   # SendEmail: exfil
```
There is **no** `TicketObject->TicketPermission(...)` and **no** `ChallengeTokenCheck()` anywhere
in the module (both greps return 0). The `admin`-group registration is the sole access control.

**Confirmed at the boundary:** `TicketPermission(attacker, victim) = {0,0,0}` yet the response is
`Content-Disposition: attachment; filename="UnitTest-…-<TID>.t"` whose body contains the victim's
`CONFIDENTIAL-VULN029-<sfx>` marker.

## Why it is a vulnerability
Znuny separates two authorization axes: the `admin` *frontend* group (who may open admin screens)
and per-*queue* ticket permissions (who may read a given ticket). Reading ticket content must
require the latter. This module conflates them — `admin`-group membership is treated as licence to
read *any* ticket — so an admin-group operator restricted to, say, configuration tasks, and holding
no queue rights, can still exfiltrate every ticket by iterating numeric IDs. The absent CSRF token
turns the `SendEmail` subaction into a one-click exfil (a lured admin GET mails the dump offsite).
This is a developer/debug tool that shipped reachable (its menu links are `Valid=0`, i.e. hidden
but live) without the ticket-level authorization every normal ticket screen enforces.

## Reproduction
1. Create agent `att029` in the `admin` group only (no queue group). 2. Victim ticket in a fresh
group/queue. 3. `GET …AgentTicketToUnitTest;Subaction=CreateFile;TicketID=<victim>`. 4. `./run.sh`:
```
[PROOF] attacker TicketPermission on victim 71: {'ro':0,'note':0,'rw':0}
[PROOF] HTTP 200; Content-Disposition='attachment; filename="UnitTest-…-71.t"'; victim marker in dump: True
```

## Impact
Confidentiality-high: complete disclosure of any ticket (subject, all articles/bodies, history,
dynamic fields, customer identity) to an admin-group operator without the queue rights that would
normally gate it — and, via `SendEmail`, a CSRF-driven exfiltration to a fixed external address.
Numeric IDs are trivially enumerable.

## Suggested fix
Add `TicketPermission(Type=>'ro', TicketID=>$Param{TicketID}, UserID=>$Self->{UserID})` (deny on
failure) and `ChallengeTokenCheck()` to both subactions; switch `SendEmail` to POST; and gate the
whole developer tool behind an explicit `Valid=0`/dev flag so it is not reachable in production.

## References
- OWASP API1:2023 BOLA / WSTG-ATHZ-04 (IDOR); OWASP CSRF Prevention Cheat Sheet. CWE-862, CWE-352.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. NVD API keyword pull for "Znuny" (17) and "OTRS" (120) grepped for UnitTest / ToUnitTest — only CVE-2023-38056 (code execution via SysConfig `SchedulerCronTaskModule` using UnitTests modules, admin)
2. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB (19 entries), Debian tracker reviewed — no AgentTicketToUnitTest entry
3. `gh search issues --repo znuny/Znuny "ToUnitTest"` / `"AgentTicketToUnitTest"` — no results
4. Earlier web search `Znuny security advisory 2026 privilege escalation agent ticket IDOR` — no ticket-dump / IDOR advisory
5. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2023-38056 / OSA-2023-02 — admin code execution via UnitTest modules referenced from SysConfig; different module, different class
- CVE-2025-26842 / ZSA-2025-01 — ticket content exposed to users without ticket access via CommunicationLog; same "admin-area screen bypasses ticket ACL" theme, different module

**Reasoning:** `AgentTicketToUnitTest` is a Znuny-specific developer tool (merged from the Znuny TicketToUnitTest add-on) with no OTRS lineage, and no public advisory or issue reports that it serialises any `TicketID` for admin-group agents without `TicketPermission` or a ChallengeToken (including the `SendEmail` exfil subaction). A similar ACL-bypass theme was fixed in ZSA-2025-01 for another admin screen, so the vendor would likely accept it as a defect; nothing public matches.
