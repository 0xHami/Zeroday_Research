# VULN-005 — `AgentTicketProcess` split reads an arbitrary ticket + article body without `ro`

| | |
|---|---|
| **ID** | VULN-005 (raw ZN-024) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **6.5** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | any agent (needs no rights on the target ticket) |
| **Attacker gains** | Reads the subject and full article body of any ticket by ID — cross-queue confidentiality breach. |

## Summary
When `AgentTicketProcess` is used to start a *new/split* process ticket, it fetches the linked
source ticket and article at the top of `Run()` — before any permission check — and pre-fills
their subject/body into the process form. Because there is no `TicketID` on a new-process action,
the module's only permission gate (wrapped in `if ($TicketID)`) never executes. Confirmed: an
agent with `{ro:0,note:0,rw:0}` on the victim read the victim's subject (into the `Title` field)
and article body (into the `Body` textarea).

## How it works (mechanism & code trace)
Entry — `GET index.pl?Action=AgentTicketProcess;Subaction=DisplayActivityDialog` with
`LinkTicketID`/`ArticleID`. In `Kernel/Modules/AgentTicketProcess.pm`, at the top of `Run()`:
```perl
 85:  if ( $Self->{LinkTicketID} ) {
 86:      my %TicketData = $TicketObject->TicketGet( TicketID => $Self->{LinkTicketID}, UserID => ..., Extended => 1 );
 91:      $Self->{LinkTicketData} = \%TicketData;
 98:  if ( $Self->{ArticleID} ) {
104:      my %Article = $ArticleBackendObject->ArticleGet( TicketID => $Self->{LinkTicketID}, ArticleID => $Self->{ArticleID} );
109:      $Self->{LinkArticleData} = \%Article;
```
No `TicketPermission(Type=>'ro', TicketID=>$Self->{LinkTicketID})` guards these fetches. The
permission gate appears only later and only for an existing ticket:
```perl
115:  if ($TicketID) {                 # skipped on a NEW/split process (no TicketID)
      ...  # the ro/rw check lives here
```
The captured data is then rendered into the activity dialog: the article body into the `Body`
textarea and the subject into the `Title` field (`:2864-2879`, `_OutputActivityDialog`). Note
`TicketGet` is called with `UserID => $Self->{UserID}` but that argument does **not** enforce
permission — it only tags who is reading; the disclosure happens regardless.

**Confirmed at the boundary.** `TicketPermission(attacker, victim) = {0,0,0}`, yet the response
contains `name="Title" … value="SUBJMARK…"` and `name="Body" …>BODYMARK…</textarea>`.

## Why it is a vulnerability
The "split" feature is meant to pre-fill a new ticket from one the agent is *already allowed to
read*. The invariant is "you may only pre-fill from a source ticket you have `ro` on." The
sibling split handlers enforce exactly that — `AgentTicketEmail.pm:467` and
`AgentTicketPhone.pm:338` call `TicketPermission(Type=>'ro')` on the split source before using it.
`AgentTicketProcess` omits the check, so any agent turns the pre-fill into an arbitrary-ticket
read oracle: subject + full article body of any ticket by numeric ID, across every queue/team.
This is a Broken Object-Level Authorization (confidentiality), not a designed capability.

## Reproduction
1. Import/deploy a process with a Title+Article start dialog (bundled `minimal_process.yml` +
   ProcessSync). 2. Victim ticket in a fresh off-limits queue with unique subject/body. 3. As a
   low-priv agent, `GET …AgentTicketProcess;Subaction=DisplayActivityDialog;ProcessEntityID=<P>;
   ActivityDialogEntityID=<D>;LinkTicketID=<victim>;ArticleID=<victim article>`. 4. `./run.sh`:
   ```
   [PROOF] attacker TicketPermission on victim 78: {'ro':0,'note':0,'rw':0}
   [PROOF] victim SUBJECT leaked into process form: True
   [PROOF] victim ARTICLE BODY leaked into process form: True
   ```

## Impact
Confidentiality-high: any agent reads the subject and article body (and, via `LinkTicketData`,
owner/queue/customer) of any ticket by ID, bypassing the queue ACL. Combined with VULN-001/002
(write) this yields full any-agent read+write control of the ticket base (report chain
"Any-agent ticket takeover"). Precondition (a configured process) is common in Znuny ITSM/BPM
deployments.

## Suggested fix
Guard the `LinkTicketID`/`ArticleID` fetches at `:85`/`:98` with
`return $LayoutObject->NoPermission(...) unless $TicketObject->TicketPermission(Type=>'ro',
TicketID=>$Self->{LinkTicketID}, UserID=>$Self->{UserID});` — mirroring the sibling split
handlers.

## References
- OWASP API1:2023 BOLA, WSTG-ATHZ-04 (IDOR). CWE-639.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `OTRS Znuny AgentTicketProcess LinkTicketID split process permission ticket read vulnerability` — only CVE-2025-26846 (GI) and CVE-2025-26842 (S/MIME CommunicationLog); nothing on AgentTicketProcess
2. `CVE-2023-38058 OTRS description ticket` (cited by scanner as related) — it is an improper privilege check in the OTRS 8 ticket *move* action, not a split/pre-fill read
3. `Znuny security advisory 2026 privilege escalation agent ticket IDOR` — 2026 ZSAs are XSS/SQLi/BasicAuth/FormID; no process-split advisory
4. NVD API keyword pull for "Znuny"/"OTRS" grepped for process/split — CVE-2013-3551 (AgentTicketPhone split, OTRS 3.x) and CVE-2024-43443/CVE-2024-48937 (XSS in process management) only
5. Znuny advisory index (ZSA-2021-01 … ZSA-2026-16), GitHub advisory DB, Debian tracker reviewed — no entry; `gh search issues "AgentTicketProcess permission"` — none

**Related but distinct public references** (same class or component, not this bug):
- CVE-2013-3551 — the same "ticket split reads a restricted ticket via crafted URL" pattern, but in `AgentTicketPhone.pm` on OTRS 3.x (fixed 2013); AgentTicketPhone/Email now enforce `ro`, AgentTicketProcess does not
- CVE-2023-38058 — OTRS 8 AgentInterface ticket move without permission; different module/product line
- CVE-2024-48937 / ZSA-2024-05 — XSS in process-management activity dialogs; same module family, different class

**Reasoning:** No public disclosure covers the unguarded `LinkTicketID`/`ArticleID` fetch at the top of `AgentTicketProcess::Run()` for a new/split process ticket. The closest item is CVE-2013-3551, which fixed the identical pattern in a sibling split handler 13 years ago, making this a plausible regression/omission that was never reported for the process module. Confidence is held below 90 because of that near-miss and the commonness of authorization gaps in this codebase.
