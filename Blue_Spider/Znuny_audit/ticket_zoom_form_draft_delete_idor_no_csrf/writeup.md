# VULN-016 — `AgentTicketZoom;FormDraftDelete` cross-user draft deletion (no owner check + no CSRF token)

| | |
|---|---|
| **ID** | VULN-016 (raw ZN-027) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **5.4** — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | any agent with `ro` on one ticket; also CSRF-triggerable (no token) |
| **Attacker gains** | Deletes any other user's saved in-progress form draft (integrity/DoS on their work). |

## Summary
`FormDraftDelete` removes the draft identified by the caller-supplied `FormDraftID`, authorised
only by `ro` permission on an *unrelated* URL `TicketID`. The delete scopes on the draft `id`
alone — the owner is never checked — so any agent deletes any user's draft. The subaction also
has no CSRF token. Confirmed: an attacker deleted a draft owned by a different agent (uid 84) via
a tokenless GET.

## How it works (mechanism & code trace)
Entry — `GET index.pl?Action=AgentTicketZoom;Subaction=FormDraftDelete`. In
`Kernel/Modules/AgentTicketZoom.pm`:
```perl
322:  my $FormDraftID = $ParamObject->GetParam( Param => 'FormDraftID' );
324:  my $Success = $Kernel::OM->Get('Kernel::System::FormDraft')->FormDraftDelete(
325:      FormDraftID => $FormDraftID, UserID => $Self->{UserID} );
```
The surrounding module authorises only `ro` on the URL `TicketID` (a *different* object) and there
is **no** `ChallengeTokenCheck` anywhere in the file. `Kernel/System/FormDraft.pm`
`FormDraftDelete`/`FormDraftGet` execute `... WHERE id = ?` — the `UserID` argument is passed but
never used in the WHERE clause. So ownership is neither enforced by the module nor by the storage
layer.

**Confirmed:** `form_draft.create_by` = victim uid; before the request the row exists, after the
tokenless attacker GET it is gone.

## Why it is a vulnerability
A saved form draft is per-user private work-in-progress; the invariant is "only the owner (or an
admin) may delete it." The code enforces neither an owner check nor a token, and the `ro`-on-an-
unrelated-ticket gate is unrelated to the draft's ownership — a Broken Object-Level
Authorization. The absent CSRF token additionally lets a malicious page trigger the deletion in a
logged-in agent's session (amplified by VULN-042, no SameSite). It is not by design: every draft
belongs to a `create_by` user that the code simply ignores.

## Reproduction
1. Victim agent + a saved FormDraft (owned by victim). 2. Attacker agent with `ro` on its own
ticket. 3. `GET …FormDraftDelete;TicketID=<attacker ticket>;FormDraftID=<victim draft>`. 4.
`./run.sh`:
```
[PROOF] victim draft before attack: [['3','VictimDraft_…']]
[PROOF] victim draft after attack: []
```

## Impact
Any agent (or a CSRF page) destroys other users' saved drafts by enumerating small sequential
`FormDraftID`s — silent loss of in-progress ticket work across the instance (integrity/
availability). No confidentiality impact.

## Suggested fix
In `FormDraft.pm`, scope `FormDraftDelete`/`FormDraftGet` with `AND create_by = ?` (the acting
UserID), or have `AgentTicketZoom` verify `FormDraftGet(...)->{CreateBy} == $Self->{UserID}`
before deleting. Add `ChallengeTokenCheck()` to the subaction.

## References
- OWASP WSTG-ATHZ-04 (IDOR); OWASP CSRF Prevention Cheat Sheet. CWE-639, CWE-352.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. OSA-2020-03 / CVE-2020-1767 advisory page fetched — Agent B can open/edit/send Agent A's draft in A's name (CE 6.0.24 / OTRS 7.0.13); deletion is not mentioned, no module named
2. ZSA-2024-03 / CVE-2024-32493 advisory page fetched — SQL injection in the draft form ID parameter of an AJAX request; a different defect in the draft feature
3. NVD API keyword pull for "Znuny"/"OTRS" grepped for draft — only CVE-2020-1767 and CVE-2024-32493
4. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB, Debian tracker reviewed — no FormDraft deletion / CSRF advisory
5. `gh search issues --repo znuny/Znuny "FormDraft"` (#639, unrelated cleanup error) and `"FormDraftDelete"` (none)
6. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2020-1767 / OSA-2020-03 — same FormDraft component, cross-agent *open/edit/send* impersonation; not the tokenless, owner-unchecked `FormDraftDelete` on an arbitrary `FormDraftID`
- CVE-2024-32493 / ZSA-2024-03 — SQL injection in a draft form ID AJAX parameter; same feature, different class
- CVE-2026-78358 / CVE-2026-48211 — OTRS 7+ admin actions without ChallengeToken (CSRF); same class, different modules/product line

**Reasoning:** No advisory covers deleting another user's form draft via `AgentTicketZoom;Subaction=FormDraftDelete` with neither an ownership check nor a ChallengeToken. The draft feature has two prior advisories, and OTRS-family drafts are by design visible per ticket to agents with access, so a vendor might argue same-ticket deletion is intended; the cross-ticket (`ro` on an unrelated ticket) and CSRF aspects are not public, hence a moderate score.
