# VULN-005 — AgentTicketProcess split reads an arbitrary ticket + article body without `ro`

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (6.5)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- At least one deployed Process whose start activity dialog has Title + Article fields (a normal
  Znuny configuration). The exploit imports the bundled `minimal_process.yml` and ProcessSyncs it.
- A victim ticket in an off-limits queue; attacker `TicketPermission` on it = {0,0,0} (proven).
- Attacker: any authenticated agent.

## Request / Response
`GET index.pl?Action=AgentTicketProcess;Subaction=DisplayActivityDialog;ProcessEntityID=<P>;
ActivityDialogEntityID=<D>;LinkTicketID=<victim>;ArticleID=<victim article>` → the process form
renders with the victim's subject in the `Title` field and the victim's article body in the
`Body` textarea. See `request.http` / `response.txt` (context line shows
`name="Body" …>BODYMARK…</textarea>` and `name="Title" … value="SUBJMARK…"`).

## Observation
Attacker perm on victim = {ro:0,note:0,rw:0}, yet subject + body leaked. Confirms
`AgentTicketProcess.pm:85-113` fetches `TicketGet`/`ArticleGet` on the attacker-supplied
`LinkTicketID` before the permission gate at `:115`, which is inside `if ($TicketID)` and never
runs on the new/split process path.

## Side effects
None (read only; no ticket is created — the dialog is only rendered). Imports+deploys a process
(reproducible via the fixture) and creates a victim ticket. Idempotent.

## Research & references
- OWASP WSTG-ATHZ-04 (IDOR)/API1:2023 BOLA. CWE-639. Internal contrast: `AgentTicketEmail.pm:467`
  / `AgentTicketPhone.pm:338` check `ro` on their split source; `AgentTicketProcess` does not.

## Notes
`minimal_process.yml` is a process exported from the lab with a Title+Article start dialog; the
finding's precondition ("a Process is configured") is common in real Znuny deployments.
