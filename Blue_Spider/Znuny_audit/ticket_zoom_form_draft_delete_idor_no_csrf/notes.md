# VULN-016 — AgentTicketZoom;FormDraftDelete cross-user draft deletion (no owner check, no token)

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (5.4)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- A victim agent with a saved FormDraft (created here via `FormDraftAdd`, owned by the victim uid).
- Attacker agent with `ro` on any one ticket (its own).

## Request / Response
`GET index.pl?Action=AgentTicketZoom;Subaction=FormDraftDelete;TicketID=<attacker's own ticket>;
FormDraftID=<victim draft id>` (no ChallengeToken) → victim's `form_draft` row disappears. See
`request.http` / `response.txt`.

## Observation
`form_draft.create_by` = victim uid (84); before: row present, after: gone. Confirms
`AgentTicketZoom.pm:322-327` deletes the attacker-supplied `FormDraftID` gated only by `ro` on the
unrelated URL ticket, `FormDraft.pm` scopes deletion on `id` alone (no `create_by`/UserID in the
WHERE), and there is no `ChallengeTokenCheck` in the module (CSRF).

## Side effects
Deletes the victim's draft (created by the exploit). Random-suffixed; safe to re-run.

## Research & references
- OWASP WSTG-ATHZ-04 (IDOR), OWASP CSRF Prevention Cheat Sheet (tokenless state-changing GET).
  CWE-639, CWE-352.
