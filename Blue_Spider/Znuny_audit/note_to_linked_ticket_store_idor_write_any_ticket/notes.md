# VULN-001 — AgentTicketNoteToLinkedTicket;Store writes articles + state to ANY ticket

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: High (7.1)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- An ordinary agent (`att001_*`) in the default `users` group → rw (⊇ note) on the default
  queues (Raw/Junk/Misc/Postmaster), and holding a source ticket there.
- A victim ticket in a dedicated group/queue (`vgrp001_*`/`vq001_*`) the attacker is NOT a
  member of. Ground truth from the app's permission engine (see PROOF): attacker note=1 on the
  source, ro/note/rw=0 on the victim.

## Request
`POST /znuny/index.pl` (see `request.http`), Subaction=Store, TicketID=<source>,
`LinkedTicketIDs=<VICTIM_TID>`, Subject/Body markers, valid attacker ChallengeToken.

## Response / Observation
`TicketPermission(source)={ro:1,note:1,rw:1}`, `TicketPermission(victim)={0,0,0}`. After Store, a
new row in the victim's `article` table: `article_sender_type='agent'`, subject/body = the
attacker's marker. Confirms `AgentTicketNoteToLinkedTicket.pm:134` checks only the source ticket,
and the `LinkedTicketIDs` loop (`:1209`) calls `ArticleCreate`/`TicketStateSet` on the target
with no `TicketPermission`.

## Side effects
Adds one agent-sender article to the victim ticket and sets its state to
`LinkedTicketStateDefault`. Random-suffixed markers; safe to re-run (each run uses fresh
source/victim tickets).

## Research & references
- OWASP API Security API1:2023 Broken Object Level Authorization; WSTG-ATHZ-04 (IDOR). The
  sibling `AgentLinkObject.pm` (which DOES check both ends) is the internal contrast.
- CWE-639 / CWE-862.

## Notes
The Store path IS ChallengeToken-protected (so not zero-click CSRF — the ZN-030 reclassification
stands), but object-level authorization on the write target is entirely absent.
