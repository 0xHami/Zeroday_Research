# VULN-002 — AgentTicketBulk;Do merges/links into an unchecked target ticket

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: High (7.1)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Attacker agent in `users` (rw on `Raw`) with a source ticket there.
- Victim ticket in an off-limits group/queue; attacker perm on it = {ro:0,note:0,rw:0} (proven).

## Request / Response
`POST index.pl Action=AgentTicketBulk;Subaction=Do;TicketID=<source>;LinkTogetherParent=<victim
NUMBER>;ChallengeToken=<attacker>` → a `link_relation` row `(source_key=<victim>,
target_key=<source>)` is created. See `request.http` / `response.txt`.

## Observation
Confirms `AgentTicketBulk.pm:1215` resolves the victim by number and `:1223` `LinkAdd(SourceKey=
victim,…)` with no `TicketPermission` on the target; sources are checked (`:806/:1474`) but the
merge/link target is not. The sibling `AgentTicketMerge.pm:296-300` checks its target — proving
the omission. `TicketIDLookup` on a bad number returns undef → ticket-number existence oracle.

## Side effects
Creates one ParentChild link between the attacker's ticket and the victim (random-suffixed
tickets). The MergeTo variant (not exercised) would additionally set the source to `merged` and
re-parent its articles into the victim.

## Research & references
- OWASP API1:2023 BOLA / WSTG-ATHZ-04 (IDOR). CWE-639, CWE-862.

## Notes
Do is ChallengeToken-protected; the defect is missing object-level authz on the target, plus a
ticket-number oracle.
