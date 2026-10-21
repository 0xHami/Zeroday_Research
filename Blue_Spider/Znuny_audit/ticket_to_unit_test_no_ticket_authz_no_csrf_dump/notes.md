# VULN-029 — AgentTicketToUnitTest dumps/exfils ANY ticket (no ticket authz + no CSRF)

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (5.3)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Attacker agent in the `admin` frontend group only (no queue/ticket group). Its per-ticket
  `TicketPermission` on the victim is {ro:0,note:0,rw:0} (proven).
- A victim ticket in an off-limits queue.

## Request / Response
`GET index.pl?Action=AgentTicketToUnitTest;Subaction=CreateFile;TicketID=<victim>` (no
ChallengeToken) → `HTTP 200`, `Content-Disposition: attachment; filename="UnitTest-…-<TID>.t"`,
body contains the victim's confidential title/marker. See `request.http` / `response.txt`.

## Observation
Confirms the module reads `TicketID`, serialises the ticket, and returns it with no
`TicketPermission` and no `ChallengeToken`. The only gate is `admin`-frontend-group membership,
which does not imply per-queue ticket rights — so an admin-group operator with zero queue
permissions exfiltrates any ticket by numeric ID. The `SendEmail` subaction is the CSRF-driven
exfil-to-support@znuny.com variant (not fired to avoid outbound mail).

## Side effects
None (read/dump only). Idempotent.

## Research & references
- OWASP WSTG-ATHZ-04 (IDOR)/API1:2023 BOLA; OWASP CSRF Cheat Sheet. CWE-862, CWE-352.

## Notes
In the OTRS model the `admin` permission group governs admin-frontend access, NOT per-queue ticket
ACLs — so this is a genuine cross-boundary read for an admin-group operator lacking queue rights.
