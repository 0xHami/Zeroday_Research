# VULN-031 — Extra PostMaster follow-up detectors broaden the unauth arbitrary-ticket injection

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (6.5, when enabled)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- One of the extra follow-up detectors enabled (here `PostMaster::CheckFollowUpModule###0300-Body`,
  ships Valid=0; enabled via `Admin::Config::Update --valid 1`). Same DateChecksum tn precondition.

## Request / Response
Unauthenticated email whose **subject does not reference the ticket** but whose **body** contains
`Ticket#<victim tn>` (see `request.http`) → the attacker's article is appended to the victim ticket
(count 1→2).

## Observation
Confirms `FollowUpCheck/Body.pm:46` matches the ticket number anywhere in the body — removing
VULN-006's subject-tag constraint. Same missing-sender-authz sink (`FollowUp.pm`). The body must
carry the hook format `Ticket#<tn>` (DateChecksum GetTNByString regex).

## Side effects
Enables the Body detector (reset afterward), creates + appends to a victim ticket. Idempotent.

## Research & references
- Same class as VULN-006 (CWE-862). Siblings RawEmail/Attachments/ExternalTicketNumberRecognition
  broaden it further (Ticket.xml:12478-12513, all Valid=0). The VULN-006 sender-authz fix closes all.
