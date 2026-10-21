# VULN-006 — Unauthenticated article injection into arbitrary tickets via e-mail follow-up

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (6.5)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Knowledge of the victim ticket number (enumerable DateChecksum: `YYYYMMDD`+SystemID(10)+counter+
  checksum). Works even `--untrusted` (no X-OTRS headers needed). `###0100-Subject` follow-up
  detector is Valid=1 by default.

## Request / Response
Unauthenticated email with `Subject: Re: [Ticket#<victim tn>] …` (see `request.http`) → the
attacker's article is appended to the victim ticket and the closed ticket is reopened (state
closed→open); article count 1→2.

## Observation
Confirms follow-up matches the ticket number (`FollowUpCheck/Subject.pm:46` → `TicketCheckNumber`
= `SELECT id WHERE tn=?`, existence-only) and never the sender; `FollowUp.pm:585-599` appends the
article with the spoofed From.

## Side effects
Appends an article to and reopens the victim ticket. Random-suffixed victim; idempotent.

## Research & references
- OWASP Broken Access Control (missing sender authz); email spoofing. CWE-862. The subject tag
  format is `Ticket#<tn>` (Ticket::Hook), checksum publicly computable.
