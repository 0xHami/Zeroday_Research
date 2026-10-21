# VULN-003 — Unauthenticated X-OTRS-* header injection via trusted inbound mail

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: High (8.2, conditional on trusted ingestion)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Trusted inbound-mail ingestion (the default): `Maint::PostMaster::Read` without `--untrusted`;
  the shipped `.procmailrc.dist`/`.mailfilter.dist` pipe without the flag. (POP3/IMAP MailAccounts
  default Trusted=0 and are unaffected.)

## Request / Response
Raw email (see `request.http`) with `X-OTRS-Queue: Junk`, `X-OTRS-OwnerID: 2`, `X-OTRS-State:
closed successful`, `X-OTRS-Priority: 1 very low`, `X-OTRS-SenderType: agent`,
`X-OTRS-IsVisibleForCustomer: 0` → the created ticket honoured ALL of them (DB row:
`tn, Junk, owner uid 2, closed successful, sender agent, is_visible_for_customer 0`).

## Observation
Confirms `PostMaster.pm:92` `Trusted` default 1 and `:581` strip only when `!Trusted`; the honoured
headers flow to `NewTicket.pm` sinks (queue via `DestQueue.pm`, owner/state/priority, and article
SenderType/IsVisibleForCustomer at `:602-616`). NB: there is no `X-OTRS-ArticleType` in this
version — article visibility is `X-OTRS-SenderType` + `X-OTRS-IsVisibleForCustomer`.

## Side effects
Creates one ticket + forged agent article. Idempotent.

## Research & references
- OWASP Email/Header injection; OTRS admin docs on `PostmasterX-Header`/Trusted. CWE-807 / insecure
  default. Documented "trusted mail" footgun but the shipped default is dangerous.
