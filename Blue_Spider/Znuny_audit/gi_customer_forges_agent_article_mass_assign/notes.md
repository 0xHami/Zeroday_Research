# VULN-008 — GI customer channel divergence: forge agent/internal articles, mass-assign

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (6.5, conditional on a web service)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- The shipped `GenericTicketConnectorREST` example web service imported (exposes
  `Ticket::TicketCreate`). The exploit imports it under a fresh name via `Admin::WebService::Add`.
- A plain customer portal account (created via `Admin::CustomerUser::Add`).
- Default `CustomerGroupSupport=0` (shipped default) — makes the group check a no-op.

## Request
`POST /znuny/nph-genericinterface.pl/Webservice/<ws>/Ticket` (see `request.http`), JSON:
```json
{"CustomerUserLogin":"cust008_*","Password":"...",
 "Ticket":{"Title":"Refund *","Queue":"Raw","State":"new","Priority":"3 normal","CustomerUser":"cust008_*"},
 "Article":{"Subject":"Refund approved by staff","Body":"...","SenderType":"agent",
            "IsVisibleForCustomer":0,"From":"IT Support <helpdesk@corp.example>",
            "ContentType":"text/plain; charset=utf8"}}
```

## Response
`HTTP 200 {"ArticleID":76,"TicketID":"63","TicketNumber":"..."}`.

## Observation
DB confirms the stored article: `sender_type=agent`, `is_visible_for_customer=0`,
`from='IT Support <helpdesk@corp.example>'` — created **by a customer account**. The customer
web UI (`CustomerTicketMessage`) always forces `SenderType=customer`, `IsVisibleForCustomer=1`,
and derives `From` from the account; none of these forged values is reachable there. Confirms
`TicketCreate.pm:553` only *defaults* `SenderType` and keeps a supplied value, and the per-field
customer permission check is neutralised (CustomerUserIDCheck Granted=1 + CustomerGroupSupport=0).

## Side effects
Creates one ticket + one article (random-suffixed title). Destructive-lite; safe to re-run.

## Research & references
- CVE-2025-26846 / ZSA-2025-02 (the fix that is present but ineffective here for the customer
  channel) — https://www.znuny.org/en/advisories
- OWASP API Security Top 10 — API3:2023 Broken Object Property Level Authorization (mass
  assignment) and API5:2023 Broken Function Level Authorization; used to frame the customer
  setting agent-only article properties.
- CWE-639 / CWE-269.

## Notes
The report's claim "the vendor fix exists but does nothing for the customer channel" is borne
out: the fix's `TicketCustomerPermission(Type=>…)` calls run, but return-true regardless of
Type, so `SenderType=agent`/`IsVisibleForCustomer=0` are honoured.
