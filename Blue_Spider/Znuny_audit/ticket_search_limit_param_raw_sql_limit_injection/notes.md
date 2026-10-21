# VULN-017 — Request Limit → raw LIMIT/TOP clause (SQL injection; two channels)

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (6.3)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- GI channel: the shipped `GenericTicketConnectorREST` web service (exposes Ticket::TicketSearch).
  UI channel: any agent hitting `AgentTicketEscalationView`.

## Request / Response
- GI: `POST /Ticket/Search {"...","Title":"%","Limit":"100"}` → 78 tickets; same with
  `"Limit":"100 OR 1=1"` → 0 tickets (query broken). See `response.txt`.
- Sink: `DB::Prepare(SQL=>"SELECT id FROM ticket", Limit=>"424242 OR 7=7")` → MySQL
  `You have an error in your SQL syntax … near 'OR 7=7'`, SQL = `SELECT id FROM ticket LIMIT 424242 OR 7=7`.

## Observation
The request `Limit` is interpolated verbatim into `" LIMIT $Limit"` (`DB.pm:732`) with no
integer coercion; `TicketSearch.pm:345` forwards it raw (`$Limit = $Param{Limit} || 10000`, no
`int()`), and both the GI operation (`:302`) and the escalation-view UI (`:266,303`) pass the raw
request value. A sanitising implementation would have returned rows for `100 OR 1=1` (treating it
as 100/0); the empty result + the sink error prove verbatim interpolation.

## Side effects
None (read query; the injection breaks the query rather than mutating data). Idempotent. (The
general query log's TABLE mode self-matches diagnostic queries — the reliable proofs are the HTTP
differential and the captured DB error string.)

## Research & references
- OWASP WSTG-INPV-05 (SQL Injection); OWASP SQL Injection Prevention Cheat Sheet (use
  parameterised queries / cast numeric inputs). CWE-89. Source-diff: the TicketSearch SQLi fixes
  targeted `ContentSearch`/CVE-2022-4427, not the `Limit` sink.

## Scope / honest bound
On the MySQL 8 lab the `LIMIT` grammar accepts only integer literals, so a non-integer payload is
a syntax error (query breakage / error-based, constrained DoS) rather than data extraction. Full
UNION/subquery weaponisation applies on PostgreSQL/Oracle/MSSQL (different LIMIT/TOP syntax). The
injection itself (attacker string → SQL) is real and confirmed here.
