# VULN-017 — Request `Limit`/`FilterLimit` → raw `LIMIT`/`TOP` clause (SQL injection; two channels)

| | |
|---|---|
| **ID** | VULN-017 (raw ZN-004/053) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **6.3** — `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | any agent (UI) / any GI user (API) |
| **Attacker gains** | Injects into the SQL `LIMIT` clause; on MySQL8 this breaks the query (error/DoS), on Postgres/Oracle/MSSQL it is fully weaponisable. |

## Summary
The request `Limit` parameter is interpolated verbatim into the SQL `LIMIT` clause with no integer
coercion. Both the GenericInterface `TicketSearch` operation and the `AgentTicketEscalationView`
UI forward the raw value to `DB::Prepare`. Confirmed two ways: over HTTP, GI `TicketSearch` with
`Limit=100` returns 78 tickets while `Limit="100 OR 1=1"` returns 0 (the injected string breaks
the query); and at the sink, `DB::Prepare` produced `SELECT id FROM ticket LIMIT 424242 OR 7=7`,
which MySQL rejected citing the injected `OR 7=7`.

## How it works (mechanism & code trace)
**Sink** — `Kernel/System/DB.pm`:
```perl
682:  my $Limit = $Param{Limit} || '';
...
730:  if ($Start) { $Limit = $Limit + $Start; ... }        # numify ONLY when Start is set (it isn't here)
732:  if ( ...{'DB::Limit'} eq 'limit' ) { $SQL .= " LIMIT $Limit"; }   # verbatim interpolation
735:  elsif ( ...{'DB::Limit'} eq 'top' ) { $SQL =~ s{...}{$1 TOP $Limit}...; }
```
`$Param{Limit}` is concatenated into the SQL string — never a bound placeholder, never cast to
int.

**Caller forwards raw** — `Kernel/System/Ticket/TicketSearch.pm`:
```perl
345:  my $Limit = $Param{Limit} || 10000;    # <-- no int()
...
2762:  Limit => $Limit,                       # -> DB::Prepare
```
**Two entry channels pass the request value unmodified:**
- GI: `GenericInterface/Operation/Ticket/TicketSearch.pm:302` `$Self->{SearchLimit} =
  $Param{Data}->{Limit}` → `:330 Limit => $Self->{SearchLimit}`.
- UI: `AgentTicketEscalationView.pm:266` `my $Limit = $ParamObject->GetParam(Param=>'Limit')` →
  `:303 Limit => $Limit`.
The contrast is `AgentTicketSearch.pm:101`, which wraps its Limit in `int()` — proving the
correct handling and that these two callers omit it.

**Dynamic confirmation.** (a) End-to-end: `POST /Ticket/Search` with `Limit=100` → 78 tickets;
`Limit="100 OR 1=1"` → 0 tickets. A parameterised/int-cast implementation would treat the payload
as `100` (or `0`) and still return rows; returning **zero** means the raw string reached the SQL
and made it invalid. (b) Sink: `DB::Prepare(SQL=>"SELECT id FROM ticket", Limit=>"424242 OR
7=7")` → `SELECT id FROM ticket LIMIT 424242 OR 7=7`, MySQL error `… near 'OR 7=7'`.

## Why it is a vulnerability
User input concatenated into a SQL statement without parameterisation or casting is SQL injection
by definition (CWE-89). Here the injectable position is the `LIMIT` clause. On the lab's **MySQL
8**, `LIMIT` accepts only integer literals, so a non-integer payload is a parse error — the query
breaks (empty result / error), giving an availability/error-oracle impact rather than data
extraction. On database backends whose row-limiting grammar is more permissive (PostgreSQL
`LIMIT … OFFSET (subquery)`, Oracle/MSSQL `TOP`), the same sink is fully weaponisable for
UNION-/subquery-based extraction. The defect (verbatim interpolation of attacker input) is
database-independent; only the *ceiling* of exploitation is DB-dependent. Source-diff: prior
TicketSearch SQLi fixes addressed `ContentSearch`/CVE-2022-4427, not this `Limit` sink.

## Reproduction
1. Import `GenericTicketConnectorREST`. 2. `POST /Ticket/Search` with `Limit=100` (rows) then
`Limit="100 OR 1=1"` (empty). 3. `./run.sh` also drives `DB::Prepare` to print the interpolated
SQL + MySQL error. Proof lines:
```
[PROOF] Limit=100 -> 78 tickets;  Limit='100 OR 1=1' -> 0 tickets (injection breaks the query)
[PROOF] DB::Prepare(Limit='424242 OR 7=7') MySQL error: You have an error in your SQL syntax … near 'OR 7=7'
```

## Impact
On MySQL8: error-based/DoS (attacker breaks searches / escalation views; an error/timing oracle
is theoretically constructible within integer LIMIT grammar). On other supported DBs: full SQL
injection → data extraction from the ticket database (customer PII, other tenants' tickets,
password hashes → VULN-030). Reachable by any agent (UI) or any GI user (API).

## Suggested fix
Coerce once at the framework sink: in `DB::Prepare`, `$Limit = int($Limit || 0);` (and
`$Start = int($Start || 0);`) before building the clause — closing all callers at the sink. Also
cast/validate `Limit` in `TicketSearch.pm:345` and the GI operation.

## References
- OWASP WSTG-INPV-05 (SQL Injection); OWASP SQL Injection Prevention Cheat Sheet. CWE-89.
  CVE-2022-4427 (adjacent TicketSearch SQLi, different sink).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. ZSA-2022-07 and OSA-2022-15 (CVE-2022-4427) advisory pages fetched — "SQL injection in Kernel::System::Ticket::TicketSearch via the TicketSearch web service"; no parameter named
2. Znuny fix commit 29c22cc ("CVE-2022-4427: Fixed SQL injection in TicketSearch.pm") diff fetched — only the time-based filters (`*OlderDate`/`*NewerDate`, TicketChangeTime/CloseTime/PendingTime) were anchored and de-interpolated; the diff does not touch `Limit`
3. ZSA-2026-15 / CVE-2026-93484 (NVD text) — `ContentSearch` concatenated into the TicketSearch / ArticleSearchIndex SQL; fixed 7.3.7; a different parameter and clause
4. ZSA-2026-13 / CVE-2026-48188 advisory page fetched — `Kernel::System::Auth::DB` login username quoting (NO_BACKSLASH_ESCAPES); different module
5. NVD API keyword pull for "Znuny"/"OTRS" grepped for SQL / LIMIT — CVE-2010-0438 (Ticket.pm, 2010), CVE-2022-4427, CVE-2024-32493 (draft form ID AJAX), CVE-2026-48188, CVE-2026-93484, CVE-2026-6060 (SQL Box DoS); none concerns the `LIMIT`/`TOP` clause in `DB::Prepare`
6. Znuny advisory index, GitHub advisory DB, Debian tracker reviewed; `gh search issues "Limit SQL injection"` — none. (Shared WebSearch budget was exhausted before this finding.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2022-4427 / ZSA-2022-07 / OSA-2022-15 — same function (`TicketSearch`) and same web-service entry point, but the injectable inputs were the time-filter parameters; `Limit` was not part of the fix
- CVE-2026-93484 / ZSA-2026-15 — same function, `ContentSearch` parameter; fixed before the audited commit
- CVE-2024-32493 / ZSA-2024-03 — SQL injection in a draft-form-ID AJAX parameter; different module

**Reasoning:** Two prior SQL-injection advisories cover `TicketSearch`, but their fix diffs and descriptions address the time-filter and `ContentSearch` inputs, and the `Limit` value still reaches `DB::Prepare` verbatim on the post-7.3.7 commit (dynamically confirmed), so no public disclosure matches this sink (`TicketSearch.pm:345` / `DB.pm:732`) via GI `TicketSearch` or `AgentTicketEscalationView`. Confidence is 80 rather than higher because the function is a repeatedly audited hot-spot and a researcher could have reported `Limit` privately.
