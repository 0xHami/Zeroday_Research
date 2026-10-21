# VULN-017 — AOR_Reports condition `field` used as a raw column identifier (SQL injection)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 3.1 8.1 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:27Z (lab wall-clock, see run.log — final run; an earlier run at 20:20:19Z against the same payload construction also CONFIRMED with a 1-row table, see "Row-count note" below)

## Preconditions
- `./run.sh` creates a fresh **non-admin** SuiteCRM user via the admin session (`_common.create_user`), then logs that user in over the web session (`_common.web_login`). No pre-existing state required.
- Uses `report_module=AOK_KnowledgeBase` (Knowledge Base), chosen because it started this audit with exactly **1 live row**. This choice matters: a `(SELECT SLEEP(N))` subquery placed in this WHERE clause is evaluated **once per candidate row** of the report's base table in this MySQL 8.0 instance (confirmed empirically — see "Research & references"), and `LIMIT` does not short-circuit that. Injecting against a 52-row table (Accounts) would multiply the delay ~52x.
- **Row-count note**: this lab is shared with other concurrent stage-10 sessions that insert rows into arbitrary tables mid-run. Between this finding's first successful run and its final run, a sibling session's own exploit added 2 Knowledge Base articles, growing `aok_knowledgebase` from 1 → 2 rows. `automation.py` reads the live row count (`get_row_count()`) immediately before timing and scales its expected delay/tolerance by it (`row_count × N`) instead of assuming a fixed count, so the assertion stays correct either way — the final run below shows `row_count=2`, hence ~2× the raw `SLEEP(N)` values.

## Request
Two HTTP steps (both captured for the SLEEP(3) case in `request.http`):
1. `POST /index.php` `module=AOR_Reports&action=Save` — plants an `AOR_Conditions` row whose `field` is `id IS NULL OR (SELECT SLEEP(3)))#` (URL-encoded in the body).
2. `GET /index.php?module=AOR_Reports&action=export&record=<id>` — triggers `AOR_Report::build_report_csv()` → `build_report_query()` → `build_report_query_where()`, which interpolates that `field` value raw into the WHERE clause and executes it. This is the **timed** request.

## Response
`response.txt` — `HTTP/1.1 200`, `Content-Disposition: attachment; filename="....csv"` (a real CSV-export response, 0 body rows since the injected boolean happens to match none), with **6.20s wall-clock elapsed** captured alongside the headers (SLEEP(3) × 2 live rows).

## Observation
Three reports were created and each `action=export` timed (final run, `row_count=2`):

| case | condition `field` | elapsed |
|---|---|---|
| baseline | `id` | 0.05s |
| inject SLEEP(2) | `id IS NULL OR (SELECT SLEEP(2)))#` | 4.22s |
| inject SLEEP(3) | `id IS NULL OR (SELECT SLEEP(3)))#` | 6.20s |

Deltas vs baseline: **+4.17s** for `SLEEP(2)` (expected `2×2=4.0s`), **+6.15s** for `SLEEP(3)` (expected `2×3=6.0s`) — the delay tracks `row_count × attacker-chosen N` almost exactly and is monotonic (SLEEP(3) run slower than SLEEP(2) run), which is what the static finding predicted: the WHERE builder never validates `condition->field` against `field_defs` (unlike the SELECT builder), so it is spliced in and executed as live SQL. An earlier run against the same payload construction, back when `row_count=1`, showed the same pattern at 1× scale (baseline 0.04s, +2.01s, +3.00s) — the mechanism is identical; only the shared lab's row count changed between runs.

Also confirmed the **write path**: `SELECT field FROM aor_conditions WHERE aor_report_id IN (...)` via the `db` container shows the stored `field` column is **byte-for-byte identical** to what was POSTed (parens, spaces, digits, `#` all intact) — `securexss()` (`include/utils.php:2608`) only rewrites `"'<>\`` and our payload uses none of those, so nothing on the request or storage path interferes with the identifier-context injection.

## Side effects
- 1 non-admin user created (`mod_59a703c3` in the final run; random suffix each run via `_common.rand`/`create_user`).
- 3 `aor_reports` + 3 `aor_conditions` rows created, owned by that user, on module `AOK_KnowledgeBase`. No destructive effect; CSV export is read-only.
- Verified via `docker compose -p cvehunterlab_suitecrm exec -T db mysql ... -e "SELECT id,aor_report_id,field FROM aor_conditions WHERE aor_report_id IN (...)"` (read-only, not part of the attack path — the attack itself is steps 1–2 above over HTTP).

## Research & references
- Technique: PortSwigger "Blind SQL injection with time delays" (https://portswigger.net/web-security/sql-injection/blind) — conditional/unconditional response-time oracle via `SLEEP()`, applied here in an **identifier context** rather than a value/string context, which is why no quote characters are needed and `securexss`'s quote-only filtering is irrelevant.
- OWASP Testing Guide — WSTG-INPV-05 (Testing for SQL Injection), time-based blind subsection.
- MySQL manual, "Optimizing Subqueries" — background for why a non-correlated scalar subquery here is re-evaluated per row rather than materialized once in this plan shape (empirically verified with the `db` container directly: `SELECT accounts.id FROM accounts WHERE (accounts.id IS NULL OR (SELECT SLEEP(1))) LIMIT 1` still took ~52s against the 52-row `accounts` table, i.e. no LIMIT short-circuit), which is why the exploit deliberately targets a 1-row module instead.

## If FAILED
N/A — CONFIRMED.
