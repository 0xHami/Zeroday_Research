# VULN-006 — Unbounded `tableRecordsPerPage` forces a full-table load (DoS)

**Software**: Filament
**Repository**: https://github.com/filamentphp/filament
**Affected version**: v4.14.0 (git tag; `composer.json` has no `version`, tag authoritative)
**Status**: CONFIRMED
**Severity (static)**: Medium
**Confidence**: 8/10
**Confidence reasoning**: Proven — one authed request crashed the worker with an OOM fatal (512M) on a 120k-row table; baseline 0.23s. Near-universal surface (pagination on by default). Not 9+ only because impact is availability, not data.
**Target commit**: 154a22c52498a5400ae53fe64e772f8eb09946aa
**Validated at**: 2026-10-01

## Preconditions
- Lab up; low-priv seeded user `ryan@filamentphp.com` / `password`.
- A large backing table — `automation.py` bulk-seeds the `posts` table to ~120k rows via `generate_series` (additive; random slug suffix).
- Web PHP `memory_limit=512M`, `max_execution_time=0` (so the crash is OOM, not timeout).

## Request
See `request.http`. Decisive call: `POST /livewire/update` on the list-posts
component with `updates={"tableRecordsPerPage":"all"}`, `calls=[]`.

## Response
HTTP 500 (`response.txt`). App log (`evidence/oom_log.txt`):
`production.ERROR: Allowed memory size of 536870912 bytes exhausted (tried to allocate 167772160 bytes)`
raised inside the compiled table view while rendering all rows.

## Observation
Exactly as predicted. Baseline `perPage=10` → HTTP 200 in 0.23s. The identical
request with the public property `tableRecordsPerPage='all'` → HTTP 500 after
~28s, OOM. `'all'` is turned into the full row count as the SQL LIMIT
(`CanPaginateRecords.php:55`) and every row is hydrated into an Eloquent model
and rendered. The page-options allowlist is never consulted in the live getter
(`:63-66` returns the value verbatim). A value not in the options (e.g. 7777777)
is likewise honored — confirmed there is no server-side validation at all.

## Side effects
- Adds ~120k filler rows to `posts` (additive; safe). The 500 is a recoverable
  worker crash (Apache process restarts). To restore the small dataset:
  `docker exec cvehunterlab_filament_app php artisan migrate:fresh --seed --force`.

## Research & references
- OWASP WSTG — Testing for ... Resource Exhaustion; CWE-770 Allocation of
  Resources Without Limits or Throttling. Technique applied: a client-controlled
  result-set-size input with no server-side upper bound → single-request
  memory exhaustion. https://owasp.org/www-project-web-security-testing-guide/

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
If the exploit prints NEEDS_MANUAL it means 512M was not exceeded at the seeded
row count — raise `DOS_ROWS` and re-run; the code defect (no clamp) is unchanged.

## If INTENDED
Not INTENDED. `'all'` being offered is a UI convenience, but the absence of any
server-side bound on a client-controlled LIMIT is not documented as deliberate;
the vendor's own fix direction (reject off-allowlist values) confirms it should
be bounded.
