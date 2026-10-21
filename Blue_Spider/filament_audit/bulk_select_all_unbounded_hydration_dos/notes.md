# VULN-007 — Bulk "select-all" hydrates the entire table into memory (DoS)

**Software**: Filament
**Repository**: https://github.com/filamentphp/filament
**Affected version**: v4.14.0 (git tag; `composer.json` has no `version`, tag authoritative)
**Status**: CONFIRMED
**Severity (static)**: Medium
**Confidence**: 7/10
**Confidence reasoning**: Proven — select-all tracking made one request hydrate the whole 350k-row table and OOM the worker (6.5s), row count unchanged (crash preceded any delete). Needs a bulk action + large table, hence 7 not 8.
**Target commit**: 154a22c52498a5400ae53fe64e772f8eb09946aa
**Validated at**: 2026-10-01

## Preconditions
- Lab up; low-priv user `ryan@filamentphp.com` / `password`.
- A bulk action on the table — PostResource ships `DeleteBulkAction` (fetches by default).
- Large backing table — `automation.py` bulk-seeds `posts` to ~350k rows, chosen so
  `->get()` hydration alone exceeds the 512M limit (observed 291MB @ 120k) → the OOM
  lands during hydration, before DeleteBulkAction's delete loop (zero deletes).

## Request
See `request.http`. Two `POST /livewire/update` calls: (1) `mountAction("delete", [], {table,bulk})`
with `updates={isTrackingDeselectedTableRecords:true, deselectedTableRecords:[], selectedTableRecords:[]}`;
(2) `callMountedAction`.

## Response
Step 1 → HTTP 200 in 0.09s (confirm modal). Step 2 → HTTP 500 after ~6.5s
(`response.txt`). App log (`evidence/oom_log.txt`): `Allowed memory size of 536870912 bytes exhausted`.

## Observation
Exactly as predicted. "Select all" is deselection-tracking: with the flag set and
an empty `deselectedTableRecords`, `getSelectedTableRecordsQuery()` builds
`whereKeyNot([])` (every row), and with the default null chunk `getSelectedTableRecords()`
runs `->get()`, hydrating the entire 350k-row table into Eloquent models in one
request → OOM. **Row count before == after == 350000**, proving the crash occurred
during hydration (while resolving `$records`), before the delete loop — so this is a
pure availability bug here, and demonstrably non-destructive as triggered.

## Side effects
- None persisted (no rows deleted — verified by the before/after count). Adds ~350k
  filler rows (additive). The 500 is a recoverable worker crash.
- Restore the small dataset with `php artisan migrate:fresh --seed --force`.

## Research & references
- CWE-770; OWASP WSTG resource-exhaustion. Technique: a client-controlled
  selection expressed as deselection-tracking resolves to the full table scope with
  no server-side cap/chunk → single-request memory exhaustion.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
If it prints NEEDS_MANUAL, hydration fit in 512M at the seeded size — raise
`DOS_ROWS`. (Do not lower it so far that hydration succeeds and the delete loop runs.)

## If INTENDED
Not INTENDED. No default cap/chunk on select-all hydration is not documented as
deliberate; the vendor ships `maxSelectableRecords()`/`chunkSelectedRecords()` as
opt-in mitigations, confirming the unbounded default is an oversight. (Chains with
the documented F8 "no per-record bulk authz" for an integrity angle on broad custom
tables — see report Attack chains.)
