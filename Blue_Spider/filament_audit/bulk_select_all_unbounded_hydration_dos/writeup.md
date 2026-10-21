# VULN-007 — Bulk "select-all" hydrates the entire table into memory (DoS)

| | |
|---|---|
| **ID** | VULN-007 |
| **Software** | Filament |
| **Repository** | https://github.com/filamentphp/filament |
| **Affected version** | v4.14.0 |
| **Commit** | `154a22c52498a5400ae53fe64e772f8eb09946aa` |
| **Severity** | Medium |
| **CVSS 3.1** | 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` |
| **Status** | CONFIRMED (dynamic) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | One request hydrated a 350k-row table → OOM in 6.5s; row count unchanged. Needs a bulk action + large table. |
| **Auth required** | Any authenticated user who can reach a table with a bulk action |
| **Attacker gains** | Crashes a request worker with a single "select all + run bulk action"; repeatable → outage |

## Summary

Filament implements "select all records" not as an explicit id list but as
**deselection tracking**: a boolean flag plus a list of records the user
de-selected. All three inputs — `$isTrackingDeselectedTableRecords`,
`$deselectedTableRecords`, `$selectedTableRecords` — are public, non-`#[Locked]`
Livewire properties. With tracking on and an **empty** deselect list, the selection
query becomes `whereKeyNot([])`, which Laravel renders as an always-true predicate
(the whole table). When any fetching bulk action runs (the shipped
`DeleteBulkAction` fetches by default), the framework resolves `$records` by running
`->get()` with no cap and no chunking, hydrating every in-scope row into an Eloquent
model in a single request — exhausting memory on a large table.

## How it works (mechanism & code trace)

**The client-controlled selection** —
`packages/tables/src/Concerns/HasBulkActions.php`:

```php
public array $selectedTableRecords = [];            // :24-31 — all client-writable, not #[Locked]
public array $deselectedTableRecords = [];
public bool  $isTrackingDeselectedTableRecords = false;

// getSelectedTableRecordsQuery():
if ($this->isTrackingDeselectedTableRecords) {
    $query = $table->getQuery()->whereKeyNot($this->deselectedTableRecords);   // :303 — whereKeyNot([]) ⇒ ALL rows
} else {
    $query = $table->getQuery()->whereKey($this->selectedTableRecords);
}
if ($maxSelectableRecords) {                                                    // :308 — only if a cap was set
    $query->limit($maxSelectableRecords);
}
```

**The unbounded hydration** (same file):

```php
} elseif ($chunkSize) {
    $resolvedSelectedRecords = $query->lazyById($chunkSize);
} else {
    $resolvedSelectedRecords = $this->hydratePivotRelationForTableRecords($query->get());   // :284 — whole table into models
}
```

**The defaults that make it fire** — `$maxSelectableRecords = null`
(`Table/Concerns/HasBulkActions.php:28`), and
`packages/actions/src/Concerns/CanFetchSelectedRecords.php:9,11`:
`$shouldFetchSelectedRecords = true`, `$selectedRecordsChunkSize = null`. So by
default a bulk action fetches, with no cap and no chunk.

**Order of operations (why it's non-destructive as triggered)** — `DeleteBulkAction`
(`DeleteBulkAction.php:82`) receives `$records` as a hydrated collection; the
framework hydrates it *before* invoking the action body. On a table large enough
that `->get()` alone exceeds the memory limit, the fatal error aborts the request
during hydration — before the delete loop runs. This exploit asserts the row count
is unchanged afterward, confirming the crash preceded any mutation.

## Why it is a vulnerability

The invariant is that a client-driven record-set size must be bounded server-side.
The broken assumption is that a bulk action operates on a user-sized selection;
instead "select all" resolves to the entire table scope with no cap and no chunk, so
the hydrated set is bounded only by table size — a client-triggered unbounded memory
allocation (CWE-770). Chained with the documented default of no per-record bulk
authorization (report F8), on a broadly-scoped custom table the same primitive also
*operates* on every in-scope row the user shouldn't touch — but the availability
impact proven here stands on its own.

## Reproduction

1. **Precondition:** a table with a bulk action (PostResource ships
   `DeleteBulkAction`) and a large table. `automation.py` seeds `posts` to ~350k
   rows — sized so hydration OOMs before the delete loop.
2. **Auth:** log in as `ryan@filamentphp.com` / `password`.
3. **Select all:** set `isTrackingDeselectedTableRecords=true`,
   `deselectedTableRecords=[]`, `selectedTableRecords=[]`.
4. **Mount + execute:** `mountAction("delete", [], {table:true, bulk:true})` then
   `callMountedAction` (see `request.http`).
5. **Run:** `./run.sh` → `[OK] exploit confirmed`, exit 0.

Observed (`run.log`, `evidence/oom_log.txt`):

```
mountAction(delete,bulk) → HTTP 200 in 0.09s   (confirm modal; cheap COUNT)
callMountedAction        → HTTP 500 after 6.51s
app log: Allowed memory size of 536870912 bytes exhausted
row count before=350000 after=350000  (UNCHANGED — OOM preceded any delete)
```

## Impact

A single authenticated request crashes the PHP worker (A:H). Reachable on any table
exposing a bulk action — ubiquitous across panel resources and custom tables. With
no default throttle (F22) it loops for sustained outage. Chains with F8 for an
integrity angle on broadly-scoped custom tables. Part of the DoS family
(VULN-006/-008/-011).

## Suggested fix

Give select-all a safe default bound and/or always chunk the resolution:

```php
// HasBulkActions: a conservative default cap, and chunked resolution
$query = $this->isTrackingDeselectedTableRecords
    ? $table->getQuery()->whereKeyNot($this->deselectedTableRecords)
    : $table->getQuery()->whereKey($this->selectedTableRecords);

$cap = $maxSelectableRecords ?? config('filament.tables.max_bulk_records', 10_000);
$query->limit($cap);

// resolve in chunks by default so the whole set is never materialised at once
$chunkSize = $this->getSelectedRecordsChunkSize() ?? 1_000;
$resolvedSelectedRecords = $query->lazyById($chunkSize);
```

Principle: never hydrate a client-sized record set unboundedly; default to a cap +
chunked/lazy iteration, letting developers opt into larger explicit limits.

## References

- CWE-770 Allocation of Resources Without Limits or Throttling.
- OWASP WSTG — application-level DoS via unbounded result-set materialisation.
- Laravel query builder `whereKeyNot([])` semantics (empty array ⇒ no constraint).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Vendor advisory list `github.com/filamentphp/filament/security/advisories` (pages 1–2, 19 advisories) — no bulk-action / select-all / memory-exhaustion advisory.
2. GitHub Advisory Database, Composer ecosystem, query `filament` — closest is CVE-2026-48500 (unauthenticated temporary upload on auth pages), a different resource-exhaustion path.
3. Project issue tracker query `is:issue bulk action select all memory exhausted` — 0 results.
4. Vendor docs `filamentphp.com/docs/4.x/tables/actions` — states "By default, a bulk action will load all Eloquent records into memory" and documents `chunkSelectedRecords()`, `fetchSelectedRecords(false)`, `maxSelectableRecords()`, `selectCurrentPageOnly()` as opt-ins; no default limit is specified. (Web-search quota exhausted; checks via direct fetch of primary sources.)

**Related but distinct public references** (same class or component, not this bug):
- Filament bulk-action docs — publicly state the load-everything default and the opt-in mitigations, framed as performance guidance rather than a client-triggerable DoS.
- CVE-2026-48500 / GHSA-44wp-g8f4-f4v5 — unauthenticated temp-upload exhaustion, different component.

**Reasoning:** No advisory or issue frames select-all plus a fetching bulk action as an unbounded, client-triggered hydration DoS, and no fix defaults `maxSelectableRecords`/chunking on. Confidence is only moderate because the vendor documentation openly describes the "load all records into memory" default and ships the mitigations, so the vendor is likely to treat this as documented behaviour / hardening rather than a new vulnerability.
