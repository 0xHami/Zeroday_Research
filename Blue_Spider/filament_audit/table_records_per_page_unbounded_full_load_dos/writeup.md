# VULN-006 — Unbounded `tableRecordsPerPage` forces a full-table load (DoS)

| | |
|---|---|
| **ID** | VULN-006 |
| **Software** | Filament |
| **Repository** | https://github.com/filamentphp/filament |
| **Affected version** | v4.14.0 |
| **Commit** | `154a22c52498a5400ae53fe64e772f8eb09946aa` |
| **Severity** | Medium |
| **CVSS 3.1** | 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` |
| **Status** | CONFIRMED (dynamic) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | One authed request crashed the worker (OOM, 512M) on a 120k-row table; near-universal surface. |
| **Auth required** | Any authenticated panel user (unauthenticated on demo table pages) |
| **Attacker gains** | Crashes a request worker with a single request; repeatable → sustained outage |

## Summary

Every Filament table paginates through a public Livewire property,
`$tableRecordsPerPage`. Livewire mass-assigns it from the request body, and the
live getter returns it **verbatim** — no upper bound and no check that the value
is one of the offered page sizes. The special value `'all'` is translated into the
table's full row count and used as the SQL `LIMIT`, so a single request can make
the server load and render the entire table into memory. On a large table this
exhausts PHP's `memory_limit` and returns HTTP 500, crashing the worker handling
the request. Pagination is on by default, so effectively every panel table is a
target.

## How it works (mechanism & code trace)

**Entry point** — the per-page `<select>` in any table binds (`wire:model`) to the
component's public `$tableRecordsPerPage` property. The attacker does not need the
select: they set the property directly over `/livewire/update`.

**The client-controlled, unbounded property** —
`packages/tables/src/Concerns/CanPaginateRecords.php`:

```php
public $tableRecordsPerPage = null;          // :16 — untyped public property, NOT #[Locked]

public function getTableRecordsPerPage(): int | string | null
{
    return $this->tableRecordsPerPage;        // :63-66 — returned verbatim; no clamp, no allowlist
}
```

**The sink** — the getter feeds `->paginate()` with `'all'` expanded to the row
count:

```php
$total = $query->toBase()->getCountForPagination();
$records = $query->paginate(
    perPage: ($perPage === 'all') ? $total : $perPage,   // :55 — 'all' ⇒ entire table as LIMIT
    pageName: $this->getTablePaginationPageName(),
    total: $total,
);
```

**The exact defect** — the page-options allowlist (`in_array($option, $pageOptions)`)
is applied **only** when deriving the mount-time default (`:82`), never in the live
getter. So after any client update the value is trusted as-is. I also confirmed a
value not in the options (`7777777`) is accepted without validation.

**Why the framework doesn't save it** — there is no global cap on hydrated rows per
request; `->paginate(perPage: <huge>)` issues `SELECT * ... LIMIT <huge>` and
Eloquent hydrates every returned row into a full model, after which the table view
renders each one. Both scale linearly with table size.

## Why it is a vulnerability

The invariant is that a client-controlled resource-sizing input must be bounded
server-side. The broken assumption is that `$tableRecordsPerPage` is constrained to
the offered options — but the allowlist is a UI affordance only, and the server
honours any value, including `'all'` on an arbitrarily large table. The feature is
"let the user choose a page size"; the actual capability granted is "let any user
force an unbounded full-table materialisation per request." That is resource
allocation without limits (CWE-770), not intended behaviour.

## Reproduction

1. **Precondition:** a large table. `automation.py` bulk-seeds `posts` to ~120k
   rows (`generate_series`, ~4s).
2. **Auth:** log in as the low-priv user `ryan@filamentphp.com` / `password`.
3. **Baseline:** `POST /livewire/update` with `tableRecordsPerPage=10` → HTTP 200
   in ~0.2s.
4. **Attack:** the same request with `tableRecordsPerPage='all'` (see
   `request.http`).
5. **Run:** `./run.sh` → `[OK] exploit confirmed`, exit 0.

Observed (`run.log`, `evidence/oom_log.txt`):

```
baseline: perPage=10 → HTTP 200 in 0.23s
attack:   perPage='all' → HTTP 500 after 27.63s
app log:  production.ERROR: Allowed memory size of 536870912 bytes exhausted
          (tried to allocate 167772160 bytes) ... storage/framework/views/...php:2954
```

The 512 MB `memory_limit` is exhausted inside the compiled table view — i.e. the
worker crashed hydrating/rendering all 120k rows.

## Impact

A single authenticated request crashes the PHP worker serving it (A:H). There is
no default throttle on `/livewire/update` (see report finding F22), so the request
can be looped for sustained outage across workers. No confidentiality/integrity
impact. Reachable by any authenticated panel user on any paginated table — and on
the lab's unauthenticated demo table pages, by anyone. Part of the DoS family with
VULN-007/-008/-011; F22 is the amplifier.

## Suggested fix

In `getTableRecordsPerPage()`, validate against the offered options and fall back
to the default:

```php
public function getTableRecordsPerPage(): int | string | null
{
    $value = $this->tableRecordsPerPage;
    $options = $this->getTablePaginationPageOptions();   // the offered page sizes
    if (! in_array($value, $options, strict: false)) {
        return $this->getDefaultTableRecordsPerPage();   // ignore tampered/off-list values
    }
    return $value;
}
```

If `'all'` must remain available, cap the materialised row count (e.g. chunked
streaming or a hard ceiling). Principle: never derive an unbounded SQL `LIMIT` from
a client-controlled value.

## References

- CWE-770 Allocation of Resources Without Limits or Throttling.
- OWASP WSTG — Testing for Account/Resource Exhaustion; application-level DoS via
  unbounded result sets.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Vendor advisory list `github.com/filamentphp/filament/security/advisories` (pages 1–2, 19 advisories) — no DoS / pagination / `tableRecordsPerPage` advisory.
2. GitHub Advisory Database, Composer ecosystem, query `filament` — 14 `filament/*` advisories, none about pagination or resource exhaustion via page size.
3. Project issue tracker query `is:issue tableRecordsPerPage` — nine closed issues (e.g. #12554 "QueryBuilder with Actions memory exhausts", #15168/#15169 modal performance); titles concern developer-side performance, none report client tampering of the page size.
4. Vendor docs `filamentphp.com/docs/4.x/tables/overview` pagination section — only a developer-facing note: "Be aware when using very high numbers and `all` as large number of records can cause performance issues"; nothing about server-side validation of the chosen size. (Web-search quota exhausted; checks via direct fetch of primary sources.)

**Related but distinct public references** (same class or component, not this bug):
- Filament docs pagination warning — addresses developers who *offer* `'all'`/large options, not the fact that the live getter accepts any client value regardless of the offered options.
- Issue #20223 / PR #20259 (QueryBuilder complexity limits defaulted in v6) — vendor precedent for defaulting resource caps, different component.

**Reasoning:** No advisory or issue describes the client-controlled `$tableRecordsPerPage` bypassing the offered-options allowlist to force a full-table load. The docs acknowledge that `'all'` is expensive, so the vendor may treat this as a known performance trade-off and a low-severity hardening item; DoS findings in this project have not received advisories, which lowers confidence that it would be considered novel/security-relevant.
