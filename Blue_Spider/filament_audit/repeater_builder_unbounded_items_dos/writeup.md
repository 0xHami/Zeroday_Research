# VULN-011 — `Repeater`/`Builder` accept an unbounded number of client items (DoS)

| | |
|---|---|
| **ID** | VULN-011 |
| **Software** | Filament |
| **Repository** | https://github.com/filamentphp/filament |
| **Affected version** | v4.14.0 |
| **Commit** | `154a22c52498a5400ae53fe64e772f8eb09946aa` |
| **Severity** | Medium (low end) |
| **CVSS 3.1** | 4.3 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` (PR:N on the unauth demo pages raises it) |
| **Status** | CONFIRMED (dynamic) |
| **Confidence** | 6/10 |
| **Confidence reasoning** | Single unauth 25k-item submit → 30s burn → 500; weakest of the DoS family, needs a repeater/builder form. |
| **Auth required** | None on the lab demo form page; otherwise any user of a form with a repeater/builder |
| **Attacker gains** | Crashes a request worker with one oversized form submit; repeatable → outage |

## Summary

A `Repeater`/`Builder` instantiates, hydrates and validates **one full child schema
per item** in the client-submitted array; nested repeaters multiply the work. The
`maxItems()` cap is opt-in validation only — with it unset (the default) there is no
server-side ceiling on item count. Because the item array is a public, client-
controlled Livewire property, a single submit carrying tens of thousands of items
forces proportional per-request work, enough to exhaust the 30s execution budget (or
512 MB memory) and crash the worker. On the lab's unauthenticated demo form pages this
is a pre-auth DoS.

## How it works (mechanism & code trace)

**The missing default cap** —
`packages/forms/src/Components/Concerns/CanLimitItemsLength.php`:

```php
protected int | Closure | null $maxItems = null;      // :10 — no default cap

public function maxItems(int | Closure | null $count): static
{
    $this->maxItems = $count;
    $this->rule('array', static fn (Component $c): bool => $c->getMaxItems() !== null);
    $this->rule(static fn (Component $c): string => "max:{$c->getMaxItems()}",
        static fn (Component $c): bool => $c->getMaxItems() !== null);   // max: added ONLY if maxItems() called
    return $this;
}
```

So the `max:` rule exists only once a developer opts in; by default there is no limit.

**The O(items) hydration** — `packages/forms/src/Components/Repeater.php:185` (and
`Builder.php:158-168`) iterate one child schema per client item:

```php
foreach ($this->getRawState() ?? [] as $itemData) {   // one child schema per item
    ...
}
```

Each child here is a `TextInput` (`name`) plus a `Select` (`role`); nested
repeaters/builders recurse via `schemas/.../HasComponents.php::getFlatComponents()`.

**Taint source** — `data.repeater` is a public Livewire property (not `#[Locked]`),
mass-assigned from the request; the attacker sets it to a 25k-element array.

**Why the framework doesn't save it** — there is no global per-request cap on
hydrated schema nodes, so the item count directly drives CPU/memory. Measured: 2,000
items already cost 5.35s; 25,000 items exhaust the 30s budget.

## Why it is a vulnerability

The invariant is that a client-controlled input count must have a conservative
default bound. The broken assumption is that form state carries human-sized item
counts; instead the server performs O(items) schema instantiation + validation +
hydration per submit, unbounded. That is uncontrolled resource consumption
(CWE-770). It is not intended: `maxItems()` exists precisely to bound this, but is
off by default and there is no global ceiling.

## Reproduction

1. **Precondition:** a form with a `Repeater`/`Builder` and no `maxItems()` — the lab
   demo `/forms/fields/repeater` (unauthenticated).
2. **Baseline:** set `data.repeater` to 5 items → HTTP 200 in ~0.1s.
3. **Attack:** set `data.repeater` to ~25,000 items (see `request.http`).
4. **Run:** `./run.sh` → `[OK] exploit confirmed`, exit 0.

Observed (`run.log`, `evidence/dos_log.txt`):

```
baseline: 5-item repeater → HTTP 200 in 0.13s
attack:   25000 items (1,013,890 bytes) → HTTP 500 after 31.35s
app log:  production.ERROR: Maximum execution time of 30 seconds exceeded
```

## Impact

A single submit crashes the PHP worker (availability). The static score is A:L /
4.3 (framed as degradation and the weakest of the DoS family), but the observed
single-request behaviour is a full worker crash; with no default throttle (F22) it
loops for sustained outage. Pre-auth on the demo form pages (PR:N), otherwise any
authenticated form user. Part of the DoS family (VULN-006/-007/-008).

## Suggested fix

Apply a conservative default item cap (overridable upward via `maxItems()`):

```php
// CanLimitItemsLength: a safe default, and always register the bound
protected int | Closure | null $maxItems = 1000;   // sensible default; apps raise it explicitly

public function maxItems(int | Closure | null $count): static
{
    $this->maxItems = $count;
    // register the array + max: rules unconditionally against getMaxItems()
    ...
}
```

Alternatively enforce a global per-request ceiling on hydrated schema nodes.
Principle: bound client-controlled collection sizes by default.

## References

- CWE-770 Allocation of Resources Without Limits or Throttling.
- OWASP — application-level DoS via oversized input collections.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Vendor advisory list `github.com/filamentphp/filament/security/advisories` (pages 1–2, 19 advisories) — no Repeater/Builder or item-count DoS advisory.
2. GitHub Advisory Database, Composer ecosystem, query `filament` — none about Repeater/Builder.
3. Project issue tracker query `is:issue repeater maxItems memory exhausted` — 0 results.
4. PR #20259 / issue #20223 fetched — the vendor defaulted complexity limits for the QueryBuilder filter in v6 citing "high resource consumption if excessively large or deeply nested condition trees are submitted"; no equivalent change or issue for Repeater/Builder item counts. (Web-search quota exhausted; checks via direct fetch of primary sources.)

**Related but distinct public references** (same class or component, not this bug):
- Issue #20223 / PR #20259 — same vulnerability class (client-controlled structure size, opt-in limit) acknowledged and defaulted for QueryBuilder, not for Repeater/Builder.
- Filament docs `maxItems()` — documented opt-in validation, framed as a form-validation feature, not a resource bound.

**Reasoning:** Nothing public describes unbounded client item arrays in Repeater/Builder as a server-side resource-exhaustion issue or proposes a default cap. Confidence is moderate because the class is generic, the vendor's handling of the analogous QueryBuilder case was as a resource-consumption improvement (not a security advisory), and DoS of this shape is often treated as hardening.
