# VULN-011 — Repeater/Builder accept an unbounded number of client items (DoS)

**Software**: Filament
**Repository**: https://github.com/filamentphp/filament
**Affected version**: v4.14.0 (git tag; `composer.json` has no `version`, tag authoritative)
**Status**: CONFIRMED
**Severity (static)**: Medium (low end)
**Confidence**: 6/10
**Confidence reasoning**: Proven — a single UNAUTHENTICATED 25k-item submit burns the 30s budget → 500 (baseline 0.13s). Weakest of the DoS family (needs a repeater/builder form), but reachable pre-auth on demo pages, hence 6.
**Target commit**: 154a22c52498a5400ae53fe64e772f8eb09946aa
**Validated at**: 2026-10-01

## Preconditions
- Lab up. Unauthenticated demo form `/forms/fields/repeater` mounts
  `Repeater::make('repeater')` (sub-fields name+role) with no `maxItems()`.
- `post_max_size=25M` bounds the body; 25k items ≈ 1 MB (well within).

## Request
See `request.http`. `POST /livewire/update` setting public `data.repeater` to a
25,000-element array, `calls=[]`.

## Response
HTTP 500 after ~31s (`response.txt`). App log (`evidence/dos_log.txt`):
`Maximum execution time of 30 seconds exceeded` (at ~60k items it instead OOMs:
`Allowed memory size ... exhausted`).

## Observation
As predicted. Baseline 5-item repeater → 200 in 0.13s. 25,000 items → HTTP 500 after
31.35s. Work scales with item count: 2,000 items already took 5.35s. One child schema
(TextInput `name` + Select `role`) is hydrated per item on re-render; with `maxItems`
null (`CanLimitItemsLength.php:10`) there is no server-side ceiling — the `max:` rule
is only registered if `maxItems()` is called.

## Side effects
- None persisted (the demo form has no backing save; this only hydrates/validates
  transient state). The 500 is a recoverable worker crash. Random item names per run.

## Research & references
- CWE-770. OWASP application-DoS. Technique: inflate a client-controlled collection to
  force O(items) server-side object construction per request.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
If it prints NEEDS_MANUAL, the item count didn't exceed the budget — raise
`REPEATER_ITEMS` (stay under ~400k so the body is < post_max_size=25M).

## If INTENDED
Not INTENDED. `maxItems()` is documented as a validation option, but the absence of
any conservative default cap on hydrated items is not stated as deliberate; it is the
same unbounded-input pattern as the rest of the DoS family.
