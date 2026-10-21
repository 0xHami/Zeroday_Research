# VULN-012 — callSchemaComponentMethod enforces hidden() but not disabled()

**Software**: Filament
**Repository**: https://github.com/filamentphp/filament
**Affected version**: v4.14.0 (git tag; `composer.json` has no `version`, tag authoritative)
**Status**: CONFIRMED
**Severity (static)**: Medium (low end)
**Confidence**: 5/10
**Confidence reasoning**: Mechanism proven live (exposed read method fired on a field rendered `disabled="disabled"`), but incremental impact is low — it only widens the VULN-004 oracle to disabled fields; mutating methods self-guard. Matches the static 5.
**Target commit**: 154a22c52498a5400ae53fe64e772f8eb09946aa
**Validated at**: 2026-10-01

## Preconditions
- Lab up. A FileUpload rendered `->disabled()` exposing `#[ExposedLivewireMethod] getUploadedFiles`.
- HARNESS: the demo has no disabled FileUpload, so `automation.py` temporarily adds one
  (`FileUpload::make('fileUploadDisabled')->disk('public')->disabled()`) to the demo
  component in-container (opcache revalidates ~2s), tests, then reverts it (verified: page
  shows 0 occurrences and no `.bak` after). This uses the documented `->disabled()` feature
  — the normal way a developer disables a field for non-owners — and does **not** touch
  library code. The defect proven is the library dispatcher ignoring `isDisabled()`.
- A victim file is planted on the public disk (as in VULN-004) for the read.

## Request
See `request.http`. `POST /livewire/update` →
`callSchemaComponentMethod("form.fileUploadDisabled","getUploadedFiles")` with
`updates={"data.fileUploadDisabled":{"inj":"<victim path>"}}`.

## Response
`effects.returns` (`response.txt`):
`[{"inj":{"name":"secret-<suffix>.txt","size":70,"type":"text/plain","url":"http://localhost:21890/storage/disabled-victim-<suffix>/secret-<suffix>.txt"}}]`
— and the page HTML shows the field rendered `disabled="disabled"`.

## Observation
Confirmed the inconsistency. The field is genuinely rendered disabled, yet
`callSchemaComponentMethod` (`InteractsWithSchemas.php:83-127`) resolved the component
(`getSchemaComponent` filters hidden, not disabled), confirmed the `#[ExposedLivewireMethod]`
attribute, and invoked `getUploadedFiles` — returning metadata + a readable URL for the
attacker-named path (then fetched: victim content read). The sibling table dispatcher
(`HasColumns.php:63`) *does* `if ($column->isDisabled()) return null;`, so this is a
channel divergence, not a design choice. Mutating FileUpload methods self-guard
(`BaseFileUpload.php:817,892`), so the practical consequence is widening the VULN-004 read
oracle to disabled fields.

## Side effects
- None persisted; harness field reverted (verified pristine). Victim file left for
  inspection (remove `storage/app/public/disabled-victim-*`).

## Research & references
- CWE-862 (missing authorization on one channel) / defense-in-depth channel divergence.
- OWASP WSTG-ATHZ — test that server-side state controls (disabled) are enforced on every
  channel, not just the UI. Chains with VULN-004 (the reachable sink).

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.

## If INTENDED
Not INTENDED. The vendor guards `isDisabled()` in the table dispatcher but not the schema
dispatcher — the asymmetry shows the disabled check was intended but omitted here, not a
documented decision.
