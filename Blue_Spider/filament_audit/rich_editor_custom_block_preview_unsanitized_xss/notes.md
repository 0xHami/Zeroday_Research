# VULN-010 — RichEditor::customBlocks() preview rendered via innerHTML, sanitizer never invoked → stored XSS

**Software**: Filament
**Repository**: https://github.com/filamentphp/filament
**Affected version**: v4.14.0 (git tag; `composer.json` has no `version`, tag authoritative)
**Status**: CONFIRMED
**Severity (static)**: Medium
**Confidence**: 5/10
**Confidence reasoning**: Full chain proven — server base64's the RAW payload (unsanitized) while the reader path strips it, and a real browser executed it via the preview innerHTML. Conditional on a custom block whose toPreviewHtml reflects config (the demo's shipped blocks escape with e()), and detonates in an editor-opening reviewer's session — hence 5.
**Target commit**: 154a22c52498a5400ae53fe64e772f8eb09946aa
**Validated at**: 2026-10-01

## Preconditions
- Lab up. `/forms/fields/rich-editor` mounts `richEditorCustomBlocks` (a RichEditor with customBlocks).
- HARNESS: the demo's shipped blocks escape config in toPreviewHtml (e()), so they're safe. The
  exploit registers a minimal config-reflecting block `RawHtmlBlock`
  (`toPreviewHtml($config) => $config['body']` — the "natural pattern" the finding describes) on the
  field, runs `composer dump-autoload`, tests, then UNregisters + deletes the class + regenerates the
  autoloader (verified pristine: page 200, block gone). No library code changed.

## Request
See `request.http`. Insert flow: `mountAction("customBlock", {id:'rawhtml', mode:'insert',
editorSelection:{type:'node',anchor:0,head:0}}, {schemaComponent:'form.richEditorCustomBlocks'})`
then `callMountedAction` with `mountedActions.0.data.body = <img src=x onerror=...>`.

## Response
`response.txt` (insert dispatch): contains `base64("<img src=x onerror=...>")` in the
`run-rich-editor-commands` dispatch — the RAW payload, unsanitized. `browser.log`:
`TITLE_AFTER=PWNED-<suffix>`, `RESULT=PASS`. Screenshot `evidence/after_insert.png`.

## Observation
Both halves confirmed:
- **Server (sanitizer bypass):** `RichEditorStateCast` computes `base64_encode($block::toPreviewHtml($config))`
  with NO `Str::sanitizeHtml()` (:115). The insert dispatch carried the base64 of the raw
  `<img src=x onerror=...>`. Contrast: the reader path's `Str::sanitizeHtml('<img src=x onerror=...>')`
  → `<img src="x" />` (onerror stripped). So the preview path skips the sanitizer the reader path applies.
- **Client (innerHTML):** `extension-custom-block.js:132` does `preview.innerHTML = atob(node.attrs.preview)`.
  In a real browser, driving the insert made `document.title` become the sentinel — the onerror executed.

## Side effects
- None persisted (the demo field has no DB backing; content is transient). Harness fully reverted.

## Research & references
- PortSwigger Web Security Academy — DOM XSS via `innerHTML` sink; stored XSS through a second,
  unsanitized render path.
- OWASP XSS Prevention Cheat Sheet — all HTML-producing paths must sanitize; CWE-79. The library
  sanitizes the reader path (`Str::sanitizeHtml`) but not the editor-preview path.

## If FAILED
n/a — CONFIRMED end-to-end.

## If NEEDS_MANUAL
n/a (fully automated). Note the deployment condition: a real victim is a higher-priv user who OPENS
content authored by a lower-priv user in an editor configured with the same (config-reflecting) block.

## If INTENDED
Not INTENDED. This is distinct from the documented F4 (where the sanitizer IS invoked but allows
style/class) — here the sanitizer is NOT invoked at all on the preview path, an inconsistency with
the reader path, so it is a sanitizer-bypass defect, not a documented trade-off.
