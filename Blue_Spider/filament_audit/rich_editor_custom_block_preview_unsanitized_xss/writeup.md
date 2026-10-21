# VULN-010 — `RichEditor::customBlocks()` preview rendered via `innerHTML`, sanitizer never invoked → stored XSS

| | |
|---|---|
| **ID** | VULN-010 |
| **Software** | Filament |
| **Repository** | https://github.com/filamentphp/filament |
| **Commit** | `154a22c52498a5400ae53fe64e772f8eb09946aa` |
| **Affected version** | v4.14.0 |
| **Severity** | Medium |
| **CVSS 3.1** | 4.4 — `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N` |
| **Status** | CONFIRMED (dynamic) — preview innerHTML executed |
| **Confidence** | 5/10 |
| **Confidence reasoning** | Full chain proven (server unsanitized + browser execution); conditional on a custom block whose toPreviewHtml reflects config and a reviewer opening it. |
| **Auth required** | Low-priv author to store the block; fires in an editor-opening (often higher-priv) user's session |
| **Attacker gains** | Script execution in a reviewer/admin session that opens the attacker's content in the editor |

## Summary

RichEditor custom blocks have two render paths: `toHtml($config)` for readers and
`toPreviewHtml($config)` shown inline in the editor. The reader path is deliberately sanitized
(`RichContentRenderer::toHtml()` runs `Str::sanitizeHtml()`); the **editor-preview path is not**.
The preview HTML is computed from attacker-controlled block config, base64-encoded server-side with
**no `Str::sanitizeHtml()`**, and injected client-side via **`innerHTML`**. A low-privilege author
whose block config carries an HTML/JS payload therefore gets script execution when a higher-privilege
user opens that content in an editor configured with the same block. Proven end-to-end: driving the
custom-block insert flow made `document.title` become the attacker's sentinel in a real browser.

## How it works (mechanism & code trace)

**Server — preview computed unsanitized** —
`packages/forms/src/Components/RichEditor/StateCasts/RichEditorStateCast.php:100-117`:

```php
if ($this->richEditor->getCustomBlocks()) {
    $editor->descendants(function (object &$node): void {
        if ($node->type !== 'customBlock') { return; }
        $block = $this->richEditor->getCustomBlock($node->attrs->id);
        if (blank($block)) { return; }
        $nodeConfig = json_decode(json_encode($node->attrs->config ?? []), associative: true);   // :112 CLIENT config
        $node->attrs->label = $block::getPreviewLabel($nodeConfig);
        $node->attrs->preview = base64_encode($block::toPreviewHtml($nodeConfig));                 // :115 NO Str::sanitizeHtml()
        ...
    });
}
```

**Client — injected via innerHTML** —
`packages/forms/resources/js/components/rich-editor/extension-custom-block.js:121-137`:

```js
if (node.attrs.preview) {
    const preview = document.createElement('div')
    preview.innerHTML = new TextDecoder().decode(                 // :132 RAW innerHTML, no sanitize/escape
        Uint8Array.from(atob(node.attrs.preview), (char) => char.charCodeAt(0)),
    )
    dom.appendChild(preview)
}
```

**The contrast (the defect)** — the reader path sanitizes: `RichContentRenderer::toHtml()` runs
`Str::sanitizeHtml()` (`:576-583`). I verified `Str::sanitizeHtml('<img src=x onerror=...>')` →
`<img src="x" />` (onerror stripped) and `<script>…</script>` → `` (removed). The preview path never
calls it, so whatever `toPreviewHtml()` returns is injected raw. (This is distinct from the documented
F4, where the sanitizer *is* invoked but permissively allows `style`/`class` — here it is not invoked
at all.)

## Why it is a vulnerability

The invariant is that *all* RichEditor render paths are sanitized (the reader path is). The editor-
preview path treats attacker-derived HTML as trusted and hands it to `innerHTML`, so a block whose
`toPreviewHtml()` reflects config (the natural pattern — rendering an author-supplied title/body)
yields stored XSS that detonates in editors' sessions — typically higher-privileged reviewers opening
lower-privileged authors' submissions. A sanitizer-bypass inconsistency (CWE-79), not a documented
trade-off.

## Reproduction

`./run.sh` (self-contained; drives Livewire + a real browser):

1. **Harness precondition:** the demo's shipped blocks escape config (`e()`), so the exploit registers
   a minimal config-reflecting block (`RawHtmlBlock`, `toPreviewHtml => $config['body']` — the natural
   pattern) on `richEditorCustomBlocks`, `composer dump-autoload`, and reverts it afterwards (verified
   pristine). No library code changed.
2. **Server proof:** `mountAction('customBlock', {id:'rawhtml', mode:'insert', editorSelection:…},
   {schemaComponent:'form.richEditorCustomBlocks'})` → `callMountedAction` with
   `mountedActions.0.data.body = <img src=x onerror="document.title='PWNED-<suffix>'">`.
3. **Browser proof:** the same flow in Chromium.

Observed (`run.log`, `response.txt`, `browser.log`, `evidence/after_insert.png`):

```
preview path emitted base64 of the RAW payload (unsanitized): True
reader path Str::sanitizeHtml('<img onerror...>') → '<img src="x" />'   (onerror stripped)
document.title after insert = 'PWNED-<suffix>'                           (innerHTML executed the payload)
RESULT=PASS
```

## Impact

Stored XSS detonating in the session of any user who opens the attacker's content in a RichEditor
configured with the same custom blocks — typically a higher-privileged reviewer/admin reviewing a
lower-privileged author's submission (S:C, UI:R, AC:H). Base 4.4; the real-world ceiling is High if
the victim is an admin (the XSS can drive `/livewire/update` as the admin). Escalates like VULN-002's
stored-XSS variant and VULN-009.

## Suggested fix

Sanitize the preview path exactly as the reader path does:

```php
// RichEditorStateCast: sanitize before base64-encoding, mirroring RichContentRenderer::toHtml()
$node->attrs->preview = base64_encode(Str::sanitizeHtml($block::toPreviewHtml($nodeConfig)));
```

and/or escape/sanitize client-side before `innerHTML` (or build the preview DOM without `innerHTML`).
Principle: every path that turns block config into HTML must run the same sanitizer; a second render
path must not silently skip it.

## References

- PortSwigger Web Security Academy — DOM XSS (`innerHTML` sink); stored XSS via an unsanitized render path.
- OWASP XSS Prevention Cheat Sheet; CWE-79 Improper Neutralization of Input During Web Page Generation.
- Contrast with report F4 (RichEditor sanitizer allows `style`/`class` — sanitizer invoked but permissive).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 40 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Vendor advisory list `github.com/filamentphp/filament/security/advisories` — near match GHSA-9g92-9qj5-cqjc (2026-10-08, "Imported RichEditor custom block previews can be used for XSS", filament/forms >=4.0.0 <4.15.0, patched 4.15.0) fetched in full: root cause is trusting a crafted `data-preview` attribute in HTML pasted/dropped into the editor.
2. Current 4.x `extension-custom-block.js` fetched — the fix sets the `preview` attribute's `parseHTML` to always return `null` (imported previews discarded) but still assigns the decoded preview to `innerHTML` with no sanitizer.
3. Current 4.x `RichEditorStateCast.php` fetched — `$node->attrs->preview = base64_encode($block::toPreviewHtml($nodeConfig))` is still unsanitized; no `Str::sanitizeHtml()` call on that path.
4. GitHub Advisory Database, Composer ecosystem, query `filament` — also CVE-2026-55409 / GHSA-m9cv-24rx-8mv7 (disabled RichEditor state XSS, v3), different mechanism. (Web-search quota exhausted; checks via direct fetch of primary sources.)

**Related but distinct public references** (same class or component, not this bug):
- GHSA-9g92-9qj5-cqjc — same `innerHTML` preview sink, but the disclosed source is imported HTML (`data-preview`), and the 4.15.0 fix neutralises only that source; the server-computed `toPreviewHtml()` path this finding targets is unchanged.
- CVE-2026-55409 / GHSA-m9cv-24rx-8mv7 — raw render of a disabled RichEditor field's state (v3 only).

**Reasoning:** The published advisory covers the same component and sink but a different taint source, and the shipped fix does not sanitize the server-side preview path, so the specific defect here (no `Str::sanitizeHtml()` parity with the reader path before `innerHTML`) is not publicly described or fixed. Confidence is low because the vendor has just patched this exact preview surface, the residual requires a custom block whose `toPreviewHtml()` reflects config unescaped (arguably the block author's responsibility), and the vendor may regard the remaining path as covered or as a hardening item.
