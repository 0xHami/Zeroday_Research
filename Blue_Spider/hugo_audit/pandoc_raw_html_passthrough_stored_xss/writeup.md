# VULN-027 — Pandoc content rendering keeps `raw_html` enabled → stored XSS

| | |
|---|---|
| **ID** | VULN-027 |
| **Software** | Hugo — https://github.com/gohugoio/hugo |
| **Affected version** | 0.167.0-DEV (`common/hugo/version_current.go:19-24`); commit-pinned, no tagged release |
| **Commit** | `c7f9999309a2e7a12d24c03fe639008ddc4565f8` |
| **Severity** | Medium — CVSS 3.1 **4.7** `AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None. Actor is an untrusted `.pandoc`/`.pdc` content author (T1). Precondition: operator enabled Pandoc (installed `pandoc` + `security.exec.allow += ^pandoc$`). |
| **Attacker gains** | Injects stored `<script>` into every reader's browser. |

## Summary

Third sibling of VULN-025/026. The Pandoc content format has no safety knob, `text/pandoc` is
omitted from the `security.allowContent` denylist, and Hugo invokes `pandoc` with no
reader/sandbox flags — so pandoc's default Markdown reader keeps the **`raw_html` extension
enabled** and passes inline `<script>…</script>` straight to the HTML output. Confirmed
dynamically: a `.pandoc` file emitted a raw `<script>` into the published page. (Pandoc's base
Markdown has no file-include directive, so there is no default-config LFI here — hence Medium,
not High.)

## How it works (mechanism & code trace)

**(a) `text/pandoc` omitted from the content denylist.**
`targets/hugo/config/security/securityConfig.go:86` — same deny-only list, same omission as
VULN-025/026.

**(b) No reader/sandbox flags.**
`targets/hugo/markup/pandoc/convert.go:71-76`:

```go
mathFlag := "--mathjax"
if c.pandocSupportsMathMethod() { mathFlag = mathMethodFlag }   // "--math-method=mathjax"
args := []string{mathFlag, "--citeproc"}
return internal.ExternallyRenderContent(c.cfg, ctx, src, binaryName, args)
```

There is no `-f`/`--from` (so pandoc's default Markdown reader is used, with `raw_html`
enabled) and no `--sandbox`. The content body is piped to `pandoc` on stdin.

**The exact defect.** pandoc's default markdown reader enables the `raw_html` extension, which
passes inline/blocks of literal HTML straight through to the writer. Hugo neither selects a
raw-HTML-disabling reader (`-f markdown-raw_html`) nor enables the sandbox, so untrusted
`.pandoc` content controls the output HTML.

**Dynamic confirmation** (`response.txt` = rendered `public/p/index.html`): contains the literal
`<script>pandoc-xss-<rand></script>`. Run-log `[PROOF]`: `raw <script> emitted … True`.

## Why it is a vulnerability

The Markdown `unsafe` gate exists precisely to keep author-supplied raw HTML/script out of the
output; Pandoc bypasses it because `text/pandoc` is not on the `allowContent` denylist and the
reader keeps `raw_html`. Untrusted content therefore crosses the content-sandbox boundary and
runs script in every reader's browser (stored XSS, `S:C`). Unlike AsciiDoc/RST there is no
default file-include primitive, so confidentiality/integrity impact is limited to XSS
(`C:L/I:L`) — hence Medium. The enablement precondition (install `pandoc` + allowlist it) drives
`AC:H`.

## Reproduction

1. `cd claude_audit/hugo/exploits/VULN-027 && ./run.sh`
2. The script builds a throwaway site with `security.exec.allow` including `^pandoc$` and
   `content/p.pandoc` = `Hi there <script>…</script>`, using
   `cvehunterlab_hugo_st10tools:latest` (target hugo binary + `pandoc`) and `--network none`.
3. Expected: `[OK] exploit confirmed …`, exit 0. `response.txt` shows the `<script>` in the
   rendered page.

## Impact

Stored XSS against all site readers (cookie/session theft, CSRF-style actions in the reader's
authenticated context, defacement). No default-config file read (unlike AsciiDoc/RST). Part of
the content-format cluster (VULN-025/026/027).

## Suggested fix

- Run pandoc with a raw-HTML-disabling reader (`-f markdown-raw_html`) and/or `--sandbox`
  (pandoc ≥3) by default (`convert.go:71-76`).
- Add `text/pandoc` to the `security.allowContent` denylist (`securityConfig.go:86`).
- Document the raw-HTML passthrough. Principle: disable raw HTML by default; fail closed.

## References

- Pandoc `raw_html` extension and `--sandbox`: https://pandoc.org/MANUAL.html
- OWASP Stored XSS; CWE-79.
- Related `allowContent` advisories: GHSA-c54g-xjwj-8g82 (text/html), CVE-2026-100694 (text/org).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `hugo pandoc content raw_html XSS allowContent text/pandoc advisory` — only CVE-2026-50133, which states Pandoc content is unaffected by that fix; no Pandoc advisory
2. `hugo security.allowContent asciidoc rst pandoc raw HTML XSS external renderers advisory 2026` — CVE-2026-50133 / CVE-2026-100694 only
3. `site:github.com/advisories gohugoio hugo asciidoc OR reStructuredText OR pandoc ...` — nothing for Pandoc
4. Fetched Hugo issue search `pandoc sandbox OR raw_html security` (only #15062 bibliography support), security advisories pages 1-3, release notes v0.163.1-v0.168.0 (v0.164.0 Pandoc citeproc, v0.166.0 pandoc 3.11 support - features only), and docs (no Pandoc options or warnings)

**Related but distinct public references** (same class or component, not this bug):
- GHSA-c54g-xjwj-8g82 / CVE-2026-50133 and GHSA-pq74-mj4h-cjq2 / CVE-2026-100694 — same raw-HTML-content class fixed for text/html and text/org via `security.allowContent`; Pandoc not included
- pandoc.org/MANUAL.html — documents `raw_html` and `--sandbox` (generic)

**Reasoning:** No advisory, issue or third-party report covers Pandoc's `raw_html` passthrough in Hugo content or the missing `text/pandoc` denylist entry. The vendor fixed the identical class for two other formats, so this appears to be an unreported sibling; caveat that Pandoc requires operator enablement and the impact is XSS only.
