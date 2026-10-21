# VULN-026 — reStructuredText content runs `rst2html` with docutils file-insertion/raw enabled → arbitrary host-file read (LFI) + stored XSS

| | |
|---|---|
| **ID** | VULN-026 |
| **Software** | Hugo — https://github.com/gohugoio/hugo |
| **Affected version** | 0.167.0-DEV (`common/hugo/version_current.go:19-24`); commit-pinned, no tagged release |
| **Commit** | `c7f9999309a2e7a12d24c03fe639008ddc4565f8` |
| **Severity** | High — CVSS 3.1 **8.1** `AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None. Actor is an untrusted `.rst` content author (T1). Precondition: operator enabled RST (installed docutils/`rst2html` + `security.exec.allow += ^rst2html(\.py)?$`). |
| **Attacker gains** | Reads arbitrary host files into published HTML and injects stored `<script>`. |

## Summary

Sibling of VULN-025. The reStructuredText content format has **no safety knob** (`markup.rst`
exposes only `syntaxHighlight`), `text/rst` is **omitted** from the `security.allowContent`
denylist, and Hugo invokes docutils' `rst2html` with **no hardening flag**. docutils ships
with `file_insertion_enabled=True` and `raw_enabled=True` by default, so untrusted `.rst`
content reads arbitrary host files (`.. include::`, `.. csv-table:: :file:`) and injects HTML
(`.. raw:: html`). Confirmed dynamically: a `.rst` file inlined a planted host secret and
emitted a raw `<script>`.

## How it works (mechanism & code trace)

**(a) `text/rst` omitted from the content denylist.**
`targets/hugo/config/security/securityConfig.go:86` —
`AllowContent: MustNewWhitelist("! ^text/html$", "! ^text/org$")` — same omission as VULN-025.
Deny-only list ⇒ `text/rst` permitted under `/content` by default.

**(b) No docutils hardening flag is ever passed.**
`targets/hugo/markup/rst/convert.go:75-78`:

```go
args := []string{"--leave-comments", "--initial-header-level=2"}
if c.cfg.Conf != nil && c.cfg.MarkupConfig().RST.SyntaxHighlight != "long" {
    args = append(args, "--syntax-highlight="+c.cfg.MarkupConfig().RST.SyntaxHighlight)
}
```

The argv never includes `--no-file-insertion`, `--no-raw`, or `--no-direct`. The content body
is piped to `rst2html` on stdin (`convert.go:90,92` via `internal.ExternallyRenderContent`).
docutils therefore runs with its permissive defaults.

**The exact defect.** docutils' `file_insertion_enabled` / `raw_enabled` default to `True`;
the only way to make `rst2html` safe against untrusted input is to pass
`--no-file-insertion --no-raw`, which Hugo never does. Combined with the `allowContent`
omission, untrusted `.rst` reaches docutils in full-trust mode.

**Dynamic confirmation** (`response.txt` = rendered `public/p/index.html`): contains the
planted `RST-LFI-<rand>` secret (from `.. include:: /site/SECRET.txt`) and the literal
`<script>rst-xss-<rand></script>` (from `.. raw:: html`). Run-log `[PROOF]`: LFI=True, XSS=True.

## Why it is a vulnerability

Identical boundary break to VULN-025: the Markdown path enforces a content sandbox; RST has
none. `.. include::`/`:file:` read arbitrary host files into the published output, and
`.. raw:: html` injects script into readers' browsers — crossing from "author supplies a
document" to "author reads build-host secrets and runs script in readers' browsers"
(`S:C`, `C:H`, `I:H`). The operator's enablement (install docutils + allowlist `rst2html`) is
a deliberate action to *support* RST, with no hint that it re-opens these holes — hence `AC:H`
and a genuine latent-but-live defect. The control here is the contrast with the Markdown path,
which would have contained both primitives.

## Reproduction

1. `cd claude_audit/hugo/exploits/VULN-026 && ./run.sh`
2. The script builds a throwaway site with `security.exec.allow` including `^rst2html(\.py)?$`,
   a planted `/site/SECRET.txt`, and `content/p.rst` containing `.. include:: /site/SECRET.txt`
   and a `.. raw:: html` block with `<script>…</script>`. It builds with
   `cvehunterlab_hugo_st10tools:latest` (target hugo binary + docutils `rst2html`) and
   `--network none`.
3. Expected: `[OK] exploit confirmed …`, exit 0. `response.txt` shows the secret and the
   `<script>` in the rendered page.

## Impact

Arbitrary host-file disclosure (secrets, keys, other tenants' source) + stored XSS. On
CI/multi-tenant docs pipelines the file read enables credential theft / lateral movement.
Same secret-reuse and reader-XSS consequences as VULN-025.

## Suggested fix

- Invoke `rst2html` with `--no-file-insertion --no-raw` (and consider `--no-direct`) **by
  default** (`convert.go:75-78`); expose a `safeMode`-style knob like AsciiDoc.
- Add `text/rst` to the `security.allowContent` denylist (`securityConfig.go:86`).
- Document that RST content is a raw-HTML/file-read sink. Principle: pass the hardening flags
  by default; fail closed.

## References

- docutils config (`file_insertion_enabled`/`raw_enabled`, `--no-file-insertion`/`--no-raw`):
  https://docutils.sourceforge.io/docs/user/config.html
- OWASP WSTG-ATHZ-01 (LFI) + Stored XSS; CWE-829, CWE-79.
- Related `allowContent` advisories: GHSA-c54g-xjwj-8g82 (text/html), CVE-2026-100694 (text/org).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `hugo rst2html docutils file insertion raw html content vulnerability` — only the docutils "Deploying Docutils Securely" guide and unrelated Django/Zope threads; nothing for Hugo
2. `hugo security.allowContent asciidoc rst pandoc raw HTML XSS external renderers advisory 2026` — CVE-2026-50133 / CVE-2026-100694 only; RST explicitly excluded from the text/html fix
3. `site:github.com/advisories gohugoio hugo asciidoc OR reStructuredText OR pandoc ...` — no Hugo advisory for RST
4. Fetched Hugo issue search `rst2html security OR "file-insertion"` (only PR #14841 syntax highlighting), security advisories pages 1-3, release notes v0.163.1-v0.168.0, and docs (configuration/markup lists only `syntaxHighlight` for RST, no warning)

**Related but distinct public references** (same class or component, not this bug):
- GHSA-c54g-xjwj-8g82 / CVE-2026-50133 and GHSA-pq74-mj4h-cjq2 / CVE-2026-100694 — raw-HTML content XSS for text/html and text/org; same `allowContent` control, different format
- docutils "Deploying Docutils Securely" — generic upstream guidance that `raw`/`include` must be disabled for untrusted input

**Reasoning:** No public reference describes Hugo invoking `rst2html` without `--no-file-insertion`/`--no-raw` or omitting `text/rst` from `allowContent`. The vendor has fixed the same class for two other formats, so this sibling gap appears unreported; caveat that RST support requires operator enablement and the vendor may scope it as "trusted external renderer".
