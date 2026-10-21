# VULN-025 — AsciiDoc content rendering runs Asciidoctor in `unsafe` safe-mode → arbitrary host-file read (LFI) + stored XSS

| | |
|---|---|
| **ID** | VULN-025 |
| **Software** | Hugo — https://github.com/gohugoio/hugo |
| **Affected version** | 0.167.0-DEV (`common/hugo/version_current.go:19-24`); commit-pinned, no tagged release |
| **Commit** | `c7f9999309a2e7a12d24c03fe639008ddc4565f8` |
| **Severity** | High — CVSS 3.1 **8.1** `AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None. Actor is an untrusted content author (T1 — a `.adoc` file / docs PR). Precondition: operator enabled AsciiDoc (installed `asciidoctor` + `security.exec.allow += ^asciidoctor$`). |
| **Attacker gains** | Reads arbitrary files on the build host (secrets, keys, other tenants' source) into published HTML, and injects stored `<script>` into every reader's browser. |

## Summary

Hugo gates raw-HTML injection **only on the Markdown path** (`markup.goldmark.renderer.unsafe`
fails closed). The AsciiDoc content format has **no equivalent gate**: `text/asciidoc` is
omitted from the `security.allowContent` denylist, and Hugo invokes the external
`asciidoctor` binary in its most-permissive **`unsafe`** safe-mode — because it emits the
`--safe-mode` flag only when Hugo's configured value *differs* from Asciidoctor's own CLI
default, and Hugo's default (`"unsafe"`) *equals* it, so no flag is ever passed. In unsafe
mode Asciidoctor honours `include::<path>[]` (arbitrary host-file read) and `pass:[…]`
(raw HTML). Confirmed dynamically: a `.adoc` file read a planted secret **and** `/etc/passwd`
into the published HTML and emitted a raw `<script>`.

## How it works (mechanism & code trace)

Three independent defaults combine.

**(a) `text/asciidoc` omitted from the content denylist.**
`targets/hugo/config/security/securityConfig.go:86`:

```go
AllowContent: MustNewWhitelist("! ^text/html$", "! ^text/org$"),
```

The denylist recognises the raw-HTML-content risk for `text/html` (GHSA-c54g-xjwj-8g82,
fixed 0.162.0) and `text/org` (CVE-2026-100694, fixed 0.166.0) but **omits `text/asciidoc`**.
`Whitelist` is deny-only ("allow anything not denied", `config/security/whitelist.go`), so
`text/asciidoc` is permitted under `/content` by default.

**(b) Asciidoctor default safe-mode is `unsafe`.**
`targets/hugo/markup/asciidocext/asciidocext_config/config.go:24,37` — both `Default.SafeMode`
and `CliDefault.SafeMode` are `"unsafe"`.

**(c) No `--safe-mode` flag is emitted.**
`targets/hugo/markup/asciidocext/internal/converter.go:247-259`:

```go
func (a *AsciiDocConverter) AppendArg(args []string, option, value, defaultValue string, ...) []string {
    if value != defaultValue {   // "unsafe" == "unsafe" -> condition false -> flag NOT appended
        if allowedValues[value] { args = append(args, option, value) }
    ...
}
```

Call site `converter.go:242`:
`args = a.AppendArg(args, "--safe-mode", cfg.SafeMode, asciidocext_config.CliDefault.SafeMode, …)`.
Since Hugo's default equals the CLI default, **no `--safe-mode` is passed**, so Asciidoctor
runs in its own most-permissive mode. The content body is piped to `asciidoctor -` on stdin
(`converter.go:98,102`), and the output is treated as trusted HTML (no post-sanitisation).

**The exact defect.** The "emit only when different from default" optimisation at
`converter.go:247` means Hugo *never* pins a safe mode, and the omission of `text/asciidoc`
from `allowContent` means nothing else blocks the format. Together they leave Asciidoctor in
`unsafe` mode against untrusted content.

**Dynamic confirmation** (`response.txt` = rendered `public/p/index.html`): the page contains
the planted `ASCIIDOC-LFI-<rand>` secret, `/etc/passwd` (`root:x:0:0…`), **and** the literal
`<script>adoc-xss-<rand></script>`. Run log `[PROOF]` lines: LFI-secret=True, LFI-passwd=True,
XSS=True.

## Why it is a vulnerability

The Markdown path enforces a content sandbox (`unsafe=false` fails closed; `os.readFile` is
BasePathFs+DropSymlinks-confined). AsciiDoc has **no** equivalent, so untrusted content
escapes the sandbox entirely: it reads arbitrary host files (`include::/etc/passwd[]`,
`include::../../config/…`) and injects script (`pass:[<script>…]`). This crosses from "author
supplies a document" to "author reads build-host secrets and runs script in every reader's
browser" — the strongest boundary break in this audit (`S:C`, `C:H`, `I:H`). The enablement
precondition (operator installs `asciidoctor` + allowlists it) is a deliberate, documented
action taken to *support* AsciiDoc, with no indication that it re-opens the file-read/raw-HTML
holes the Markdown path closes — which is exactly why `AC:H` (not `AC:L`) and why it is a real,
latent-but-live defect rather than mere misconfiguration.

## Reproduction

1. `cd claude_audit/hugo/exploits/VULN-025 && ./run.sh`
2. The script builds a throwaway site with `security.exec.allow` including `^asciidoctor$`, a
   planted `/site/SECRET.txt`, and `content/p.adoc` containing
   `include::/site/SECRET.txt[]`, `include::/etc/passwd[]`, `pass:[<script>…]`. It builds with
   `cvehunterlab_hugo_st10tools:latest` (the target hugo binary + `asciidoctor` — the operator's
   enablement) and `--network none`.
3. Expected: `[OK] exploit confirmed …`, exit 0. `response.txt` shows the secret, `/etc/passwd`,
   and the `<script>` in the rendered page.

## Impact

- **Arbitrary host-file disclosure:** any file the build process can read — site secrets,
  `.env`, SSH keys, CI tokens, other tenants' content on shared build farms — is inlined into
  published HTML.
- **Stored XSS** against all site readers.
- On CI/multi-tenant docs pipelines the file read is the more serious primitive (credential
  theft → lateral movement). The disclosed secrets feed any credential-reuse attack; with
  `markup.asciidocext.attributes.allow-uri-read=true` the `include::https://169.254.169.254/…[]`
  variant reaches cloud metadata (overlaps **VULN-001**).

## Suggested fix

- Default `markup.asciidocext.safeMode` to `"secure"` (or at least `"server"`) and **always
  emit `--safe-mode` explicitly** rather than skipping it when the value equals the CLI default
  (`converter.go:247` — remove the `value != defaultValue` short-circuit for security-relevant
  flags).
- Add `text/asciidoc` to the `security.allowContent` denylist (`securityConfig.go:86`) for
  parity with `text/html`/`text/org`.
- Document that AsciiDoc content is a raw-HTML/file-read sink. Principle: fail closed, and pin
  the safe mode explicitly.

## References

- Asciidoctor safe modes: https://docs.asciidoctor.org/asciidoctor/latest/safe-modes/
- OWASP WSTG-ATHZ-01 (LFI/path traversal), WSTG "Stored XSS"; CWE-829, CWE-79.
- Related `allowContent` advisories: GHSA-c54g-xjwj-8g82 (text/html), CVE-2026-100694 (text/org).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `hugo asciidoctor safe mode unsafe include arbitrary file read security advisory` — only Asciidoctor safe-mode docs and a 2020 Hugo blog post; no advisory
2. `gohugoio hugo asciidocext safeMode default "unsafe" security issue content include LFI 2026` — godoc confirms `SafeMode: "unsafe"` default; no security report
3. `hugo security.allowContent asciidoc rst pandoc raw HTML XSS external renderers advisory 2026` — only CVE-2026-50133 (text/html) and CVE-2026-100694 (text/org); CVE-2026-50133 explicitly states AsciiDoc/Pandoc/RST are unaffected by that fix
4. `gohugoio hugo github issue asciidoctor "safe-mode" flag not passed default unsafe security` — nothing relevant
5. Fetched github.com/advisories?query=hugo+asciidoc (only GHSA-c54g-xjwj-8g82), Hugo issue searches for `asciidoctor safe-mode` / `safeMode unsafe asciidoc` (PR #7281, PR #8131 - no security discussion), advisory pages 1-3, release notes v0.166.0-v0.168.0, and docs (configuration/markup, content-management/formats) — `safeMode` default `unsafe` is documented without any warning

**Related but distinct public references** (same class or component, not this bug):
- GHSA-c54g-xjwj-8g82 / CVE-2026-50133 — raw HTML via `text/html` content; fixed via `security.allowContent` (AsciiDoc explicitly excluded)
- GHSA-pq74-mj4h-cjq2 / CVE-2026-100694 — same class for `text/org`; shows the vendor treats raw-HTML passthrough in content formats as a vulnerability
- gohugoio/hugo PR #7281 (2020 AsciiDoc rework; stated default "safe" at the time) and PR #8131 (arbitrary extensions in unsafe mode) — no security framing

**Reasoning:** No advisory, issue or third-party report covers Asciidoctor running in `unsafe` mode (no `--safe-mode` emitted) or `text/asciidoc` missing from the `allowContent` denylist, while the same class has been CVE'd for `text/html` and `text/org`. Confidence is moderate because the `unsafe` default is publicly documented and matches Asciidoctor's own CLI default, so the vendor may argue it is a documented choice rather than a bug; the operator-enablement precondition also lowers severity.
