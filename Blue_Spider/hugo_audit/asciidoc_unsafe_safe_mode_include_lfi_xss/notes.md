# VULN-025 — AsciiDoc `unsafe` safe-mode → LFI + stored XSS

**Software**: Hugo
**Repository**: https://github.com/gohugoio/hugo
**Affected version**: 0.167.0-DEV (common/hugo/version_current.go:19-24) — commit-pinned: no tagged release
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: c7f9999309a2e7a12d24c03fe639008ddc4565f8
**Validated at**: 2026-09-30

## Preconditions
- Operator installed `asciidoctor` **and** added `^asciidoctor$` to `security.exec.allow`
  (the two-step "support AsciiDoc" action). Validated using a throwaway image
  `cvehunterlab_hugo_st10tools:latest` (target hugo binary + asciidoctor 2.0.18) and that
  `exec.allow` entry.
- Site accepts untrusted `.adoc` content.

## Request / build input
`content/p.adoc`:
```
= Innocent looking post
include::/site/SECRET.txt[]
include::/etc/passwd[]
pass:[<script>adoc-xss-<rand></script>]
```
Planted `/site/SECRET.txt` = `ASCIIDOC-LFI-<rand>`.

## Response
See `response.txt` (rendered `public/p/index.html`). It contains the planted secret,
`/etc/passwd` contents (`root:x:0:0…`), and the literal `<script>adoc-xss-<rand></script>`.

## Observation
Predicted (securityConfig.go:86 omits text/asciidoc; converter.go:242,247-259 emits no
`--safe-mode` since Hugo's default `"unsafe"` equals the CLI default): confirmed. `include::`
performed arbitrary host-file read (LFI) of both a planted secret and `/etc/passwd`, and
`pass:[…]` emitted a raw `<script>` (stored XSS). Latent in the base lab (asciidoctor
absent); made live with the tools image, which is exactly the operator's enablement action.

## Side effects
None persistent — `--network none` throwaway build; the tools image is a throwaway.

## Research & references
- OWASP WSTG-ATHZ-01 (LFI/path traversal) + WSTG "Stored XSS". Asciidoctor safe-mode docs
  (`unsafe` honors `include::` and `pass:[]`) — https://docs.asciidoctor.org/asciidoctor/latest/safe-modes/.
- Hugo `allowContent` advisories the omission parallels: GHSA-c54g-xjwj-8g82 (text/html),
  CVE-2026-100694 (text/org).

## If FAILED
n/a — CONFIRMED.
