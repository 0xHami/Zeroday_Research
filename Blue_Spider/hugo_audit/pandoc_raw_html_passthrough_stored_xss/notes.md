# VULN-027 — Pandoc `raw_html` → stored XSS

**Software**: Hugo
**Repository**: https://github.com/gohugoio/hugo
**Affected version**: 0.167.0-DEV (common/hugo/version_current.go:19-24) — commit-pinned: no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: c7f9999309a2e7a12d24c03fe639008ddc4565f8
**Validated at**: 2026-09-30

## Preconditions
- Operator installed `pandoc` **and** added `^pandoc$` to `security.exec.allow`. Validated
  with `cvehunterlab_hugo_st10tools:latest` (target hugo binary + pandoc 2.17.1.1).
- Site accepts untrusted `.pandoc` content.

## Request / build input
`content/p.pandoc`: `Hi there <script>pandoc-xss-<rand></script>`.

## Response
See `response.txt` (rendered `public/p/index.html`): contains the literal
`<script>pandoc-xss-<rand></script>`.

## Observation
Predicted (securityConfig.go:86 omits text/pandoc; convert.go:71-76 passes no
`-f`/`--sandbox`, so pandoc's default Markdown reader keeps `raw_html`): confirmed. The
inline `<script>` was emitted verbatim (stored XSS). No default-config LFI (pandoc base
Markdown has no include directive) — hence Medium, not High. Latent in the base lab (pandoc
absent); made live with the tools image.

## Side effects
None persistent — `--network none` throwaway build.

## Research & references
- Pandoc `raw_html` extension (default-on in the markdown reader) and `--sandbox` (pandoc
  ≥3) — https://pandoc.org/MANUAL.html. OWASP Stored XSS. Same `allowContent` cluster as
  VULN-025/026.

## If FAILED
n/a — CONFIRMED.
