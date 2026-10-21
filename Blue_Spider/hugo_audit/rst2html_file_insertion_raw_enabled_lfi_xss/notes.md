# VULN-026 — reStructuredText → LFI + stored XSS

**Software**: Hugo
**Repository**: https://github.com/gohugoio/hugo
**Affected version**: 0.167.0-DEV (common/hugo/version_current.go:19-24) — commit-pinned: no tagged release
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: c7f9999309a2e7a12d24c03fe639008ddc4565f8
**Validated at**: 2026-09-30

## Preconditions
- Operator installed docutils/`rst2html` **and** added `^rst2html(\.py)?$` to
  `security.exec.allow`. Validated with the throwaway image
  `cvehunterlab_hugo_st10tools:latest` (target hugo binary + docutils 0.19 `rst2html`).
- Site accepts untrusted `.rst` content.

## Request / build input
`content/p.rst`:
```
.. include:: /site/SECRET.txt

.. raw:: html

   <script>rst-xss-<rand></script>
```
Planted `/site/SECRET.txt` = `RST-LFI-<rand>`.

## Response
See `response.txt` (rendered `public/p/index.html`): contains the planted secret
(`.. include::` inlined it) and the literal `<script>rst-xss-<rand></script>` (`.. raw:: html`).

## Observation
Predicted (securityConfig.go:86 omits text/rst; convert.go:75-78 passes no
`--no-file-insertion`/`--no-raw`, so docutils' `file_insertion_enabled`/`raw_enabled`
defaults apply): confirmed. `.. include::` read a host file (LFI); `.. raw:: html` emitted
a raw `<script>` (stored XSS). Latent in the base lab (docutils absent); made live with the
tools image (the operator's enablement action).

## Side effects
None persistent — `--network none` throwaway build.

## Research & references
- docutils security docs (`file_insertion_enabled`/`raw_enabled` default True;
  `--no-file-insertion`/`--no-raw` disable them) — https://docutils.sourceforge.io/docs/user/config.html.
- OWASP WSTG LFI + Stored XSS. Same `allowContent` cluster as VULN-025.

## If FAILED
n/a — CONFIRMED.
