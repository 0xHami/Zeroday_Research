# VULN-017 — Image pipeline unbounded target dimensions (and no source-pixel cap) → build DoS

**Software**: Hugo
**Repository**: https://github.com/gohugoio/hugo
**Affected version**: 0.167.0-DEV (common/hugo/version_current.go:19-24) — commit-pinned: no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: c7f9999309a2e7a12d24c03fe639008ddc4565f8
**Validated at**: 2026-09-30

## Preconditions
- Default Hugo + a theme/template that processes a content-supplied image
  (`.Resources.GetMatch … .Resize/.Fit`). A content author can add an image to a bundle.

## Request
Leaf bundle `content/posts/bomb/` with a valid 8×8 PNG `pic.png`; template
`layouts/_default/single.html`: `{{ (.Resize "<WxH>").RelPermalink }}`.
Control `50x50`; attack `50000x50000`.

## Response
See `response.txt`: `control(.Resize 50x50) rc=0` vs `attack(.Resize 50000x50000) rc=137`.
rc=137 = OOM-kill (50000·50000·4 ≈ 10 GB destination buffer).

## Observation
Predicted: `resources/images/config.go:299,308` parse Width/Height with no upper bound
(contrast Quality, bounded 1–100). Confirmed: identical image + template OOM-kills the
1 GB build when only the target dimensions change. (The decompression-bomb variant —
a lying source IHDR — is the same class; the unbounded-target case is the deterministic
repro because Go's PNG decoder validates the source against its data.)

## Side effects
None — `--network none` throwaway builds; live server untouched.

## Research & references
- CWE-789 / CWE-409 (decompression bomb / excessive-size allocation). Generated a valid
  PNG in pure Python (correct CRC32 chunks) after an invalid embedded blob failed the
  decoder's checksum — the decoder rejects malformed sources, which is why the
  unbounded-*target* path is the clean proof.
- Hugo image-processing docs (`.Resize`) + issues #5220/#8931 (acknowledged heavy memory).

## If FAILED
n/a — CONFIRMED.
