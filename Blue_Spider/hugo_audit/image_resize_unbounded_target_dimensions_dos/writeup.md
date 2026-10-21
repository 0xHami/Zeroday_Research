# VULN-017 — Image pipeline has no target-dimension bound (or source-pixel cap) → build-time DoS

| | |
|---|---|
| **ID** | VULN-017 |
| **Software** | Hugo — https://github.com/gohugoio/hugo |
| **Affected version** | 0.167.0-DEV (`common/hugo/version_current.go:19-24`); commit-pinned, no tagged release |
| **Commit** | `c7f9999309a2e7a12d24c03fe639008ddc4565f8` |
| **Severity** | Medium — CVSS 3.1 **5.3** `AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None. Actor is a content author (T1) whose image a theme resizes, or a theme author (T2) choosing the spec. |
| **Attacker gains** | OOM-kills the build (denial of service) from a few-byte image + a resize call. |

## Summary

Hugo's image pipeline trusts caller-supplied target dimensions with no upper bound: a
resize spec of `50000x50000` makes Hugo allocate a destination RGBA buffer of
`50000 × 50000 × 4 ≈ 10 GB`, OOM-killing the build. Confirmed dynamically — the same
8×8 source image resized to `50x50` builds cleanly, but resized to `50000x50000`
SIGKILLs a 1 GB-capped build (exit 137). The same lack of a ceiling applies on the
*source* side (a decompression bomb whose header declares 60000×60000), but the
unbounded-*target* path is the deterministic proof because Go's PNG decoder validates
a source against its actual data.

## How it works (mechanism & code trace)

**Entry point — a theme resizing a content image.** A page bundle carries `pic.png`;
a template does `{{ (.Resources.GetMatch "pic.png").Resize "50000x50000" }}` (galleries,
responsive images and thumbnails all do this — very common, though bare Hugo has no
built-in shortcode that resizes content images, hence AC:H).

**Sink — unbounded dimension parse.** `targets/hugo/resources/images/config.go:299,308`:

```go
c.Width,  err = strconv.Atoi(first)    // :299 — no upper bound
c.Height, err = strconv.Atoi(second)   // :308 — no upper bound
```

Only a >2-part spec is rejected as "invalid image dimensions". There is no
max-dimension / max-megapixel check. Contrast the *same file*, where `Quality` **is**
bounded:

```go
// config.go:286 area — Quality is clamped 1..100
```

so the codebase clearly applies bounds where it chose to — and omitted one for the
dimensions that drive the allocation.

**Allocation.** The resize transform builds a destination image of the requested size
(`image.NewRGBA(Rect(0,0,w,h))` → `make([]uint8, 4*w*h)` inside
`disintegration/imaging`), forced when the resource is published
(`.RelPermalink`). `4 * 50000 * 50000 = 10^10` bytes.

**Source side (same class).** `targets/hugo/resources/images/codec.go:184-198`
decodes with the stdlib/x-image decoders (`image.Decode`, `gif.DecodeAll`,
`tiff.Decode`, `bmp.Decode`) with no max-megapixel guard before decode; a source
header declaring 60000×60000 allocates ~14 GB. (Go's PNG decoder verifies IDAT CRCs,
so a *malformed* tiny bomb is rejected — the well-formed huge-target and
huge-but-valid-source cases are the reachable ones.)

**Why the framework doesn't save it.** Go's image/imaging libraries allocate what the
caller asks; the ceiling must come from Hugo, and none exists. Under the container/CI
memory cgroup, the allocation is OOM-killed (rc 137, observed).

## Why it is a vulnerability

The security invariant is that a small, unprivileged input cannot force an unbounded
allocation on the build host. The image pipeline breaks it twice — trusting both the
source header's self-declared size and the caller's target size with no ceiling before
`make`. A content author who can add an image to a bundle a theme processes (or a
theme author choosing the resize spec) crosses into the host's availability budget: a
few-byte file OOMs the build. A skeptic can confirm from the trace that neither
`config.go` nor `codec.go` imposes a bound, and from the run that only the target
dimensions changed between the passing and OOMing builds.

## Reproduction

1. `cd claude_audit/hugo/exploits/VULN-017 && ./run.sh`
2. The script generates a valid 8×8 PNG (pure-Python, correct CRCs), places it in a
   leaf bundle, and builds the **same** site twice, changing only the resize spec in
   `layouts/_default/single.html`:
   - Control: `.Resize "50x50"` under 2 GB → builds (rc 0).
   - Attack: `.Resize "50000x50000"` under `--memory=1g` → OOM (rc 137).
3. Expected: `[OK] exploit confirmed …`, exit 0. Evidence (`response.txt`):
   ```
   control(.Resize 50x50) rc=0
   attack(.Resize 50000x50000) rc=137
   ```

## Impact

Reliable build-time DoS (OOM) from a tiny malicious input by an unprivileged content
author, on any site whose theme resizes content images. On CI/multi-tenant build farms
this halts the build and can pressure the host. Recoverable (no persistence) → Medium.
Sits in the build-DoS cluster with **VULN-004**/**VULN-018**/**VULN-023**.

## Suggested fix

- Before decoding, call `image.DecodeConfig` and reject sources whose `Width*Height`
  exceeds a configurable max-megapixel ceiling (`resources/images/codec.go`).
- Bound target `Width`/`Height` in `resources/images/config.go` exactly as `Quality`
  is bounded:
  ```go
  if c.Width <= 0 || c.Height <= 0 || int64(c.Width)*int64(c.Height) > maxImagePixels {
      return c, errors.New("image dimensions exceed the configured maximum")
  }
  ```
- Expose an `imaging.maxSize`-style setting and document it. Principle: bound every
  allocation whose size derives from untrusted input.

## References

- CWE-789 Memory Allocation with Excessive Size Value; CWE-409 Improper Handling of
  Highly Compressed Data (decompression bomb).
- OWASP "Denial of Service" cheat sheet (image/decompression-bomb guidance).
- Hugo image-processing docs: https://gohugo.io/content-management/image-processing/ ;
  issues #5220, #8931 (acknowledged heavy image memory use).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `hugo image resize huge dimensions memory exhaustion decompression bomb denial of service advisory CVE` — only other projects (Pillow CVE-2026-40192, php-image-resize CVE-2026-109398, SGLang CVE-2026-109229, OpenClaw CVE-2026-41334); nothing for Hugo
2. `gohugoio hugo issue image processing out of memory large image resize limit max pixels` — forum threads on WebP/AVIF encoder OOM and `HUGO_MEMORYLIMIT`; no dimension/megapixel cap and no advisory
3. `hugo static site generator "decompression bomb" OR "pixel flood" OR "image bomb" build OOM vulnerability` (extended) — no relevant results
4. `site:github.com/advisories gohugoio hugo ... denial of service` — no Hugo DoS advisory; fetched github.com/gohugoio/hugo/security/advisories pages 1-3 — none about image processing
5. Fetched issues #5220 and #8931 — #5220 is a 2018 performance thread (serialised image processing), #8931 is an unrelated cached-MediaType bug; neither discusses a dimension bound or DoS

**Related but distinct public references** (same class or component, not this bug):
- gohugoio/hugo#5220 — "Image processing requires lots of memory" (2018, performance; fixed by serialising processing, no size ceiling)
- gohugoio/hugo#8931 — cached MediaType bug for resized images; not memory-related (the writeup's citation is inaccurate)
- gohugo.io/about/security — states that "malformed input that fails the build" is not considered a DoS, which may affect how the vendor triages this

**Reasoning:** No CVE/GHSA/issue describes an unbounded target-dimension (or source-megapixel) allocation in Hugo's image pipeline. The class is generic and Hugo's security page scopes out build failures from malformed input, so the maintainers may treat this as out of scope rather than unknown; a private report could also exist.
