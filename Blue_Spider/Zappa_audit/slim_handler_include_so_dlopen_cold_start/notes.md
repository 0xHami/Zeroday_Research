# VULN-031 — slim_handler cdll.LoadLibrary of INCLUDE .so (native code execution at cold start)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium (High if the archive is attacker-writable)
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- `slim_handler:true` + control of the S3 archive (same as VULN-003). A constructor `.so` was compiled in a
  `gcc:14-bookworm` container, staged as an `INCLUDE` entry, and the real cold-start init was driven.

## Request / Response
See `request.http` / `response.txt` / `run.log`. Marker file
`/tmp/dbf3_marker_<rand>` contained `native-code-executed-via-dlopen-constructor-<rand>`.

## Observation
`handler.py:116-131` (SLIM_HANDLER init) `cdll.LoadLibrary(os.path.join(os.getcwd(), library))` for each
`INCLUDE` entry. `dlopen` runs the ELF `__attribute__((constructor))` immediately. The planted `evil.so`'s
constructor executed native code (wrote the marker) at cold start, before any app code — native RCE from an
attacker-controlled archive. Confirmed.

## Side effects
Compiled `evil.so` in a throwaway gcc container (host build dir `evidence/build/`); copied it into the lab
container under `/tmp/dbf3_<rand>/`; the exploit removes the container-side dir + marker afterward.

## Research & references
- CWE-94 / CWE-114. `dlopen(3)` runs ELF constructors on load — the basis of the native-exec proof.

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED (native code executed). Requires the `gcc` image to be pullable to build the demo `.so`;
if unavailable, re-run with `GCC_IMAGE` pointing at any local compiler image.
