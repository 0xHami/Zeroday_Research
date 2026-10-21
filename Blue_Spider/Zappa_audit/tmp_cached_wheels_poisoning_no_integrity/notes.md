# VULN-013 — /tmp wheel-cache poisoning (planted wheel used, no integrity check)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- Surface C (local co-tenant on the build/CI host). Direct invocation of the real
  `zappa.core.Zappa.get_cached_manylinux_wheel(pkg, "1.0")` after planting a matching wheel in
  `/tmp/cached_wheels`. Default `use_precompiled_packages` path.

## Request / Response
See `request.http` / `response.txt` / `run.log`. The planted
`/tmp/cached_wheels/evilpkg<rand>-1.0-cp312-cp312-manylinux_2_17_x86_64.whl` was returned verbatim
("Using locally cached manylinux wheel") with no download.

## Observation
`get_cached_manylinux_wheel` (`core.py:840-856`) uses a fixed world-writable cache dir (created
`exist_ok=True`), globs `{name}-{ver}-*_{arch}.whl`, matches the regex, and returns the file with **no hash
check**. A co-tenant's planted wheel is thus packaged into the Lambda. Confirmed the cache-hit path returns
the attacker file.

## Side effects
Created `/tmp/cached_wheels/<planted>.whl` in the container; the exploit removes it.

## Research & references
- CWE-427 (Uncontrolled Search Path), CWE-377 (Insecure Temp), CWE-494 (No Integrity Check).
- Upstream [#2116](https://github.com/Miserlou/Zappa/issues/2116) (cache integrity tracked as reliability).

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED (cache-hit poisoning). The symlink/TOCTOU variant and full deploy packaging are the
real-world escalation; the trusted-cache primitive is proven here.
