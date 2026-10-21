# VULN-013 — Predictable, world-writable `/tmp` wheel cache → poisoning → code execution

| | |
|---|---|
| **ID** | VULN-013 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | High · CVSS 3.1 **7.5** — `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Local unprivileged user / co-tenant on the build or CI host (Surface C) |
| **Attacker gains** | Malicious wheel packaged into the deployed Lambda (and run on the build host) |

## Summary
Zappa caches precompiled dependency wheels in a fixed, world-writable directory `/tmp/cached_wheels`
(created with `exist_ok=True`). On a cache hit the file is returned and packaged into the Lambda **with no
hash/signature check**. A local co-tenant who pre-plants a malicious wheel with the expected (predictable)
name gets that code shipped to the function and executed on import. Verified live: a planted wheel was
returned by the real cache lookup with no download.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/core.py:840-856  get_cached_manylinux_wheel()
cached_wheels_dir = Path(tempfile.gettempdir()) / "cached_wheels"     # fixed, world-writable /tmp path
if not cached_wheels_dir.is_dir() or not cached_wheels_dir.exists():
    cached_wheels_dir.mkdir(parents=True, exist_ok=True)              # accepts a pre-existing dir/symlink
else:
    wheel_name = re.sub(r"[^\w\d.]+", "_", package_name, ...)
    for arch in valid_architectures:
        wheel_file_pattern = f"{wheel_name}-{package_version}-*_{arch}.whl"
        for pathname in cached_wheels_dir.glob(wheel_file_pattern):
            if self.manylinux_wheel_file_match.match(str(pathname)):
                return pathname                                      # <-- trusted verbatim, no hash
```
The returned wheel is later `extractall`-ed into the package shipped to Lambda (`core.py:670-671`). Because
the cache path is fixed and world-writable, `exist_ok=True` accepts a pre-existing dir or symlink, and the
filenames are predictable (the project's own dependency names + the public manylinux naming), a co-tenant
pre-plants a malicious wheel (or symlinks the whole cache dir). The exploit plants
`evilpkg<rand>-1.0-cp312-cp312-manylinux_2_17_x86_64.whl`, calls the real `get_cached_manylinux_wheel`, and
it returns the planted path with no download (`response.txt`).

**The exact defect:** shared predictable path in world-writable `/tmp` + `exist_ok=True` (symlink/TOCTOU) +
**no artifact integrity verification** (CWE-377 / CWE-494). `get_manylinux_wheel_url` similarly trusts a
`/tmp/cached_pypi_info/<pkg>-<ver>.json` metadata cache (`core.py:885`), letting a poisoner set the download
URL (compounds VULN-018/021).

## Why it is a vulnerability (reasoning)
The build pipeline must not execute or ship code chosen by an unrelated local user. Here the trust boundary
between "co-tenant on the build host" and "code deployed to the cloud function" is crossed on the *default*
packaging path: whatever wheel the attacker plants runs both in the deployed Lambda (serving internet
traffic) and on the build host during packaging. `S:C` — the poison crosses into a different authority.

## Reproduction
1. Lab up; run `./run.sh` (plants a wheel in `/tmp/cached_wheels`, calls the real cache lookup).
2. Proof (`response.txt`): the lookup returns the planted wheel with no download.
3. Real-world (shared host): as attacker, `python -c "..."` to write
   `/tmp/cached_wheels/somedep-1.2.3-cp312-cp312-manylinux2014_x86_64.whl` (or `ln -s
   /home/attacker/evil_wheels /tmp/cached_wheels`); victim `zappa deploy` packages/ships it.
4. Expected `[OK] exploit confirmed` / `==> VULN-013: CONFIRMED`.

## Impact
Supply-chain code execution via a default code path, reachable by any local user on a shared build/CI host;
the foothold persists into the deployed function's IAM role (VULN-017) and runs on the build host.

## Suggested fix
- Use a per-user cache (`~/.cache/zappa`) or a `mkdtemp()` (0700) directory; never accept a pre-existing
  shared dir via `exist_ok=True`, and reject symlinks.
- Verify each wheel's SHA256 against PyPI's published digests before use (also closes VULN-018).

## References
- CWE-377 (Insecure Temporary File), CWE-427 (Uncontrolled Search Path), CWE-494 (No Integrity Check).
- Upstream [#2116](https://github.com/Miserlou/Zappa/issues/2116). Amplifiers VULN-018/021; blast VULN-017.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa cached_wheels /tmp wheel cache poisoning get_cached_manylinux_wheel` — only generic pip/zope wheel-cache discussion; nothing on Zappa.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. Cited issues fetched: Miserlou/Zappa #2116 (filename-mismatch re-download bug) and zappa #1009 (corrupt partial download cached; MD5 suggested for corruption) — both reliability threads, no mention of world-writable `/tmp`, symlinks, or poisoning.
4. `core.py` on master (fetched) — cache dir is still `tempfile.gettempdir()/cached_wheels`; only `zipfile.is_zipfile` check, no digest verification.

**Related but distinct public references** (same class or component, not this bug):
- zappa #1009 — same cache, framed as corruption/reliability; the MD5 suggestion was not a security control and was never implemented.
- Miserlou/Zappa #2116 — same function, naming bug only.
- zappa #493 / #1293 — generic "add package integrity checking" to-do items (2017), never actioned.

**Reasoning:** The predictable shared-`/tmp` cache with no integrity verification has only been discussed publicly as a reliability nuisance; no one has described the local co-tenant poisoning / TOCTOU path to shipped code. The generic "package integrity checking" wish-list items are related but do not identify this component or attack.
