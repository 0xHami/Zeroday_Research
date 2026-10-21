# VULN-003 — Unsanitized `tarfile.extractall` of the S3 project archive (tar-slip → cold-start RCE)

| | |
|---|---|
| **ID** | VULN-003 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium (High if archive attacker-writable) · CVSS 3.1 **6.8** — `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Write access to the `ARCHIVE_PATH` S3 object on a `slim_handler` deployment |
| **Attacker gains** | Arbitrary file write in the Lambda sandbox → code execution via `sys.path` poisoning |

## Summary
Under `slim_handler`, at cold start Zappa downloads the project archive from S3 and extracts it with
`tarfile.extractall` and **no member-path validation**, then prepends the extraction dir to `sys.path`. A
crafted archive member with `../` escapes the intended directory, letting whoever controls the S3 object
plant/overwrite Python modules and gain code execution on the next import. Verified live: a traversal
member was written outside `project_folder`.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/handler.py:219-242  load_remote_project_archive()
project_folder = "/tmp/{0!s}".format(self.settings.PROJECT_NAME)
if not os.path.isdir(project_folder):
    ...
    with tarfile.open(fileobj=archive_on_s3["Body"], mode="r|gz") as t:
        t.extractall(project_folder)      # <-- no filter=, no per-member path/symlink check
...
sys.path.insert(0, project_folder)        # extraction dir prepended to import path
os.chdir(project_folder)
```
Python's `TarFile.extractall` does not sanitise members; entries named `../../…` escape
`/tmp/<PROJECT_NAME>`. On the lab's Python 3.12 the default is the legacy unsafe behaviour with only a
`DeprecationWarning` (PEP 706 makes the safe `data` filter default only in 3.14). The exploit stubs the S3
fetch to feed a gzip tar whose member is `../../../../../../tmp/zappa_slip_<rand>/PWNED.py`; the real
function writes it there — outside `project_folder` (`response.txt`).

**The exact defect:** unsafe `tarfile.extractall` on an externally-controlled archive with no `filter="data"`
and no member validation (CWE-22). Because `project_folder` is on `sys.path`, a planted module shadows a
legitimate import → RCE; under `slim_handler` the same archive also feeds `cdll.LoadLibrary` (**VULN-031**).

## Why it is a vulnerability (reasoning)
The `ARCHIVE_PATH` S3 object is treated as trusted deployment content, but under `slim_handler` it is
fetched from S3 at runtime and is only as trustworthy as the bucket's write policy. Trusting it for
unsanitised extraction into an importable directory crosses the boundary between "storage" and "code" —
`S:C`, escalating to account-wide via VULN-017.

## Reproduction
1. Lab up; run `./run.sh` (drives the real archive extractor with a stubbed S3 body).
2. Proof (`response.txt`): file written to `/tmp/zappa_slip_<rand>/PWNED.py`, outside `project_folder`.
3. Real-world: build a `.tar.gz` with a `../`/shadowing member, upload to `s3://<ARCHIVE_PATH>`, trigger a
   cold start.
4. Expected `[OK] exploit confirmed` / `==> VULN-003: CONFIRMED`.

## Impact
Arbitrary file write in the Lambda sandbox → code execution via `sys.path` shadowing, persistent across
cold starts; account-wide via VULN-017. **Chains:** shares the "who controls the S3 object" boundary with
VULN-031 (native `.so` load) and VULN-026 (`REMOTE_ENV`).

## Suggested fix
- Use `tarfile.extractall(project_folder, filter="data")` (Python 3.12+), or validate every member resolves
  inside `project_folder` and reject symlinks/absolute paths before extraction.
- Treat the `ARCHIVE_PATH` S3 object as a trust boundary equivalent to the deployment artifact.

## References
- CWE-22 (Path Traversal); CVE-2007-4559 (tarfile traversal family); PEP 706 (`filter="data"`).
- Amplifier VULN-031; sibling VULN-026; blast VULN-017.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 25 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa slim_handler tarfile extractall path traversal` — only generic CVE-2007-4559 / PEP 706 material and the Semgrep rule; nothing Zappa-specific.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory of any kind.
3. GitHub issue search `zappa/Zappa issues?q=security` — surfaced #1178 "CVE-2007-4559 impact" (fetched and reviewed, see below).
4. `handler.py` on master (fetched) — `load_remote_project_archive` still calls `t.extractall(project_folder)` with no `filter=` and no member validation; no upstream fix.

**Related but distinct public references** (same class or component, not this bug):
- zappa/Zappa #1178 "CVE-2007-4559 impact" (Sep-Oct 2022, closed "not considered impacted") — a user asked whether Zappa's two `extractall` call sites are affected by the tarfile traversal CVE. The maintainer answered that the only archive extracted is the package Zappa itself builds, adding that "if an attacker can create or replace the zappa package on s3 with one that they created, you can be affected, but that is a separate security issue". No fix was made and the slim_handler/`sys.path` RCE consequence was not analysed.
- CVE-2007-4559 — the Python-stdlib class; not a Zappa advisory.

**Reasoning:** No advisory or report describes the slim_handler S3-archive `extractall` as a vulnerability, and the code is unchanged. However #1178 publicly raised the exact call site and the maintainer explicitly acknowledged (and dismissed as out of threat model) the attacker-controlled-S3-object scenario this finding depends on, so this is a borderline partial match. Kept per the "lean NOT KNOWN when borderline" rule, but with low confidence: a disclosure will very likely be answered with a pointer to #1178.
