# VULN-031 — `slim_handler` `cdll.LoadLibrary` of a tar-extracted `.so` → native code execution at cold start

| | |
|---|---|
| **ID** | VULN-031 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium (High if archive attacker-writable) · CVSS 3.1 **6.8** — `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic — native code executed)** |
| **Auth required** | Write access to the `ARCHIVE_PATH` S3 object on a `slim_handler` deployment |
| **Attacker gains** | Native code execution in the function at every cold start (no exported function need be called) |

## Summary
When `slim_handler` is enabled, at cold start Zappa `dlopen`s every `INCLUDE` entry from the current
directory — which the same feature has just populated by extracting the (attacker-controllable) S3 archive
(VULN-003). Loading a shared object runs its ELF constructors immediately, so an attacker who controls the
archive plants a malicious `.so` and obtains native code execution before any app code runs. Verified live:
a purpose-built constructor `.so` executed and wrote a marker.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/handler.py:116-131
is_slim_handler = getattr(self.settings, "SLIM_HANDLER", False)
if is_slim_handler:
    included_libraries = getattr(self.settings, "INCLUDE", [])
    from ctypes import cdll
    for library in included_libraries:
        try:
            cdll.LoadLibrary(os.path.join(os.getcwd(), library))   # <-- dlopen of archive content
        except OSError:
            print("Failed to find library: {}...right filename?".format(library))
```
`cdll.LoadLibrary()` is `dlopen(3)`: it runs the shared object's `__attribute__((constructor))` / `_init`
immediately, in-process, with the function's IAM role. `os.getcwd()` is `/tmp/<PROJECT_NAME>` — the
extraction target from VULN-003 — so the bytes loaded come from the attacker-controlled archive. The
exploit compiles a `.so` whose constructor writes a marker, stages it as an `INCLUDE` entry, and drives the
real slim-handler cold start; the marker is written (`response.txt`), proving native code ran on load.

**The exact defect:** `dlopen` of a file whose bytes come from an externally-controlled archive, with no
integrity check and no path validation (CWE-94 / CWE-114). `INCLUDE` and the extracted archive are treated
as trusted deployment content, but under `slim_handler` the archive is fetched from S3 at runtime.

## Why it is a vulnerability (reasoning)
This is a *second* execution sink activated by the same feature and same attacker as VULN-003, and a
stronger one: it does not even require importing a shadowed Python module — merely loading the library runs
code. Trusting runtime-downloaded bytes as loadable native code crosses the storage→code boundary (`S:C`);
account-wide via VULN-017.

## Reproduction
1. Lab up (and a `gcc` image pullable); run `./run.sh`.
2. It compiles a constructor `.so`, stages it as `INCLUDE=["evil.so"]`, and drives
   `LambdaHandler(SLIM_HANDLER=True, INCLUDE=["evil.so"])`.
3. Proof (`response.txt`): marker file written by the `.so` constructor — native code executed on dlopen.
4. Expected `[OK] exploit confirmed` / `==> VULN-031: CONFIRMED`.

## Impact
Native RCE at cold start, persistent, in the function's role → account-wide via VULN-017. Completes the
`slim_handler` blast radius alongside VULN-003 (Python `sys.path` poisoning).

## Suggested fix
- Treat the S3 archive as untrusted (see VULN-003): validate/allow-list `INCLUDE` library paths, verify each
  `.so` against a known digest, and never `dlopen` a file whose bytes came from a runtime download.
- Load only libraries shipped in the immutable deployment package, not from a mutable S3 archive.

## References
- CWE-94 (Code Injection), CWE-114 (Process Control). `dlopen(3)` constructor semantics.
- Chains with VULN-003 (shared archive boundary); blast VULN-017.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa slim_handler INCLUDE cdll.LoadLibrary shared object cold start` — only generic dlopen/LoadLibrary references; nothing on Zappa.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=... slim_handler .so OR LoadLibrary ...` — only missing-library errors (#940 libmysqlclient, #1213 libxmlsec1), the slim_handler breakage #1342, and archive-retention docs #1475; nothing about loading archive-supplied `.so` files as code execution.
4. zappa #1178 "CVE-2007-4559 impact" (fetched) — maintainer notes generically that an attacker who can replace the S3 package "can be affected, but that is a separate security issue"; the `cdll.LoadLibrary` constructor-execution sink is not mentioned. `handler.py` on master still dlopens every `INCLUDE` entry from the extracted archive.

**Related but distinct public references** (same class or component, not this bug):
- zappa #1178 — same trust boundary (attacker-controlled S3 archive) acknowledged and dismissed in the tarfile context; this native-load sink was not discussed.
- README "slim_handler" / "include" — documented feature ("load libraries into PYTHONPATH at handler init"); no caveat.

**Reasoning:** No public reference identifies `cdll.LoadLibrary` of archive-extracted `INCLUDE` libraries as a native code-execution sink. Confidence is tempered because the maintainer has already publicly declared the "attacker controls the S3 archive" scenario out of scope in #1178, which a disclosure of this finding would likely be met with.
