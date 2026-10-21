# VULN-003 — tarfile.extractall tar-slip on the S3 project archive (slim_handler)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium (High if the archive is attacker-writable)
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- `slim_handler:true` (sets `ARCHIVE_PATH`) + control of the S3 archive. Direct invocation of the real
  `zappa.handler.LambdaHandler.load_remote_project_archive` with the S3 fetch stubbed to feed a malicious
  gzip tar.

## Request / Response
See `request.http` / `response.txt` / `run.log`. A tar member `../../../../../../tmp/zappa_slip_<rand>/PWNED.py`
was written to `/tmp/zappa_slip_<rand>/PWNED.py` — outside the intended `project_folder`.

## Observation
`load_remote_project_archive` (`handler.py:219-242`) calls `tarfile.open(..., "r|gz").extractall(project_folder)`
with no `filter=` and no member validation, then `sys.path.insert(0, project_folder)`. On Python 3.12 the
default is the legacy (unsafe) behaviour with only a `DeprecationWarning` (PEP 706; the safe `data` filter
becomes default in 3.14). The traversal member escaped `project_folder`; since that dir is on `sys.path`,
an attacker who controls the archive plants importable code → cold-start RCE.

## Side effects
Wrote a file under `/tmp/zappa_slip_<rand>/` in the container; the exploit removes the tree.

## Research & references
- CWE-22; the CVE-2007-4559 tarfile-traversal family; PEP 706 (`filter="data"`).

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED. Note Python-version dependence: on 3.14+ the default `data` filter would block this unless
Zappa keeps specifying no filter (Lambda runtimes are currently 3.9–3.13).
