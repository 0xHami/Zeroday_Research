# VULN-002 — Arbitrary module import & function invocation via event-controlled dotted paths

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High (Critical when reached via VULN-012)
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- The running lab (Surface B via harness `POST /_sim/raw-event`), which forwards a raw Lambda event
  straight into `LambdaHandler.handler()` — modelling a direct Lambda invocation (an AWS-authenticated
  caller or, via VULN-012, any AWS account).

## Request
See `request.http`. Two events, each a direct-invoke JSON:
- `{"command": "os.getcwd"}`
- `{"command": "platform.platform"}`

## Response
See `response.txt` / `run.log`:
- `os.getcwd` → `"/app/_harness"` (the Lambda's real working directory)
- `platform.platform` → `"Linux-7.0.0-34-generic-x86_64-with-glibc2.41"`

## Observation
The `command` event field is split, `import_module`'d and `getattr`'d with no allow-list
(`utilities.py:146-153`), then invoked by `run_function` (`handler.py:909`). Two *different* modules
(`os`, `platform`) were imported and executed purely from event data, each returning its live result to
the caller — exactly as the static finding predicted. The async plumbing
(`asynchronous.route_lambda_task` → `run_message` → `func(*args, **kwargs)`) extends this to an arbitrary
callable **with attacker-supplied arguments** (e.g. `os.system("id")`), i.e. full RCE.

## Side effects
None from the benign probes (`os.getcwd`, `platform.platform` are read-only). No state written.

## Research & references
- OWASP WSTG "Testing for Code Injection"; CWE-94 (Code Injection), CWE-470 (Unsafe Reflection).
- Confirmed the `run_function` arity-fallback (`handler.py:615-632`): tries `(event, context)`, then
  `(event)`, then `()` — which is why zero-arg callables like `os.getcwd` execute and return.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. The arbitrary-**args** RCE variant (`task_path`+`args`) is the same code path; the benign zero-arg
probes already prove import+invoke of attacker-named callables.
