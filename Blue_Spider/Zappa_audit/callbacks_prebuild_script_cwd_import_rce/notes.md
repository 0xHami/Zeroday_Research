# VULN-014 — callbacks/prebuild_script config imports & calls a module from cwd (local RCE)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- Surface C (deploy host). Direct invocation of the real `zappa.cli.ZappaCLI.callback("settings")` with a
  hostile `stage_config` (`callbacks={"settings":"evilcb.pwn"}`) and a planted `evilcb.py` in cwd.

## Request / Response
See `request.http` / `response.txt` / `run.log`. The callback loaded `evilcb` from cwd and ran `pwn()`,
which wrote `/tmp/vuln014_rce_<rand>` containing `RCE via callbacks on deploy host`.

## Observation
`callback()` (`cli.py:2554-2593`) reads the config dotted path, loads the module from `os.getcwd()` via
`pkgutil.get_importer(...).find_spec(...).loader.load_module(...)` (executing its top level), then
`getattr` + calls the function passing the CLI object. No allow-list. Confirmed the planted module executed.
`callbacks["settings"]` fires at `cli.py:650` on ordinary/read-only commands (e.g. `zappa status`).

## Side effects
Wrote a random-named marker in `/tmp` inside the container; exploit removes it.

## Research & references
- CWE-94 (Code Injection). The `prebuild_script` twin (`cli.py:3391-3431`) fires via the offline,
  credential-free `zappa package`.

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED.
