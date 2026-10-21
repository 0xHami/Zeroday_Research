# VULN-008 — stageVariables copied into os.environ (warm-container pollution)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- Surface B via `/_sim/raw-event`. Two separate invocations against the same warm gateway process.

## Request / Response
See `request.http` / `response.txt` / `run.log`. Invocation #1 set `stageVariables {ZAPPA_POLLUTED_<rand>:
set-by-invocation-1-<rand>}`; a *separate* invocation #2 read it back from `os.environ` — value present.

## Observation
`handler.py:705-709` copies every `stageVariables` key into `os.environ` for ANY event, before dispatch,
with no allow-list. Lambda reuses warm containers, so the mutation persists across invocations — confirmed
by invocation #2 seeing invocation #1's value. A direct-invoke caller can pollute the env other (incl.
Surface-A) requests run under (e.g. overwrite `REQUESTS_CA_BUNDLE`, `DJANGO_SETTINGS_MODULE`, secrets).

## Side effects
Set a random env var in the gateway process; the lab was restarted after this exploit to clear it.

## Research & references
- CWE-15 (External Control of System/Config Setting). Sibling of VULN-026.

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED (cross-invocation persistence). Note the read-back uses a second raw_command invocation
because `os.environ.copy` isn't importable via the `command` dotted-path resolver.
