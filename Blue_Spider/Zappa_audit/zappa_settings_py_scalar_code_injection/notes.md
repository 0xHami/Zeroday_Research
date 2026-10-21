# VULN-016 — Code injection into generated zappa_settings.py via '{0!s}' interpolation

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- Surface C. Direct invocation of the real `zappa.cli.ZappaCLI.get_zappa_settings_string()` with a hostile
  scalar (`api_stage`), then `exec()` of the generated string (models the Lambda cold-start import).

## Request / Response
See `request.http` / `response.txt` / `run.log`. The generated line was
`INJECTED_<tok>=__import__('os').getcwd()`; after `exec`, the namespace held that symbol (value `/tmp/proj_...`).

## Observation
`get_zappa_settings_string` (`cli.py:3050-3203`) interpolates scalar config into Python source with
`'{0!s}'.format(value)` and no escaping (e.g. `API_STAGE='{0!s}'` at `:3129`). A value with a quote+newline
breaks out of the literal and injects module-level Python that executes when the generated
`zappa_settings.py` is imported at cold start (`handler.py:76`). Confirmed the injected statement ran.

## Side effects
None (the injected code only read cwd; exec ran in an isolated namespace dict).

## Research & references
- CWE-94 (Code Injection). Fix pattern: `repr()` / `json.dumps` instead of bare `'{0!s}'`. Dict-valued
  settings (`CONTEXT_HEADER_MAPPINGS`, `ENVIRONMENT_VARIABLES`) are already safe (rendered via repr/str of a
  dict) — only string scalars are injectable.

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED. In production the injected code runs in the *deployed* Lambda at cold start (persistent).
