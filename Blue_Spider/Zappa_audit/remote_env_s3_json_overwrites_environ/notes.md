# VULN-026 — remote_env S3 JSON overwrites existing os.environ at cold start

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- `remote_env` set + write to that S3 object. Direct invocation of the real
  `zappa.handler.LambdaHandler.load_remote_settings` with the S3 fetch stubbed.

## Request / Response
See `request.http` / `response.txt` / `run.log`. Pre-existing `APP_DB_URL=postgres://real-db.internal/app`
was overwritten to `postgres://attacker-db.evil.example/steal`; `REQUESTS_CA_BUNDLE=/tmp/attacker-ca.pem`
injected.

## Observation
`load_remote_settings` (`handler.py:274-281`) copies every S3 JSON key into `os.environ`, explicitly
overwriting existing keys ("# overwrites existing keys!"), with no allow-list. Runs in `__init__` before
`APP_MODULE`/`DJANGO_SETTINGS` are consumed. Confirmed overwrite + injection.

## Side effects
Mutated os.environ in the fresh lab_python process only (not the gateway).

## Research & references
- CWE-15 (External Control of System/Config Setting). Sibling of VULN-008; shares VULN-003's S3-object boundary.

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED.
