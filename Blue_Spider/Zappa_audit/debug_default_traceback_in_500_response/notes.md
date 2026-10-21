# VULN-006 — DEBUG traceback returned to the client (default-on)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- `DEBUG=True` — the default (`cli.py:2699` sets `self.debug = self.stage_config.get("debug", True)`;
  lab confirms `/_sim/info` → `"debug": true`).
- An exception that reaches Zappa's handler `try/except`: either the deployed WSGI app propagates it
  (bare WSGI / Flask `PROPAGATE_EXCEPTIONS`|`TESTING` / middleware error / Django with propagation), or a
  fault inside Zappa's own request/response handling.

## Request
See `request.http`. `GET /_sim/info` (posture) and a Surface-A-reachable event that faults inside the
handler (`{"httpMethod":"GET"}` → missing `path` → `create_wsgi_request` raises). The realistic
app-propagation case is exercised by driving a fresh `LambdaHandler` bound to a bare WSGI app that raises
(see `automation.py` `_DRIVER`).

## Response
See `response.txt` / `run.log`:
- `/_sim/info` → `"debug": true`.
- Propagating-app case: handler returns `statusCode 500` with `body` containing `"traceback"`, internal
  frames (`/app/zappa/handler.py`), and the app's embedded secret
  `S3CRET_DB_PASSWORD_hunter2_in_exception_msg`.
- Live handler-fault case: 500 body carries the full traceback JSON including `/app/zappa/handler.py`.

## Observation
`_handle_request_exception` (`handler.py:342-347`) serialises `traceback.format_exception(...)` into the
JSON body returned to the caller whenever `settings.DEBUG` is truthy. Confirmed: the full stack — file
paths, framework internals, and any secret embedded in an exception message — is disclosed to an anonymous
client. **Nuance:** a Flask/Django app catches its *own* view exceptions (so `/boom` alone returns Flask's
generic HTML 500, not Zappa's traceback); the leak requires the exception to *propagate to Zappa*, which
is common for bare-WSGI apps, propagate-configured apps, middleware faults, or Zappa-level errors.

The second half of the finding — logging the whole event at `handler.py:702-703` — is gated on
`logger.debug`, i.e. `LOG_LEVEL=DEBUG`. The lab runs `LOG_LEVEL=INFO`, so that log line is suppressed
here; it fires when the operator sets `log_level: DEBUG` (documented option).

## Side effects
None (read-only). The propagating-app driver runs in a fresh in-container python process.

## Research & references
- CWE-209 (Sensitive Info in Error Message), CWE-489 (Active Debug Code). OWASP WSTG-ERRH "Testing for
  Improper Error Handling."

## If FAILED
n/a — CONFIRMED (traceback-to-client half).

## If NEEDS_MANUAL
The full-event-log half (`handler.py:702-703`) needs `LOG_LEVEL=DEBUG` + CloudWatch read to observe
`Authorization`/`Cookie`/body capture; not exercised in the INFO-level lab.
