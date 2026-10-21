# VULN-006 — DEBUG tracebacks (with secrets & file paths) returned to the client

| | |
|---|---|
| **ID** | VULN-006 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium · CVSS 3.1 **5.3** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None (anonymous HTTP, Surface A) |
| **Attacker gains** | Full server-side traceback: file paths, framework internals, and secrets embedded in exception text |

## Summary
When `DEBUG` is enabled — which the Zappa CLI does **by default** — any exception that reaches the Lambda
handler is turned into a 500 whose body contains the complete Python traceback. That includes server file
paths, the framework call stack, and the exception message, which routinely embeds request data or secrets
(e.g. a DB connection error printing the password). Verified live: a propagated app exception returned a
secret planted in its message, plus internal frames, to the anonymous caller; the same leak is observable
when Zappa's own handler faults.

## How it works (mechanism & code trace)
**Entry point / sink** — `_handle_request_exception`, invoked from the `except` arms of the v1/v2 handler
branches (`handler.py:780`, `:869`):
```python
# targets/Zappa/zappa/handler.py:342-347
content["statusCode"] = 500
body: Dict[str, Any] = {"message": message}
if settings is not None and settings.DEBUG:
    body["traceback"] = traceback.format_exception(*exc_info)   # full stack -> client
content["body"] = json.dumps(str(body), sort_keys=True, indent=4)
```
The traceback list is placed directly into the response body returned to API Gateway and thus to the
client. **The default** comes from the CLI:
```python
# targets/Zappa/zappa/cli.py:2699
self.debug = self.stage_config.get("debug", True)   # defaults True
```
so the generated `zappa_settings.py` carries `DEBUG=True` unless the operator sets `"debug": false`
(Zappa's own `example/zappa_settings.json` also ships `"debug": true`). The lab reflects this:
`/_sim/info` → `"debug": true`.

**Reachability nuance (verified).** A Flask/Django app catches its *own* view exceptions and renders its
own error page, so a view raising (the demo `/boom`) yields Flask's generic HTML 500 — Zappa's handler
never sees it. The leak fires when an exception **propagates to Zappa's handler**: a bare-WSGI app, a
Flask app with `PROPAGATE_EXCEPTIONS`/`TESTING`, an error in WSGI middleware, or a fault in Zappa's own
request/response processing. The exploit drives a fresh `LambdaHandler` bound to a bare WSGI app that
raises `RuntimeError("DB connect failed: <SECRET>")`; the handler returns a 500 whose body contains the
secret and `/app/zappa/handler.py` frames.

A second half of the finding — `logger.debug("Zappa Event: {}".format(event))` at `handler.py:702-703` —
logs the entire event (headers/cookies/body) but is gated on `LOG_LEVEL=DEBUG`; the lab is `INFO`, so that
line is suppressed here (fires with `log_level: DEBUG`).

## Why it is a vulnerability (reasoning)
Error responses must not disclose server internals to clients (CWE-209). Here internal detail is returned
*to the client* rather than logged server-side only, and the switch defaults to the insecure state. The
feature is meant to help a developer debug; shipped on by default in production it becomes a reconnaissance
and secret-disclosure primitive available to any anonymous caller who can elicit an error.

## Reproduction
1. Lab up; run `./run.sh`.
2. It (a) reads `/_sim/info` to confirm `debug:true`; (b) drives Zappa's handler with a WSGI app that
   propagates `RuntimeError("DB connect failed: S3CRET_DB_PASSWORD_hunter2_in_exception_msg")`; (c) shows a
   live 500 body carrying the traceback when Zappa's own handler faults.
3. Proof (`run.log`): the 500 `body` contains the secret string, `"traceback"`, and
   `/app/zappa/handler.py`.
4. Expected `[OK] exploit confirmed` / `==> VULN-006: CONFIRMED`.

## Impact
Any client that can trigger an error path reads server file paths, library layout, and exception messages
(which frequently include connection strings, credentials, or SQL). This sharpens every other exploit
(precise paths/versions for VULN-001/002/003) and can directly leak secrets. Confidentiality impact; no
integrity/availability change. Enabled by default.

## Suggested fix
- In `_handle_request_exception` (`handler.py:342-347`), never place the traceback in the client response
  regardless of `DEBUG`; log it server-side only.
- Redact `Authorization`/`Cookie`/body before any event logging (`handler.py:702-703`).
- Change the CLI default to `self.debug = self.stage_config.get("debug", False)` (`cli.py:2699`) and
  document `DEBUG` as strictly non-production. Principle: fail closed; diagnostics go to logs, not clients.

## References
- CWE-209 (Sensitive Info in Error Message), CWE-489 (Active Debug Code).
- OWASP WSTG-ERRH-01/02 (Improper Error Handling); upstream [#1029](https://github.com/Miserlou/Zappa/issues/1029), [#933](https://github.com/Miserlou/Zappa/issues/933).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 30 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa debug traceback returned in response information disclosure` — only generic stack-trace-in-response guidance (ZAP, OWASP WSTG) and an unrelated pyLoad advisory; nothing on Zappa.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=traceback response debug OR "information disclosure"` and the cited #1029 / #933 — both are troubleshooting threads that happen to show tracebacks in 500 bodies; neither frames it as a security problem.
4. README (master) settings reference — `"debug": true, // Print Zappa configuration errors tracebacks in the 500. Default true.` (documented behaviour and default, no production warning); `cli.py` on master still defaults `debug` to `True`.

**Related but distinct public references** (same class or component, not this bug):
- Miserlou/Zappa #1293 / zappa #487 "'Production Mode' Project" (maintainer, Dec 2017, open) — checklist item "Disable any public-facing error reporting"; acknowledges the hardening gap without naming `debug`, tracebacks or secrets in exception text.
- Miserlou/Zappa #1029, #933 — user reports containing tracebacks returned by the handler; no security framing.

**Reasoning:** No advisory or report describes `_handle_request_exception` returning `traceback.format_exception` to the client under the default `debug: true` as a vulnerability. However the behaviour and the insecure default are explicitly documented in the README, and the maintainer's own production-mode issue lists disabling public-facing error reporting as a to-do, so this is close to a documented insecure default rather than an unknown bug. Kept per the borderline rule, with low confidence; the owner may prefer to treat it as known.
