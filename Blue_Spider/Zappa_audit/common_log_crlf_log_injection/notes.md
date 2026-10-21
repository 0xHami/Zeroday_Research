# VULN-007 — CRLF / log injection into the Common Log Format

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED (in-lab end-to-end; real-world reachability caveat below)
**Severity (static)**: Medium
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- None (anonymous HTTP, Surface A). Stage-09 had marked this NEEDS_MANUAL pending confirmation that a
  `%0d%0a` in the path reaches the formatter undecoded — **now confirmed in the lab.**

## Request / Response
See `request.http` / `response.txt` / `run.log`. `GET /x%0d%0a<forged CLF record>`; the container log then
contains a standalone forged line:
`66.66.66.66 - - [01/Jan/2099:00:00:00 +0000] "GET /admin/PWN_<rand> HTTP/1.1" 200 0 "-" "-"`

## Observation
`unquote(event["path"])` (`wsgi.py:129`) decodes `%0d%0a` to a real CRLF, which `format_log`
(`utilities.py:1046-1051`) interpolates into the log line unescaped, and `logger.info` emits — splitting the
entry and injecting a fully attacker-authored access-log record. Exactly the predicted CWE-117 sink, proven
end-to-end. `host`/`referer`/`agent` are equally unescaped (secondary vectors).

## Side effects
Writes to the container's log stream only. Marker is randomised per run.

## Research & references
- CWE-117 (Improper Output Neutralization for Logs). OWASP "Log Injection"; the Logging Cheat Sheet
  (neutralise CR/LF before writing log lines).
- Reachability caveat: the lab's werkzeug front-end preserves the encoded `%0d%0a` in `RAW_URI`, matching
  how API Gateway/ALB forward encoded path octets to the Lambda. Real API Gateway historically forwards
  percent-encoded path characters to the integration without normalising them, so the Surface-A path holds;
  a specific front proxy that pre-decodes+rejects control chars would reduce reachability (hence the caveat).

## If FAILED / NEEDS_MANUAL
Confirmed in-lab. If a deployment's front proxy strips `%0d%0a` from the path before Zappa, the path vector
is blocked there, but the sink remains vulnerable to any field delivered with a raw control char.
