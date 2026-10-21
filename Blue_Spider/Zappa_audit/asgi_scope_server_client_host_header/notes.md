# VULN-025 — ASGI scope["server"] taken from client Host (host injection)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium (ASGI apps only)
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- ASGI deployment (`app_type: asgi`). Direct invocation of the real `zappa.asgi.create_asgi_scope` with a
  client Host header (Surface A).

## Request / Response
See `request.http` / `response.txt` / `run.log`. `Host: attacker.evil.example`, `X-Forwarded-Port: 8443` →
`scope["server"] == ("attacker.evil.example", 8443)`.

## Observation
`create_asgi_scope` (`asgi.py:55,77`) sets `scope["server"] = (host, port)` where `host` is the client Host
(no validation), unlike WSGI which pins `SERVER_NAME="zappa"`. Starlette/FastAPI derive absolute URLs from
`scope["server"]`, so the client poisons reset links/redirects. Port is safely `int()`-coerced (avoids
VULN-010's raw-string defect); host is verbatim. Confirmed.

## Side effects
None (direct function call).

## Research & references
- CWE-644 (Host-header injection). PortSwigger "HTTP Host header attacks". ASGI analogue of VULN-004.

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED at the scope-construction level (the lab app is WSGI; the ASGI builder is exercised directly).
