# VULN-005 — REMOTE_ADDR spoofing via X-Forwarded-For (addresses[-2] heuristic)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- None. Anonymous HTTP to the running lab (Surface A). `/whoami` reflects `request.remote_addr`.

## Request
See `request.http`. `GET /whoami` with `X-Forwarded-For: 13.37.13.37, 203.0.113.9` (and a single-value
variant `X-Forwarded-For: 192.0.2.66`).

## Response
See `response.txt` / `run.log`:
- XFF `13.37.13.37, 203.0.113.9` → `remote_addr = "13.37.13.37"` (the attacker's `addresses[-2]`)
- XFF `192.0.2.66` (no comma) → `remote_addr = "192.0.2.66"`
- no XFF → `remote_addr = "127.0.0.1"` (baseline; proves the header is the source)

## Observation
`create_wsgi_request` sets `REMOTE_ADDR` from the client `X-Forwarded-For` using a hardcoded
"second-to-last" index (`wsgi.py:58-65`). The client fully controls that value in every non-CloudFront
topology, exactly as predicted. Two arbitrary IPs were reflected verbatim.

## Side effects
None (read-only GET).

## Research & references
- CWE-348 (Use of Less Trusted Source); OWASP "Cheat Sheet: Denial of Service"/rate-limiting and
  PortSwigger notes on `X-Forwarded-For` spoofing. The correct approach is to count from the number of
  *trusted* proxies, not a fixed offset.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.
