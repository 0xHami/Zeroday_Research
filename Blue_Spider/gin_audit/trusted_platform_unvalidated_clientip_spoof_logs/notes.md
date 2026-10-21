# VULN-003 — ClientIP() returns unvalidated TrustedPlatform header ⇒ spoof + log injection

**Software**: Gin (Gin Web Framework)
**Repository**: https://github.com/gin-gonic/gin
**Affected version**: v1.12.0 (`version.go:8`) — untagged master checkout, commit-pinned
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 1bd0ecf2d3e08da37efa270bb7be20c1eddb0d68
**Validated at**: 2026-09-30T16:30Z

## Preconditions
- Extended harness `tp` engine (:36276): `engine.TrustedPlatform = "X-CF-Connecting-IP"` **and**
  a correctly-locked-down `SetTrustedProxies(["192.0.2.0/24"])` that does NOT trust the real peer.
  This mirrors a production Cloudflare/Fly.io/App-Engine config. Unauthenticated; one header.

## Request
See `request.http`. `GET /ip` with `X-CF-Connecting-IP: 6.6.6.6`.

## Response
See `response.txt` / `run.log`:
```
baseline (X-Forwarded-For 9.9.9.9, peer untrusted): clientIP=172.19.0.1 (== remoteIP; XFF correctly ignored)
attack   (X-CF-Connecting-IP 6.6.6.6):              clientIP=6.6.6.6   (spoofed, != remoteIP)
raw-value(X-CF-Connecting-IP not-an-ip-...):        clientIP="not-an-ip-INJECTED-value" (verbatim, no ParseIP)
```

## Observation
Three facts proven together: (1) the `SetTrustedProxies` config is sound — a plain
`X-Forwarded-For` is correctly ignored because the peer (172.19.0.1) is not in `192.0.2.0/24`;
(2) despite that, `X-CF-Connecting-IP` sets `ClientIP()` to any value because `ClientIP`
returns `c.requestHeader(TrustedPlatform)` verbatim and FIRST (`context.go:999-1004`), before
`RemoteIP()`/`isTrustedProxy` are consulted; (3) the value is returned with no `net.ParseIP`,
so an arbitrary non-IP string is accepted — this is the string that flows unescaped into the
Logger's `%15s` ClientIP field (`logger.go:189`, contrast the `%#v`-quoted Path at `:191`),
giving CR/LF/ANSI log injection.

## Side effects
None (read-only GET).

## Research & references
- CVE-2020-28483 (IP spoof) and CVE-2020-36567 (Logger injection) — VULN-003 revives both via
  a different field (TrustedPlatform) that bypasses the proxy-trust gate entirely.
- CWE-290 (Auth Bypass by Spoofing), CWE-117 (Improper Output Neutralization for Logs).
- OWASP Logging Cheat Sheet (log injection / forging); Cloudflare `CF-Connecting-IP` docs
  (the header must be stripped/overwritten at the edge — gin trusts it unconditionally).

## If FAILED
n/a — CONFIRMED.
