# VULN-001 — GetRemote dial-IP SSRF guard disabled when security.http.urls is customized

**Software**: Hugo
**Repository**: https://github.com/gohugoio/hugo
**Affected version**: 0.167.0-DEV (common/hugo/version_current.go:19-24) — commit-pinned: no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: c7f9999309a2e7a12d24c03fe639008ddc4565f8
**Validated at**: 2026-09-30

## Preconditions
- Operator has customized `security.http.urls` (any change from the default). Modeled
  as `urls = ['(?i)^https?://']` (a common "allow my hosts" edit).
- A template/content passes a URL to `resources.GetRemote` that resolves to an internal
  address (here a hostname pinned to loopback via `--add-host`).

## Request / build input
`layouts/index.html`: `{{ $r := try (resources.GetRemote "http://internalcanary.test:PORT/…") }}…`
Two builds: default `[security.http]` absent vs `urls=['(?i)^https?://']`.
Harness: `docker run --network host --add-host=internalcanary.test:127.0.0.1`.

## Response
See `response.txt`:
```
[default]  hits=0 blocked=True   -> FETCH_ERR (dial guard denied loopback)
[customized] hits=1 fetched=True -> FETCHED:CANARY-2779fbe0 (internal secret rendered)
```

## Observation
Static prediction (securityConfig.go:238-240): `CheckAllowedHTTPAddress` returns nil
whenever `HTTP.URLs.patternsStrings != DefaultConfig`. Confirmed: the identical
loopback-resolving hostname is DENIED at dial under default config (listener gets 0
requests) and REACHED after any `urls` edit (listener hit, secret body rendered).
127.0.0.1 is a stand-in for 169.254.169.254 — `isPublicAddr` rejects both identically,
so reaching loopback proves the cloud-metadata endpoint is equally reachable.

## Side effects
None persistent — throwaway builds. Loopback canary listener runs only inside the
exploit process. Live dev server untouched.

## Research & references
- OWASP WSTG-SSRF (WSTG-INPV-19) & PortSwigger "SSRF" topic — DNS-rebinding / internal
  address bypass; applied the "hostname that passes the text allowlist but resolves to
  a blocked IP" technique, which is exactly the gap the dial-IP guard exists to close.
- Hugo security model https://gohugo.io/about/security/ and the SSRF CVE wave
  (CVE-2026-10582 / 50134 / 58404 / 100693) — this build post-dates and includes those
  fixes at *default*; VULN-001 is the residual when the operator customizes `http.urls`.

## If FAILED
n/a — CONFIRMED.
