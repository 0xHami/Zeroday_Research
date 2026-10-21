# VULN-004 — cloudfront-host header overwrites the app Host (Function URL)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- A Function-URL-style deployment (Host looks like `*.lambda-url.*`). Modelled via a crafted v1 event
  delivered to the handler (`/_sim/raw-event`) with `Host` + lowercase `cloudfront-host`, matching the
  header casing AWS delivers for a CloudFront→Function-URL request.

## Request / Response
See `request.http` / `response.txt` / `run.log`:
- With `cloudfront-host: evil.attacker.example` → app-seen `Host = evil.attacker.example`.
- Without `cloudfront-host` (control) → app-seen `Host = abc123def456.lambda-url.us-east-1.on.aws`.
- Deterministic across 3 runs.

## Observation
`handler.py:813-815` copies the client `cloudfront-host` into `event["headers"]["host"]` whenever the real
Host contains `lambda-url`, with no verification the request came from a trusted CloudFront distribution.
The overwritten Host flows into `HTTP_HOST` and the app's `request.host`. Confirmed the swap is effective
and controlled by the client header. (Note: the value survives the `merge_headers` title-case merge
deterministically in this runtime; the vulnerable *action* — trusting `cloudfront-host` — is unconditional
in the code.)

## Side effects
None (read-only /echo reflection).

## Research & references
- CWE-644 (Improper Neutralization of HTTP Headers). PortSwigger "HTTP Host header attacks" (password-reset
  poisoning, web-cache poisoning). OWASP WSTG-CONF Host-header injection.
- API-Gateway cache key excludes forwarding headers (`core.py:2375`, `CacheKeyParameters=[]`), amplifying
  the cache-poisoning variant.

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED. The downstream ATO (reset-link poisoning) depends on the consuming app building links from
`request.host`; the Zappa-layer defect (Host overwrite from a client header) is confirmed here.
