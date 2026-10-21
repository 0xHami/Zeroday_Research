# VULN-011 — CORS unanchored regex + credentialed origin reflection

**Software**: NodeBB
**Repository**: https://github.com/NodeBB/NodeBB
**Affected version**: 4.16.0 (install/package.json:5; commit-pinned, untagged master)
**Status**: CONFIRMED (config-gated)
**Severity (static)**: Medium (conditional)
**Target commit**: 20623201cbf2cc8a37612726cdf10ee82083c9c3
**Validated at**: 2026-09-28

## Preconditions
- Admin has set `access-control-allow-origin-regex` (e.g. `example\.com`) AND
  `access-control-allow-credentials` (`true`) — both supported ACP → Settings → Advanced options.
  The exploit sets them via `PUT /api/v3/admin/settings/:setting`, probes, then RESTORES the originals.

## Request / Response
See `request.http` / `response.txt` / `run.log`. Captured with config enabled:
```
GET /api/config  Origin: https://example.com.attacker.net
  -> Access-Control-Allow-Origin: https://example.com.attacker.net
     Access-Control-Allow-Credentials: true
GET /api/config  Origin: https://notexample.com          -> reflected + credentials:true
GET /api/config  Origin: https://unrelated-evil.org      -> NOT reflected (control)
```

## Observation
Confirmed exactly. With the two settings enabled, an attacker origin that merely *contains* the
configured substring (`example.com.attacker.net`, `notexample.com`) is reflected verbatim into
`Access-Control-Allow-Origin` and paired with `Access-Control-Allow-Credentials: true`; an unrelated
origin is not reflected. This is the unanchored `regex.test(origin)` at `src/middleware/headers.js:55`
plus the independent credentials emission at `:65-66`. A browser will therefore allow a page on the
attacker origin to read authenticated JSON (e.g. `/api/config` → `csrf_token`, `/api/self`) with the
victim's cookies.

## Side effects
Config changed then restored to original values (verified). No lasting state change.

## Research & references
- PortSwigger Web Security Academy — "CORS: origin reflection with credentials" and "CORS with broken
  regex/prefix matching" (exact class).
- OWASP WSTG-CLNT-07 (Testing Cross Origin Resource Sharing); OWASP HTML5 Security Cheat Sheet.
- CWE-942 (Permissive Cross-domain Policy), CWE-346 (Origin Validation Error).

## If FAILED
n/a — CONFIRMED (config-gated). Note: conditional on the non-default admin config; kept as a
conditional risk in the report.
