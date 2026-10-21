# VULN-001 — X-Forwarded-Prefix empty-prefix ⇒ protocol-relative external open redirect

**Software**: Gin (Gin Web Framework)
**Repository**: https://github.com/gin-gonic/gin
**Affected version**: v1.12.0 (`version.go:8`) — untagged master checkout, commit-pinned
**Status**: CONFIRMED
**Severity (static)**: Medium (High with a root-level `:param`/`*catchAll` route)
**Target commit**: 1bd0ecf2d3e08da37efa270bb7be20c1eddb0d68
**Validated at**: 2026-09-30T16:04:49Z

## Preconditions
- Default harness at :36274 (`gin.Default()`), `RedirectTrailingSlash` = default true.
- A route that produces a trailing-slash redirect. The harness route `/hello/:name`
  makes `GET /hello/john/` (trailing slash, no exact match) offer a 301 to `/hello/john`.
- Unauthenticated. One GET + one request header. No CSRF token, no cookie.

## Request
See `request.http`. The decisive request:
```
GET /hello/john/ HTTP/1.1
Host: localhost:36274
X-Forwarded-Prefix: ..
```

## Response
See `response.txt` / `run.log`. Captured:
```
baseline (no header):       301  Location: /hello/john        <- same-origin
ATTACK  (XFP: ..):          301  Location: //hello/john       <- protocol-relative EXTERNAL
prefix-inject (XFP: /evil): 301  Location: /evil/hello/john   <- header folded into Location
```

## Observation
Matches the static finding exactly. `X-Forwarded-Prefix: ..` is `path.Clean`ed to `..`
(so it is NOT `"."` and is accepted), then `sanitizePathChars` strips both dots → `""`.
The builder computes `p = "" + "/" + "/hello/john" = "//hello/john"`. Because the
rewritten `req.URL` has empty Scheme/Host, `req.URL.String()` returns `//hello/john`
verbatim; `http.Redirect` calls `url.Parse("//hello/john")`, which yields `Host="hello"`,
so http.Redirect's relative-path cleaning branch (which only runs when `u.Scheme==""`
AND `u.Host==""`) is SKIPPED — the raw `Location: //hello/john` reaches the wire.
The baseline (no header) is same-origin `/hello/john`, so the header is unambiguously
the cause. The `/evil` control shows the header is folded into the Location in the
general (non-empty) case too.

Browsers resolve a protocol-relative `Location: //hello/john` against the current
scheme → `http://hello/john`, i.e. off the application's origin. With the harness's
`/hello/:name` the external host is the fixed first segment `hello`; the fully
attacker-chosen-host escalation (root-level `:param`) is demonstrated separately in
`evidence/` (extended harness, root `/:tenant` route → `Location: //attacker.example/...`).

## Side effects
None. Read-only GET; server state unchanged; server stays up.

## Research & references
- CWE-601: URL Redirection to Untrusted Site (Open Redirect).
- OWASP WSTG-CLNT-04 (Client-side URL Redirect) and the OWASP Unvalidated Redirects
  and Forwards Cheat Sheet — a `//host` protocol-relative Location is the canonical
  open-redirect signature; browser navigation to the external origin needs no scheme.
- PortSwigger "DOM-based / open redirection" topic — protocol-relative (`//evil.com`)
  bypass of naive "must start with /" allowlists; applied here (the sanitizer's empty
  result reintroduces the leading `//`).
- CVE-2023-26125 / gin PR #4414 — the `sanitizePathChars` guard this bug bypasses
  (the guard fails open on an empty sanitized prefix). This is a novel residual bypass.

## If FAILED
n/a — CONFIRMED.
