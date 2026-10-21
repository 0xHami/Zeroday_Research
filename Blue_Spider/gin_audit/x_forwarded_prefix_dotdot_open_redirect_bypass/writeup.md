# VULN-001 — `X-Forwarded-Prefix` empty-prefix ⇒ protocol-relative external open redirect

| | |
|---|---|
| **Software** | Gin (Gin Web Framework) |
| **Repository** | https://github.com/gin-gonic/gin |
| **Affected version** | v1.12.0 (`version.go:8`), untagged master checkout |
| **Commit** | `1bd0ecf2d3e08da37efa270bb7be20c1eddb0d68` |
| **Severity** | **Medium** — CVSS 3.1 **6.1** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (High for apps with a root-level `:param`/`*catchAll` route) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None (unauthenticated) |
| **Attacker gains** | An unauthenticated, one-header open redirect to an arbitrary external origin — phishing, OAuth/OIDC return-path token theft, and cache-poisoning of the 301. |

## Summary

gin's automatic trailing-slash redirect folds the attacker-controlled
`X-Forwarded-Prefix` request header into the response `Location`. The sanitizer
shipped to fix the previous open-redirect (CVE-2023-26125) **fails open on an empty
result**: a prefix of `..` is reduced to the empty string, and because the request
path always starts with `/`, the emitted `Location` becomes `//<host>/…` — a
protocol-relative (network-path) URL that every browser resolves to an **external
origin**. Any unauthenticated visitor who follows a crafted link is redirected off
the application's origin. This is a **novel residual bypass** of gin's own shipped
CVE-2023-26125 fix, live and default-reachable in v1.12.0.

## How it works (mechanism & code trace)

**Entry point.** When a request has no exact route match but a trailing-slash
variant would match (or vice-versa), and `Engine.RedirectTrailingSlash` is true
(the default, `gin.go:224`), gin calls `redirectTrailingSlash(c)` from
`handleHTTPRequest` (`gin.go:759-763`). The harness registers `/hello/:name`, so
`GET /hello/john/` (trailing slash present, no exact match) enters this path.

**Source → sink taint trace.** The attacker-controlled header enters here:

```go
// targets/gin/gin.go:810-824
func redirectTrailingSlash(c *Context) {
	req := c.Request
	p := req.URL.Path                                            // "/hello/john/"
	if prefix := path.Clean(c.Request.Header.Get("X-Forwarded-Prefix")); prefix != "." {
		prefix = sanitizePathChars(prefix)                       // (1) ".." -> ""
		prefix = removeRepeatedChar(prefix, '/')
		p = prefix + "/" + req.URL.Path                          // (2) "" + "/" + "/hello/john/" = "//hello/john/"
	}
	req.URL.Path = p + "/"
	if length := len(p); length > 1 && p[length-1] == '/' {
		req.URL.Path = p[:length-1]                              // (3) trim trailing "/" -> "//hello/john"
	}
	redirectRequest(c)
}
```

Hop **(1)** — `path.Clean("..")` returns `".."`, which is *not* `"."`, so the header
is accepted. `sanitizePathChars` (the CVE-2023-26125 guard) then keeps only
`[A-Za-z0-9/-]` and drops everything else:

```go
// targets/gin/gin.go:826-835
func sanitizePathChars(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '/' || r == '-' {
			return r
		}
		return -1                                                // '.' is dropped -> ".." becomes ""
	}, s)
}
```

Both dots are stripped, so `prefix == ""`. Hop **(2)** is the defect: the code
unconditionally prepends the (now empty) prefix plus a `/` to the request path,
which itself begins with `/`, producing the double-slash `//hello/john`. Hop **(3)**
trims the trailing slash, leaving `//hello/john`. The sink:

```go
// targets/gin/gin.go:849-861
func redirectRequest(c *Context) {
	req := c.Request
	rURL := req.URL.String()                                     // Scheme="",Host="" => "//hello/john" verbatim
	code := http.StatusMovedPermanently                          // 301 for GET
	if req.Method != http.MethodGet { code = http.StatusTemporaryRedirect }
	http.Redirect(c.Writer, req, rURL, code)                     // writes Location: //hello/john
	c.writermem.WriteHeaderNow()
}
```

**The exact defect.** `http.Redirect` only sanitizes/relativizes a `Location` when
the parsed URL has **both** an empty scheme **and** an empty host
(`if u.Scheme == "" && u.Host == ""` in the stdlib). But `url.Parse("//hello/john")`
interprets the leading `//` as an *authority*, yielding `Host="hello"`, so that
cleaning branch is skipped and the raw `//hello/john` is emitted. gin's own guard ran
(sanitizePathChars) but produced the empty string that *recreates* the very `//`
prefix the guard existed to remove — it fails open. The one-line root cause is
`gin.go:817`: `p = prefix + "/" + req.URL.Path` executed when `prefix == ""`.

**Why the framework doesn't save it.** The `prefix != "."` check at `gin.go:813` is
the only gate, and an empty-but-non-`"."` sanitized prefix sails through it. Neither
`sanitizePathChars` nor `http.Redirect` collapses a leading `//` on the *whole* built
path; each only guards its own fragment.

## Why it is a vulnerability (reasoning)

The security invariant for an HTTP redirect is that an application must not send a
user to an origin it did not intend, based on unvalidated input. Here a **request
header** (`X-Forwarded-Prefix`, meant to be set by a *trusted* reverse proxy to tell
the app its external mount path) is taken from the *client* with no trusted-proxy
gate and folded directly into a response `Location`. The observed behavior is not
by-design: gin explicitly added `sanitizePathChars` to *prevent* exactly this
class (CVE-2023-26125), which shows the project's intent is that this redirect stays
same-origin. The empty-prefix path defeats that intent. The capability the feature
is supposed to grant — "rewrite the redirect path to include the proxy's mount
prefix" — is a *path* rewrite; what the attacker actually obtains is an **origin**
change (`//host`), a strictly greater capability that crosses the origin/security
boundary (CVSS Scope: Changed). A skeptic can verify the baseline: the identical
request without the header yields a same-origin `Location: /hello/john`; only the
attacker header produces `//hello/john`.

## Reproduction

From a clean state (default harness already running at :36274):

1. No special setup — unauthenticated, no accounts, no state.
2. Bring the target up (if needed): `cd claude_audit/gin/setup && docker compose -p cvehunterlab_gin up -d`.
3. Run the exploit: `cd claude_audit/gin/exploits/VULN-001 && ./run.sh`.

The decisive request (also in `request.http`):

```
GET /hello/john/ HTTP/1.1
Host: localhost:36274
X-Forwarded-Prefix: ..
```

Observed response (from `run.log` / `response.txt`):

```
HTTP/1.1 301 Moved Permanently
Location: //hello/john
```

The script asserts the `Location` is protocol-relative (`startswith("//")`) while the
no-header baseline is not, and prints:

```
[PROOF] '//' is a protocol-relative URL -> browser navigates to http(s)://hello/... = EXTERNAL origin
[OK] exploit confirmed — X-Forwarded-Prefix:.. turned a same-origin 301 into a protocol-relative external redirect
==> VULN-001: CONFIRMED — unauth open redirect: Location: //hello/john (external origin http://hello)
```

One-liner equivalent: `curl -si --path-as-is -H 'X-Forwarded-Prefix: ..' 'http://localhost:36274/hello/john/'`.

**Full attacker-chosen host.** With the harness's `/hello/:name` the external host is
the fixed first path segment `hello`. When the consuming app registers a *root-level*
`:param`/`*catchAll` route (profile pages `/:user`, i18n `/:lang/…`, tenants, SPA
fallthrough `/*path` — extremely common), the first segment is attacker-controlled and
the redirect target is `//<anything>`. This escalation is proven against the extended
harness (root `/:tenant` route) in `evidence/full-host-control.txt`.

## Impact

- **Unauthenticated open redirect** to an arbitrary external origin from a single GET
  plus one header — no auth, no CSRF token, deterministic.
- **Phishing / credential harvesting** on a look-alike page.
- **OAuth/OIDC authorization-code or token theft** when an app's redirect allowlist
  trusts same-site *relative-looking* `next`/`return` paths — the `//host` slips past
  a "must start with `/`" check (it does start with `/`).
- **Cache poisoning:** the response is a highly-cacheable `301`; a shared/edge cache
  that keys on path but not on the unkeyed `X-Forwarded-Prefix` header stores the
  poisoned `Location` and serves it to *other* users.
- **Blast radius:** every user of the app (pre-auth). **Chains:** with **VULN-010**
  (`Scheme()` spoofing) the attacker controls both scheme *and* host of app-built
  absolute URLs; feeds any app OAuth/SSO/"next" flow.

## Suggested fix

In `redirectTrailingSlash` (`gin.go:813-822`): do not prepend an empty prefix, and
defensively collapse any leading `//` on the whole built path before emitting.

```go
prefix = sanitizePathChars(prefix)
prefix = removeRepeatedChar(prefix, '/')
if prefix != "" {                              // never build "" + "/" + "/path" = "//path"
	p = prefix + "/" + req.URL.Path
}
// belt-and-braces, immediately before redirectRequest(c):
req.URL.Path = "/" + strings.TrimLeft(req.URL.Path, "/")   // a leading "//" can never survive
```

Principle: an allowlist/normalization guard must be validated on its *output* (the
final `Location`), not only on an intermediate fragment; and `X-Forwarded-Prefix` is
proxy-trust input that should be gated behind trusted-proxy configuration.

## References

- **CVE-2023-26125** / gin PR #4414 — the `sanitizePathChars` fix this bug bypasses.
- **CWE-601** — URL Redirection to Untrusted Site.
- **OWASP** Unvalidated Redirects and Forwards Cheat Sheet; **WSTG-CLNT-04**.
- **PortSwigger Web Security Academy** — open redirection: protocol-relative `//evil`
  bypass of relative-path allowlists (the exact browser behavior relied on here).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 40 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database search `gin-gonic` — gin advisories are CVE-2023-26125 (X-Forwarded-Prefix, fixed 1.9.0), CVE-2023-29401, CVE-2020-36567, CVE-2020-28483, CVE-2019-25211 (cors); no post-2023 redirect advisory
2. OSV listing for `github.com/gin-gonic/gin` (8 entries), Snyk package page ("5 total vulnerabilities, none affect 1.12.0"), gin repo security advisories page (none published) — nothing newer than CVE-2023-26125
3. GHSA-3vp4-m3rf-835h (CVE-2023-26125) — header-injection open redirect / cache poisoning, fixed by PRs #3500 / #3503 (regex sanitization); the empty-prefix residual is not described
4. gin PR #4414 (merged Nov 2025, v1.12) — replaced the regex with `sanitizePathChars` / `removeRepeatedChar` for performance; no security report or test for the empty-result case
5. gin issue / PR search `X-Forwarded-Prefix` (7 results) — #1238, #2916, #3500, #3503, #3907, #4414, #4599; none reports a `..` / empty-prefix bypass
6. gin issue / PR search `redirectTrailingSlash` (31) and `open redirect` (65, page 1) — relevant items are PR #3907 and PRs #4726 / #4731 (below); others are routing / trailing-slash behaviour
7. gin PR #3907 "fixed open redirect" (Mar 2024, closed unmerged Feb 2026) — reports `redirectTrailingSlash` emitting `Location: //evil.com` when the request **path** begins with `//` (route `/:p1/:p2`, request `//evil.com/`), affecting <= 1.9.1; fix collapses leading `//`; does not involve `X-Forwarded-Prefix` or the sanitizer's empty output
8. gin PR #4726 / #4731 "fix: [security] Bad redirect check" (Jul 2026, open / draft, from a code-scanning alert) — collapses leading `/` and `\` runs in `cleanPath` (`path.go`) to block scheme-relative and backslash redirects; `redirectTrailingSlash`, the header and `..` are not mentioned
9. gin releases v1.10.0 – v1.12.0 — no security note on redirects or X-Forwarded-Prefix
10. (gin-specific WebSearch queries could not be executed — the shared search budget was exhausted before this folder; all checks above were direct fetches)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2023-26125 / GHSA-3vp4-m3rf-835h — same header and same sink, fixed in 1.9.0; this finding is a bypass of that fix (sanitizer output "" recreates the `//`), which is not described there
- gin PR #3907 — same sink (`redirectTrailingSlash`) and same outcome (`Location: //<first-segment>`) reached through a path starting with `//` instead of the header; the proposed fix would also close this bug; strongest near-miss
- gin PR #4726 / #4731 — `cleanPath` guard against `//` / `/\` leading sequences; different function, not applied on the default `redirectTrailingSlash` path

**Reasoning:** No advisory or issue describes the `X-Forwarded-Prefix: ..` -> `sanitizePathChars` -> empty prefix -> `"" + "/" + path` concatenation that re-creates a protocol-relative `Location`. However, the identical sink and identical attacker outcome were publicly reported in PR #3907 via a path-based trigger, and maintainers have an open `//` redirect hardening PR, so a vendor or CNA may regard this as a variant of already-reported behaviour rather than a new vulnerability; confidence is therefore low. Review PR #3907 before disclosure and present this as the header-based residual of CVE-2023-26125.
