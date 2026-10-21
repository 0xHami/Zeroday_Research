# VULN-003 — `ClientIP()` returns the unvalidated `TrustedPlatform` header ⇒ spoof (defeats `SetTrustedProxies`) + log injection

| | |
|---|---|
| **Software** | Gin (Gin Web Framework) |
| **Repository** | https://github.com/gin-gonic/gin |
| **Affected version** | v1.12.0 (`version.go:8`), untagged master checkout |
| **Commit** | `1bd0ecf2d3e08da37efa270bb7be20c1eddb0d68` |
| **Severity** | **Medium** — CVSS 3.1 **6.5** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None (unauthenticated). App precondition: `engine.TrustedPlatform` set (common on CF/Fly/GAE). |
| **Attacker gains** | Spoof `ClientIP()` to any value **even when `SetTrustedProxies` is correctly configured**, and inject CR/LF/ANSI into the access log via the client-IP field. |

## Summary

When an application sets `engine.TrustedPlatform` — the documented, common way to read the real
client IP behind Cloudflare / Fly.io / Google App Engine — `c.ClientIP()` returns
`c.requestHeader(TrustedPlatform)` **verbatim and first**, before any `RemoteIP()` /
`isTrustedProxy` check, and with **no `net.ParseIP` validation**. Consequently a correctly
locked-down `SetTrustedProxies` (which stops ordinary `X-Forwarded-For` spoofing) is fully
bypassed by the `TrustedPlatform` header; and because the value is never IP-validated it can
carry CR/LF/ANSI and flows unescaped into the Logger's client-IP field, forging log lines.

## How it works (mechanism & code trace)

**The entry point** is the very top of `ClientIP()`:

```go
// targets/gin/context.go:997-1004
func (c *Context) ClientIP() string {
	if c.engine.TrustedPlatform != "" {
		if addr := c.requestHeader(c.engine.TrustedPlatform); addr != "" {
			return addr                        // <-- returned VERBATIM and FIRST, no ParseIP, no proxy gate
		}
	}
	...                                        // RemoteIP()/isTrustedProxy only reached if TP unset/empty
}
```

The `TrustedPlatform` branch short-circuits the entire trusted-proxy machinery below it (lines
1024-1045). There is no `net.ParseIP(addr)` and no check that the *peer* is a trusted proxy —
the header is honored no matter who connects.

**The log-injection sink.** That unvalidated string becomes `param.ClientIP` and is rendered in
the default access-log format with `%15s`:

```go
// targets/gin/logger.go:185-193
return fmt.Sprintf("[GIN] %v |%s %3d %s|%s %8v %s| %15s |%s %-7s %s %#v\n%s",
	param.TimeStamp.Format(...), statusColor, param.StatusCode, resetColor,
	latencyColor, param.Latency, resetColor,
	param.ClientIP,                             // <-- %15s : raw, NOT escaped
	methodColor, param.Method, resetColor,
	param.Path,                                 // <-- %#v : Go-quoted, CR/LF-safe (the safe contrast)
	param.ErrorMessage)
```

`Path` is safely `%#v`-quoted; `ClientIP` is a bare `%15s`. Since VULN-003 lets the ClientIP
string contain CR/LF/ANSI, an attacker forges additional log lines or injects terminal escapes.

**The exact defect.** Two: (1) `context.go:1002` returns a client header as the client IP with
no trusted-proxy gate and no `net.ParseIP`; (2) `logger.go:189` renders it unescaped. Either
alone is a bug; together they chain spoof → forged logs.

## Why it is a vulnerability (reasoning)

`TrustedPlatform` exists to let gin read the real client IP that a *specific trusted platform*
injects. The security precondition is that only that platform can set the header, which is true
only if the edge strips/overwrites it on ingress — but gin trusts it unconditionally, from any
peer, and never validates it is even an IP. That inverts the protection: an operator who does
everything right (sets `SetTrustedProxies` to the exact proxy CIDRs) still has a spoofable
`ClientIP()` the moment they also set `TrustedPlatform` (which the same platforms require). The
dynamic proof isolates this precisely: `X-Forwarded-For` is correctly *ignored* (peer untrusted),
yet `X-CF-Connecting-IP` moves `ClientIP()` to an arbitrary value — so the bypass is attributable
to `TrustedPlatform` alone, not to a misconfiguration. The accepted non-IP value
(`not-an-ip-INJECTED-value`) demonstrates the missing `net.ParseIP` that enables the log sink.

## Reproduction

1. App precondition (modeled by the `tp` engine): `TrustedPlatform="X-CF-Connecting-IP"` +
   `SetTrustedProxies(["192.0.2.0/24"])`.
2. `cd claude_audit/gin/exploits/VULN-003 && ./run.sh`.

Decisive requests (`run.log`):
```
GET /ip  X-Forwarded-For: 9.9.9.9          -> clientIP=172.19.0.1  (peer untrusted: XFF ignored — config is sound)
GET /ip  X-CF-Connecting-IP: 6.6.6.6       -> clientIP=6.6.6.6      (spoofed, defeats SetTrustedProxies)
GET /ip  X-CF-Connecting-IP: not-an-ip-... -> clientIP="not-an-ip-INJECTED-value"  (no net.ParseIP)
```
`curl`: `curl -s -H 'X-CF-Connecting-IP: 6.6.6.6' http://localhost:36276/ip`.

## Impact

- **Defeats a correct trusted-proxy hardening:** the mitigation operators apply for `ClientIP()`
  spoofing (`SetTrustedProxies`) does nothing when `TrustedPlatform` is set — rate limits, IP
  ACLs, geofences, audit attribution keyed on `ClientIP()` are all spoofable.
- **Log injection / forging:** an unvalidated CR/LF/ANSI value in the client-IP field forges
  whole log lines (frame an innocent IP, hide entries) and can inject terminal escapes for an
  operator viewing logs.
- **Chains:** same abuse surface as VULN-002 but *bypasses its remediation*; feeds VULN-012
  (spoof the throttle key guarding the body-DoS).

## Suggested fix

Validate the header and keep it inside the trusted-proxy model:

```go
// context.go ClientIP(), TrustedPlatform branch
if c.engine.TrustedPlatform != "" {
	if addr := c.requestHeader(c.engine.TrustedPlatform); addr != "" {
		if ip := net.ParseIP(addr); ip != nil {       // reject non-IP values (kills log injection)
			return ip.String()
		}
	}
}
```
and render `ClientIP` with a CR/LF-safe verb in the Logger (`logger.go:189`, e.g. `%q`/`%#v`).
Principle: even "platform" headers are attacker-reachable unless proven stripped at the edge —
validate type/shape and neutralize before logging.

## References

- **CVE-2020-28483** (ClientIP spoof) + **CVE-2020-36567** (Logger injection) — revived here.
- **CWE-290**, **CWE-117**. **OWASP** Logging Cheat Sheet.
- Cloudflare `CF-Connecting-IP` / `True-Client-IP` documentation (edge-strip requirement).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database search `gin-gonic` — the gin advisories are CVE-2020-28483 (XFF spoofing), CVE-2020-36567 (logger injection), CVE-2023-26125 (X-Forwarded-Prefix), CVE-2023-29401 (FileAttachment), CVE-2019-25211 (gin-contrib/cors); none mentions `TrustedPlatform`
2. OSV listing for `github.com/gin-gonic/gin` (8 entries) and Snyk package page ("5 total vulnerabilities, none affect 1.12.0") — same set
3. gin-gonic/gin security advisories page — none published
4. gin issue / PR search `TrustedPlatform` (9 results) — #2906 / #3839 (platform constants), #3336 (Cloudflare real IP, resolved by using TrustedPlatform), #4747 (take left-most value of a multi-valued TrustedPlatform header; closed unmerged; no spoofing framing), #3359 (trust XFF from unix sockets); none reports the header being unvalidated, spoofable from untrusted peers, or a log-injection vector
5. gin issue search `log injection OR ClientIP logger escape` — only the 2020 PRs #2237 / #2265 / #2277 (CVE-2020-36567)
6. GHSA-6vm3-jj99-7229 + PR #2237 — the fix quoted only the request path; the client-IP field is not discussed
7. gin `docs/doc.md` — "If you set TrustedPlatform ... it has a higher priority than TrustedProxies" and the CDN "must prevent users from passing it"; documents precedence, not the missing IP validation or the logger sink
8. (gin-specific WebSearch queries could not be executed — the shared search budget was exhausted before this folder; all checks above were direct fetches of index / advisory pages)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2020-28483 / GHSA-h395-qcrw-5vmq — `ClientIP()` XFF spoofing, mitigated by trusted proxies; the `TrustedPlatform` branch sits above that check by documented design
- CVE-2020-36567 / GHSA-6vm3-jj99-7229 / PR #2237 — logger injection fix that escapes only the path (`%#v`); the client-IP field remains `%15s`
- gin docs "TrustedPlatform" notice — states the header takes priority over TrustedProxies and that the CDN must strip it (design caveat, not a vulnerability report)
- gin PR #4747 — multi-value TrustedPlatform header parsing; same code line, different concern

**Reasoning:** The precedence of `TrustedPlatform` over `SetTrustedProxies` is documented behaviour, so the spoofing half of this finding is partly "by design" and a maintainer may reject it; that caps confidence. What no public reference describes is that the header value is returned without `net.ParseIP` and flows unescaped into the default Logger, which turns the design caveat into a log-forging vector (CWE-117) — that combination appears undisclosed.
