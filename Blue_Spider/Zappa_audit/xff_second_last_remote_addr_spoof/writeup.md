# VULN-005 — REMOTE_ADDR spoofing via the X-Forwarded-For `addresses[-2]` heuristic

| | |
|---|---|
| **ID** | VULN-005 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium · CVSS 3.1 **5.3** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None (anonymous HTTP, Surface A) |
| **Attacker gains** | Full control of the client IP the app trusts (`request.remote_addr`) |

## Summary
Zappa derives the WSGI `REMOTE_ADDR` from the client-supplied `X-Forwarded-For` header using a fixed
"second-to-last element" rule that only holds for a CloudFront-in-front topology. In every other supported
topology (API Gateway / ALB / Function URL without CloudFront) the attacker controls the value that lands
at `addresses[-2]`, so the app trusts an attacker-chosen client IP. Verified live: two arbitrary IPs were
reflected as `remote_addr`.

## How it works (mechanism & code trace)
**Entry point** — every HTTP request flows through `create_wsgi_request`, which computes `REMOTE_ADDR`:
```python
# targets/Zappa/zappa/wsgi.py:58-65
x_forwarded_for = headers.get("X-Forwarded-For", "")
if "," in x_forwarded_for:
    # The last one is the cloudfront proxy ip. The second to last is the real client ip.
    addresses = [addr.strip() for addr in x_forwarded_for.split(",")]
    remote_addr = addresses[-2]
else:
    remote_addr = x_forwarded_for or "127.0.0.1"
```
That value becomes `environ["REMOTE_ADDR"]` (`wsgi.py:70`), which Flask exposes as `request.remote_addr`
and Django as `request.META["REMOTE_ADDR"]`. The identical logic exists in the ASGI path
(`asgi.py:47-52`).

**The exact defect** — `X-Forwarded-For` is a client-settable header. The code assumes the proxy chain is
always `[..., real_client, cloudfront]` and blindly indexes `[-2]`. But an attacker simply sends their own
list: `X-Forwarded-For: <chosen>, <junk>` puts `<chosen>` at `[-2]`; a single value with no comma is used
verbatim. AWS API Gateway/ALB/Function URL (without CloudFront) *append* the true source IP but do **not**
strip a client-supplied `X-Forwarded-For`, so `addresses[-2]` is attacker data.

**Why the platform doesn't save it** — the platform can't; the header is legitimately forwarded, and
Zappa never learns how many proxies are actually in front of it. The safe design counts from the number of
*trusted* proxies, not a hardcoded offset.

## Why it is a vulnerability (reasoning)
The security invariant "the app can trust `remote_addr` for IP-based decisions" is violated: the field is
attacker-controlled. Any IP allow-list (e.g. "admin only from 10.0.0.0/8"), IP-bound rate limit, geo/fraud
check, or audit trail that reads `remote_addr` can be bypassed or poisoned. The feature is *supposed* to
report the genuine client IP; it instead reports whatever the client wrote.

## Reproduction
1. Lab up; run `./run.sh`.
2. Decisive request (`request.http`): `GET /whoami` with `X-Forwarded-For: 13.37.13.37, 203.0.113.9`.
3. Response (`response.txt`): `"remote_addr":"13.37.13.37"` — the attacker's chosen value. Single-value
   `X-Forwarded-For: 192.0.2.66` → `"remote_addr":"192.0.2.66"`. No header → `127.0.0.1`.
4. Expected `[OK] exploit confirmed` / `==> VULN-005: CONFIRMED`.

## Impact
Silent bypass of IP allow-lists and IP-bound rate limits, plus forged source IPs in audit logs, for any
app that trusts `REMOTE_ADDR`. Not a breach by itself, but a bypass primitive. **Chaining:** defeats
IP-based rate limiting → brute force/enumeration (compounded by VULN-027, no framework throttle); combines
with VULN-007 (log forging) to erase the attacker's tracks.

## Suggested fix
- In `wsgi.py:58-65` (and `asgi.py:47-52`), make the number of trusted proxies explicit and configurable,
  and index as `addresses[-(1 + trusted_proxies)]`, defaulting to treating `X-Forwarded-For` as untrusted
  unless a proxy count is configured. Principle: derive client IP from a *known* trusted-proxy depth, never
  a fixed positional guess.
- Document that `REMOTE_ADDR` is only trustworthy behind the exact assumed topology.

## References
- CWE-348 (Use of Less Trusted Source), CWE-290 (Authentication Bypass by Spoofing).
- Upstream issue [#772](https://github.com/Miserlou/Zappa/issues/772) — the `addresses[-2]` rule *is* that
  issue's partial fix; the residual spoofability is its unfixed tail.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 35 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa X-Forwarded-For REMOTE_ADDR spoofing second to last cloudfront issue 772` — only generic XFF-spoofing material (Datadog, PortSwigger, Zend advisory); nothing Zappa-specific beyond the cited issue.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=X-Forwarded-For OR remote_addr OR REMOTE_ADDR` — reviewed #772, #632 (= Miserlou #1604), #470, PR #1228, #1127/#1128/#1163 (whitespace parsing only).
4. `wsgi.py`/`asgi.py` on master — `addresses[-2]` heuristic unchanged; no trusted-proxy-count setting.

**Related but distinct public references** (same class or component, not this bug):
- Miserlou/Zappa #772 (Apr 2017, closed) "wsgi remote_addr can be user spoofed" — the original spoofing report; its fix is the `addresses[-2]` rule this finding attacks. Nobody discussed residual spoofability.
- Miserlou/Zappa #1604 / zappa #632 (2018, open/auto-closed) "remote_addr is not correct in wsgi.py" — reports `[-2]` is wrong in non-CloudFront topologies (single-IP header, or 3-IP chains behind existing infra); framed as incorrectness, not spoofability.
- zappa #470 / PR #1228 — proposals to expose `requestContext.identity.sourceIp`; maintainer says `REMOTE_ADDR` is already the client IP. No spoofing discussion.

**Reasoning:** The spoofability of `REMOTE_ADDR` via `X-Forwarded-For` in this exact function was publicly reported in #772 and "fixed" by the `[-2]` heuristic; this finding is that the fix is incomplete for API Gateway / ALB / Function URL without CloudFront. That residual has not been stated publicly as a spoofing issue, but #1604 already documents the heuristic being wrong in those topologies, so this is a partial match (same component and sink, incomplete fix). Kept with low confidence.
