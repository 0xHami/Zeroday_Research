# VULN-004 — `cloudfront-host` request header overwrites the app's Host (Function URL)

| | |
|---|---|
| **ID** | VULN-004 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium · CVSS 3.1 **6.1** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None (anonymous HTTP to a directly-exposed Function URL, Surface A) |
| **Attacker gains** | Sets the Host the app sees → reset-link/absolute-URL poisoning (ATO), cache poisoning |

## Summary
On the v1 request path, if the real `Host` looks like a Lambda Function URL (`*.lambda-url.*`), Zappa
overwrites the Host the app will see with a **client-supplied** `cloudfront-host` header — with no proof
the request actually came from the trusted CloudFront distribution the feature assumes. On a directly
exposed Function URL (a supported, common mode) the header is attacker-controlled. Verified live: the app
observed `Host: evil.attacker.example` because the request carried that `cloudfront-host`.

## How it works (mechanism & code trace)
**Entry point** — the v1 branch of `LambdaHandler.handler()`:
```python
# targets/Zappa/zappa/handler.py:802-815
host = raw_headers.get("Host")
...
if host:
    if "amazonaws.com" in host:
        script_name = f"/{settings.API_STAGE}"
    # fix function url domain
    if host.find("lambda-url") > -1 and event.get("headers", {}).get("cloudfront-host"):
        event["headers"]["host"] = event["headers"]["cloudfront-host"]   # <-- overwrite
```
**Hop** — the mutated `event["headers"]` feeds `create_wsgi_request` → `process_lambda_payload_v1`
(`wsgi.py:123-128`), which title-cases the keys and turns `host` into `HTTP_HOST`. Flask exposes it as
`request.host`; Django's `get_host()` and `ALLOWED_HOSTS` read the same value. So the client-chosen host
becomes the app's notion of its own hostname.

**The exact defect** — `cloudfront-host` is an ordinary, client-settable request header. The code trusts
it based only on the *destination* host matching `lambda-url`, never verifying the request came from the
expected CloudFront distribution (e.g. a CloudFront-added secret / `X-Amz-Cf-Id`). For a Function URL not
behind CloudFront, the header is pure attacker input.

**Why the platform doesn't save it** — a directly-exposed Function URL forwards arbitrary client headers to
the Lambda, including `cloudfront-host`. Nothing upstream strips or vouches for it.

## Why it is a vulnerability (reasoning)
The invariant "the app's Host reflects the real request host" is broken: an unauthenticated client sets it
arbitrarily. Host is a trust-bearing value — apps build absolute URLs (password-reset/verification links),
`ALLOWED_HOSTS` checks, cookie domains, and cache keys from it. The feature is meant to *restore* the
genuine host behind CloudFront; without the CloudFront trust check it instead *hands the host to the
attacker*. That is Host-header injection (CWE-644).

## Reproduction
1. Lab up; run `./run.sh`. It delivers a v1 event modelling a CloudFront→Function-URL request.
2. Decisive request (`request.http`): a `/echo` event with
   `Host: abc123def456.lambda-url.us-east-1.on.aws` + `cloudfront-host: evil.attacker.example`.
3. Response (`response.txt`): app-seen `Host = evil.attacker.example`; the control run (no `cloudfront-host`)
   keeps `Host = abc123def456.lambda-url.us-east-1.on.aws`.
4. Expected `[OK] exploit confirmed` / `==> VULN-004: CONFIRMED`.

## Impact
Host-header poisoning on Function-URL deployments. Worst practical case: an app that builds a password-reset
link from `request.host` emails the victim a link pointing at the attacker's host → the reset token is sent
to the attacker → **account takeover** (UI:R — the victim must click). Also web-cache poisoning: the
API-Gateway cache key excludes forwarding headers (`core.py:2375`, `CacheKeyParameters=[]`), so a poisoned
response can be served to other users. **Chains:** compounds VULN-010 (Host→SCRIPT_NAME) and mirrors
VULN-025 (ASGI `scope.server`).

## Suggested fix
- In `handler.py:813-815`, only honour `cloudfront-host` when the request is provably from the expected
  CloudFront distribution — verify a CloudFront-added secret header / `X-Amz-Cf-Id` against an allow-list —
  or gate the behaviour behind an explicit setting that is **off by default**. Principle: never promote a
  client header to a trust-bearing value without authenticating its origin.

## References
- CWE-644 (Improper Neutralization of HTTP Headers in a Response / request-header trust).
- PortSwigger Web Security Academy — "HTTP Host header attacks" (password-reset poisoning, cache poisoning).
- Related: VULN-010, VULN-025; blast-amplifier cache-key note `core.py:2375`.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa "cloudfront-host" header function url host` — only AWS CloudFront/Function-URL docs and a CDK issue about Host on Lambda URLs; nothing on Zappa.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub PR search `zappa/Zappa pulls?q=cloudfront-host OR lambda-url OR "function url" host` and PR #1183 (Feature/function url) — no PR or review comment discusses `cloudfront-host`, let alone its spoofability.
4. `handler.py` commit history on master (fetched) — no commit message mentions cloudfront/host; current master still does `event["headers"]["host"] = event["headers"]["cloudfront-host"]` with no origin check.

**Related but distinct public references** (same class or component, not this bug):
- aws/aws-cdk #20090 — Lambda Function URLs reject a non-matching Host header (explains why the rewrite feature exists); not about Zappa.
- PortSwigger "HTTP Host header attacks" — generic class.

**Reasoning:** The `cloudfront-host` rewrite appears publicly only as Zappa source code; no issue, PR comment, advisory or write-up identifies that the header is client-controlled on a directly exposed Function URL. The feature is recent (Function URL support merged July 2025) and the Host-poisoning class is well known, so a private report could exist, but nothing public was found.
