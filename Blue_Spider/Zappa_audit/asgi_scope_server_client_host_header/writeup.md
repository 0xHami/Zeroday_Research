# VULN-025 — ASGI `Host` header reflected into `scope["server"]` (client-controlled server identity)

| | |
|---|---|
| **ID** | VULN-025 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium (ASGI only) · CVSS 3.1 **5.3** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None (anonymous HTTP to an ASGI deployment, Surface A) |
| **Attacker gains** | Poisons every absolute URL the ASGI app derives from the request host |

## Summary
The WSGI path pins `SERVER_NAME` to a constant, but the ASGI path derives `scope["server"]` straight from
the client `Host` header with no validation. ASGI frameworks (Starlette/FastAPI/Quart) build absolute URLs
(`request.base_url`, `url_for`, redirects, reset links) from `scope["server"]`, so a spoofed Host poisons
them. Verified live: a client Host became `scope["server"][0]`.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/asgi.py:54-60
host = lower_headers.get("host", server_name)          # <-- client-controlled Host
port_header = lower_headers.get("x-forwarded-port", "443")
try:
    port = int(port_header)
except (TypeError, ValueError):
    port = 443
# targets/Zappa/zappa/asgi.py:77
"server": (host, port),
```
Contrast `wsgi.py:73` (`SERVER_NAME = str(server_name)`, i.e. `"zappa"`). The exploit calls the real
`create_asgi_scope` with `Host: attacker.evil.example` and observes `scope["server"] ==
("attacker.evil.example", 8443)` (`response.txt`). The port is the *safe* part (coerced with `int()`,
falls back to 443 — so ASGI avoids VULN-010's raw-string `SERVER_PORT`); the **host** is copied verbatim.

**The exact defect:** client `Host` placed into the authoritative `scope["server"]` with no allow-list
(CWE-644). The safe WSGI pattern (constant server name) was known but not carried to ASGI.

## Why it is a vulnerability (reasoning)
An ASGI app builds absolute URLs from `scope["server"]` unless a trusted-host middleware overrides it.
Reset/verification links, redirects, and cache keys thus reflect an attacker-chosen host. Worst case: a
password-reset email built from `request.base_url` points at the attacker's host, so the victim's reset
token is delivered to the attacker (ATO). This is the ASGI sibling of VULN-004.

## Reproduction
1. Lab up; run `./run.sh` (drives the real `create_asgi_scope`).
2. Proof (`response.txt`): `scope["server"] == ("attacker.evil.example", 8443)`.
3. Real-world (ASGI deployment): `GET /account/reset` with `Host: evil.attacker.tld` → Starlette
   `request.base_url` → `https://evil.attacker.tld/...`.
4. Expected `[OK] exploit confirmed` / `==> VULN-025: CONFIRMED`.

## Impact
Poisoning of every absolute URL an ASGI app derives from the request host; reset-link ATO for apps that
build reset URLs from `request.base_url`; amplified by the API-Gateway cache key excluding forwarding
headers (`core.py:2375`). **Chains:** ASGI sibling of VULN-004; family with VULN-010.

## Suggested fix
- Mirror the WSGI path: set `scope["server"]` from a configured server name / trusted `requestContext`
  domain, or validate `Host` against an allow-list before use (`asgi.py:55`).
- Document that ASGI apps must deploy a trusted-host middleware if they build absolute URLs from the request.

## References
- CWE-644 (Host-header injection). PortSwigger "HTTP Host header attacks". Sibling VULN-004; family VULN-010.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa asgi.py create_asgi_scope scope server host header spoof` — only the ASGI PR's coverage pages and other projects' ASGI header CVEs (Django CVE-2026-3902, Daphne CVE-2026-44546); nothing on Zappa's `scope["server"]`.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. PR #1422 "Add ASGI support and refactor codebase" (merged 2026-03-05, fetched) — description and Copilot/maintainer review comments discuss header-case normalisation and `int()` port parsing only; no mention of Host trust or spoofing.
4. GitHub issue search `zappa/Zappa issues?q=... asgi host` — no issue about the ASGI server tuple.

**Related but distinct public references** (same class or component, not this bug):
- Django CVE-2026-3902 (ASGIRequest header spoofing) and Daphne CVE-2026-44546 — ASGI header-injection issues in different projects.
- VULN-004 sibling (`cloudfront-host`, WSGI/v1 path) — different code path.

**Reasoning:** The ASGI handler is seven months old and no public discussion of `scope["server"]` taking the client `Host` exists. Host-header poisoning is a well-known class, so a private report is possible, but nothing public matches this component.
