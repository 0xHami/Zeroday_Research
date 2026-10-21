# VULN-036 — Rate-limit bypass via spoofable client-IP headers (+ fail-open)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Status**: CONFIRMED (header-spoof bypass); fail-open is code-level (see below)
**Severity (static)**: Medium
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Validated at**: 2026-09-27

## Preconditions
- None. Unauthenticated. The API is published directly (no fronting proxy) so the
  client sets the headers the limiter trusts.

## Request
See `request.http`. `GET /` with a fixed `X-Forwarded-For` (throttles after 100) vs a
rotating `X-Forwarded-For` (never throttles).

## Response
- Fixed `X-Forwarded-For: 203.0.113.7` → 429 first seen at **request #101** (limit=100/window).
- Rotating `X-Forwarded-For: 198.51.100.<i>` → **130/130 → 200, zero 429s**.
- `X-RateLimit-Remaining` decremented per fixed-IP request (99,98,…) and stayed at 99 for
  each rotating-IP request, confirming the limiter buckets on the header value.

## Observation
Matches the static finding: `extractClientIp` prefers `CF-Connecting-IP` → `X-Real-IP`
→ `X-Forwarded-For` before the socket address, with no trusted-proxy check
(`key-generators.ts:20-53`). Because nothing normalizes these headers (no reverse proxy
in front — the API is on `:21527` directly), an attacker rotating `X-Forwarded-For`
lands each request in a fresh bucket, defeating the 100/window limit entirely. This is
the header-spoof half. The fail-open half (limiter allows the request on any Redis
error — `rate-limiter.ts:101-105,131-135`) was NOT triggered dynamically because doing
so requires inducing a Redis fault, which would disrupt the shared running stack; it is
confirmed by code inspection and documented in the writeup.

Per the report's PHASE 2 triage, the brute-force/credential-stuffing consequence is out
of testable scope; the reportable core is the header-spoof + fail-open hardening gap and
its role amplifying VULN-018/VULN-004/VULN-037.

## Side effects
None (read-only GETs). Requests used spoofed `X-Forwarded-For` buckets, isolated from
any real client's bucket.

## Research & references
- OWASP WSTG-BUSLOGIC / API4:2023 "Unrestricted Resource Consumption"; OWASP "Handling
  X-Forwarded-For" guidance — only trust `X-Forwarded-For` from a known proxy; otherwise
  use the socket peer. PortSwigger "Bypassing rate limits via X-Forwarded-For" — the
  exact rotation technique used here.

## If FAILED
n/a — CONFIRMED for the header-spoof bypass.

## If NEEDS_MANUAL
Fail-open-on-Redis-error demonstration (optional): stop the `cio-redis` container, send
an auth request, observe it is allowed (limiter degrades open) — not run here to avoid
disrupting the shared stack.
