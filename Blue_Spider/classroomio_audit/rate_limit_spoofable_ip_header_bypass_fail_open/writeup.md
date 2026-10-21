# VULN-036 — Rate-limit bypass via spoofable client-IP headers (+ fail-open on Redis error)

| | |
|---|---|
| **ID** | VULN-036 (raw F-01) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.3** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **Status** | **CONFIRMED (dynamic)** — header-spoof bypass; fail-open confirmed at code level |
| **Auth required** | None |
| **What an attacker gains** | Unbounded request volume against every rate-limited endpoint → amplifies VULN-018/VULN-004 (unthrottleable anon-session floods / credit minting) and VULN-037 (DoS) |

## Summary

The API derives its rate-limit key from client-controlled proxy headers
(`CF-Connecting-IP` → `X-Real-IP` → `X-Forwarded-For`) with no trusted-proxy check, and
it is published directly on port 21527 with nothing in front to sanitize those headers.
An attacker who rotates `X-Forwarded-For` per request lands each request in a fresh
bucket, so the 100/window limit never trips. The limiter additionally fails **open** —
any Redis error causes the request to be allowed. Confirmed live: 130 requests under a
single spoofed IP hit `429` after exactly 100, while 130 requests with a rotating
`X-Forwarded-For` all returned `200` (zero throttling).

## How it works (mechanism & code trace)

**Key derivation — `apps/api/src/utils/redis/key-generators.ts:20-53`:**

```ts
export const extractClientIp = (c: Context): string => {
  const cfConnectingIp = normalizeIp(c.req.header('cf-connecting-ip'));
  const realIp = normalizeIp(c.req.header('x-real-ip'));
  const forwardedFor = c.req.header('x-forwarded-for');
  const connInfo = getConnInfo(c);
  const remoteAddress = normalizeIp(connInfo.remote.address);

  if (cfConnectingIp) return cfConnectingIp;        // attacker-settable
  if (realIp) return realIp;                        // attacker-settable
  if (forwardedFor) return normalizeIp(forwardedFor.split(',')[0]) ?? 'unknown';  // attacker-settable
  if (remoteAddress) return remoteAddress;          // the ONLY trustworthy value — checked LAST
  return 'unknown';
};
```

The socket peer (`remoteAddress`) — the only value an attacker cannot forge — is consulted
**last**, and only if all three spoofable headers are absent. The code comment even flags
`x-forwarded-for` as "can be spoofed" yet still trusts it. This key feeds the global
limiter's `userKeyGenerator` (for unauthenticated requests) and every per-route limiter
(`invite_preview:${extractClientIp(c)}:…`, etc.).

**No trusted-proxy gate.** There is no configuration of which upstream proxy is allowed to
set these headers, and in this deployment there is no proxy at all — the Hono server is
bound directly to the host port. So the headers arrive straight from the attacker.

**Fail-open — `apps/api/src/middlewares/rate-limiter.ts:101-105` (and the auth-failure
limiter at `:131-135`):**

```ts
    try {
      // ... limiter.isAllowed(key); if (!result.allowed) return 429; await next();
    } catch (error) {
      logRedisUnavailableOnce('Redis rate limiter unavailable, allowing requests without rate limiting', error);
      await next();      // ← any Redis error → request is ALLOWED
    }
```

If Redis is unavailable or errors, the limiter does not degrade to a socket-IP in-memory
limit or fail closed — it simply calls `next()`, disabling rate limiting globally,
including on the authentication endpoints.

## Why it is a vulnerability (reasoning)

A rate limiter's security value rests on the key being an identity the attacker cannot
cheaply change. Here the key is a request header the attacker fully controls, so the
"limit" is per-attacker-chosen-string, i.e. unlimited. The invariant "≤100 requests per
window per client" is not enforced against any real client — only against a cooperative
one that keeps the same header.

Per the project's triage rules, the downstream *brute-force / credential-stuffing*
consequence is out of testable scope and is **not** claimed here. The reportable defect is
the **hardening gap** itself: (a) a security control keyed on spoofable input with no
trusted-proxy check, and (b) fail-open on backend error. Its real weight is as an
amplifier — it removes the only throttle that could slow VULN-018 (anonymous-session
minting), VULN-004 (credit-purchase spam), and VULN-037 (large-body DoS).

## Reproduction

Preconditions: none (target up).

1. Fixed IP (control): send `GET /` 130× with header `X-Forwarded-For: 203.0.113.7`.
   Observe `429` first at request #101 (`X-RateLimit-Remaining` counts 99,98,…,0).
2. Rotating IP (bypass): send `GET /` 130× with `X-Forwarded-For: 198.51.100.<i>` (i=1..130).
   Observe all `200`, zero `429`, `X-RateLimit-Remaining` stays 99 each time.
3. `./run.sh` → prints `[PROOF] rotating the IP sent 130 requests with ZERO 429s, while a
   single IP was blocked after 101`, `[OK]`, exit 0. See `run.log` / `response.txt`.

Fail-open (not run here to avoid disrupting the shared stack; documented for completeness):
stop `cio-redis`, send any rate-limited request, observe it is allowed (limiter catches the
Redis error and calls `next()`).

## Impact

- **Unbounded request volume** against every endpoint, defeating the intended 100/window
  throttle. Directly amplifies: VULN-018 (mint unlimited anonymous sessions), VULN-004
  (spam forged credit purchases), VULN-037 (repeat large-body requests for memory DoS),
  and any auth-endpoint abuse.
- **Fail-open** means an attacker who can perturb Redis (or a transient outage) removes
  rate limiting entirely, including on `/api/auth/*`.
- Availability-oriented (A:L); no direct confidentiality/integrity by itself.

## Suggested fix

In `apps/api/src/utils/redis/key-generators.ts:20-53`: derive the client IP from the
socket peer (`getConnInfo(c).remote.address`) by default, and only honor
`X-Forwarded-For`/`CF-Connecting-IP` when the immediate peer is a configured, trusted
proxy (an allowlist of proxy IPs / a `TRUST_PROXY` setting):

```ts
const peer = normalizeIp(getConnInfo(c).remote.address);
if (isTrustedProxy(peer)) {
  const fwd = normalizeIp((c.req.header('x-forwarded-for') ?? '').split(',')[0]);
  if (fwd) return fwd;
}
return peer ?? 'unknown';
```

In `rate-limiter.ts:101-105,131-135`: on a Redis error for auth-sensitive routes, **fail
closed** (or fall back to a per-socket-IP in-memory token bucket) rather than `next()`.
Principle: never key a security control on unauthenticated input, and never fail open on
a security control.

## References

- OWASP API Security Top 10 2023 — API4:2023 Unrestricted Resource Consumption.
- PortSwigger Web Security Academy — "Bypassing rate limits" (X-Forwarded-For rotation).
- OWASP "X-Forwarded-For" / proxy-header handling guidance (trust only from a known proxy).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; none concerns rate limiting.
2. `classroomio github security advisory GHSA` — 9 GHSAs; none on rate limiting, proxy headers, or fail-open.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no match.
5. Issue tracker `spoof OR "trusted proxy" OR cf-connecting-ip OR x-real-ip OR x-forwarded-for OR extractClientIp OR "fail open"` — 20 hits; #804 and #812 are the closest (inspected below); nothing on header spoofing.
6. Issue tracker `"rate limit" OR x-forwarded-for OR "body size" OR "race condition" OR "student limit"` — #1204 (automation-key video routes lack rate limiting), #804.
7. Fetched issue #804 (2026-07-30, closed via PR #812 "scope public API rate limiting per API key") — reports public-API callers being keyed per IP instead of per key; contains one caveat sentence: "It fails open if Redis is down (rate-limiter.ts:93-96)"; no mention of `X-Forwarded-For` / `CF-Connecting-IP` / `X-Real-IP` spoofing or trusted-proxy checks.
8. Fetched issue #1204 — automation-key presign routes bypass the limiters; no header-spoof or fail-open content.
9. Fetched `main` `apps/api/src/utils/redis/key-generators.ts` — `extractClientIp` still prefers `cf-connecting-ip` → `x-real-ip` → `x-forwarded-for` over the socket address with no trusted-proxy gate (unfixed).
(Note: WebSearch quota exhausted after the general sweep; items 4–9 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- Issue #804 / PR #812 (2026-08-24) — rate-limit keying per API key for public-API callers; publicly notes the Redis fail-open as an aside (partial overlap with the secondary half of this finding) but does not describe the spoofable-header bypass that is the primary defect here.
- Issue #1204 / PR #1211 (2026-09-27) — automation-key routes outside the limiter; a different gap.

**Reasoning:** The primary defect — the limiter's identity key being derived from attacker-settable proxy headers with no trusted-proxy check, allowing a rotating-`X-Forwarded-For` flood to never trip the limit — appears nowhere in advisories, the tracker, or commit history, and the code is unchanged on `main`. The secondary fail-open behaviour is, however, mentioned in one sentence of public issue #804, so part of this writeup is already public knowledge; confidence is therefore reduced to 55 and the fail-open component should be presented as previously noted upstream.
