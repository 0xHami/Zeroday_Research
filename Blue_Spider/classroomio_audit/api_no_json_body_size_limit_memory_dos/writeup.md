# VULN-037 — No global JSON body-size limit (memory-exhaustion DoS)

| | |
|---|---|
| **ID** | VULN-037 (raw F-29) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.3** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None |
| **What an attacker gains** | Force the API to allocate unbounded per-request memory → memory-exhaustion denial of service |

## Summary

No middleware caps request body size and the Node HTTP server sets no
`maxRequestBodySize`, so every JSON endpoint buffers the entire request body into memory
before Zod validation runs. An unauthenticated attacker (amplified by VULN-018 free
sessions and VULN-036 unthrottleable requests) sends many large bodies to exhaust the
process's memory. Confirmed live: 1 MB, 10 MB, and 30 MB bodies were all accepted and
buffered (HTTP 401 from a later middleware, never `413 Payload Too Large`).

## How it works (mechanism & code trace)

**Middleware chain — `apps/api/src/app.ts:52-106`.** The global chain is `logger` →
`prettyJSON` → `secureHeaders` → CORS → session resolution → `rateLimiter`. There is **no**
`bodyLimit` (Hono ships `hono/body-limit` for exactly this) anywhere in the chain.

**Server bootstrap — `apps/api/src/index.ts`.** The app is served with
`serve()` from `@hono/node-server`; no `maxRequestBodySize`/`maxHeaderSize` option is
passed, so Node's HTTP server imposes no application body cap. Per-route `zValidator('json', …)`
handlers call `c.req.json()`, which reads and buffers the whole body *before* the schema
runs — so even a body destined to fail validation is fully materialized in memory first.

Only multipart file uploads have their own size checks (in the media/presign paths); plain
JSON endpoints — the majority — have none.

## Why it is a vulnerability (reasoning)

The invariant a hardened API upholds is "a single request cannot cause unbounded server
resource allocation." Here the per-request memory cost is attacker-controlled and unbounded:
the server reads N bytes into memory for any N the attacker sends, on any JSON route,
before it can even decide the request is unauthorized. Because the body is buffered *ahead*
of auth/validation, the attacker doesn't need an account or a valid payload — the cost is
paid on ingestion. A 401/400 response is cold comfort: the memory was already allocated.

We proved the absence of a limit rather than actually crashing the process (which would be
irresponsible on a shared instance): a `413`/connection-reset at some size would indicate a
cap; none appeared through 30 MB. Combined with VULN-018 (unlimited free sessions) and
VULN-036 (the rate limiter can't throttle a rotating-IP flood), an attacker can open many
concurrent large-body requests and drive the container (1536 MB `mem_limit` here) to OOM.

## Reproduction

Preconditions: none (target up).

1. `POST /agent/credits/purchase` (or any JSON route) with `Content-Type: application/json`
   and a 30 MB body of arbitrary bytes.
2. Observe **HTTP 401** (auth rejects it) — crucially *not* `413` and not a reset: the
   server read all 30 MB before responding.
3. `./run.sh` → sends 1/10/30 MB, prints `[PROOF] bodies up to 30 MB were buffered with no
   413`, `[OK]`, exit 0. See `run.log` / `response.txt`.
4. To weaponize (not run here): fire many such requests concurrently (rotating
   `X-Forwarded-For` per VULN-036 so none are throttled) until the API container OOMs.

## Impact

- **Availability:** memory-exhaustion DoS of the API process; with the 1536 MB container
  limit, a modest number of concurrent tens-of-MB requests can force an OOM restart, and a
  sustained flood keeps it down.
- **Amplified by** VULN-018 (no account needed) and VULN-036 (no effective rate limit).
- No confidentiality/integrity impact by itself (A:L).

## Suggested fix

Add a global body limit early in the chain in `apps/api/src/app.ts` (before the routers):

```ts
import { bodyLimit } from 'hono/body-limit';
app.use('*', bodyLimit({ maxSize: 1 * 1024 * 1024,          // 1 MB default
                         onError: (c) => c.json({ error: 'Payload too large' }, 413) }));
```

Grant higher caps only on the specific routes that need them (media/import). Optionally
also set a `maxRequestBodySize` on the node-server `serve()` call as defence in depth.
Principle: bound per-request resource allocation before doing any work on the request.

## References

- OWASP API Security Top 10 2023 — API4:2023 Unrestricted Resource Consumption; CWE-770/CWE-400.
- Hono `bodyLimit` middleware documentation.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; none is a resource-exhaustion / DoS issue.
2. `classroomio github security advisory GHSA` — 9 GHSAs; none on request body limits.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no CWE-400/770 entry.
5. Issue tracker `"413" OR "payload too large" OR bodyLimit OR "body limit" OR "request size" OR "memory exhaustion" OR DoS` — 10 hits; #1257 (display real video upload limit) is the closest and concerns multipart uploads, not JSON bodies.
6. Issue tracker `"rate limit" OR x-forwarded-for OR "body size" OR "race condition" OR "student limit"` — nothing on body size.
7. Commit search `"rate limit" OR bodyLimit OR "body limit" OR "trusted proxy" OR "student limit"` — 20 commits; no `bodyLimit` / `maxRequestBodySize` commit.
8. Fetched `main` `apps/api/src/app.ts` — global chain is logger → prettyJSON → secureHeaders → CORS → session → rateLimiter; still no `hono/body-limit` or `maxRequestBodySize`. `docker-compose.yaml` on `main` exposes only `UPLOAD_MAX_*` (multipart) limits.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- Issue #804 / PR #812 — rate-limit keying (an amplifier for this finding), not body size.
- `UPLOAD_MAX_*` environment limits / PR #1257 — multipart upload caps only; JSON routes are not covered.

**Reasoning:** No public record notes the absence of a global JSON body-size cap on the Hono API or the resulting pre-auth memory buffering. The upstream code on `main` still lacks any such limit, and the only size controls that exist publicly are multipart upload caps. Missing body limits are a common hardening gap, so a private note is possible, but nothing was found in advisories, OSV/Snyk, the tracker, or commit history.
