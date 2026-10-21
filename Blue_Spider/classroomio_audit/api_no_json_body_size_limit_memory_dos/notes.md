# VULN-037 — No global JSON body-size limit (memory-exhaustion DoS)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Validated at**: 2026-09-27

## Preconditions
- None (unauthenticated). The body is buffered by the HTTP server before any handler.

## Request
See `request.http`. `POST /agent/credits/purchase` with a 1/10/30 MB body and
`Content-Type: application/json` (fixed spoofed `X-Forwarded-For` to isolate the bucket).

## Response
- 1 MB → HTTP 401; 10 MB → HTTP 401; 30 MB → HTTP 401. **No `413 Payload Too Large`** at
  any size; no connection reset. The application-level 401 JSON is returned only after the
  Node HTTP server has read the entire request body.

## Observation
Matches the static finding: `apps/api/src/app.ts:52-106` has no `hono/body-limit`, and
`apps/api/src/index.ts` starts `@hono/node-server` with no `maxRequestBodySize`. So the
server accepts and buffers arbitrarily large bodies. The 401 (from `authOrApiKeyMiddleware`)
rather than a 413/reset confirms the server ingested all 30 MB before responding. Repeated
concurrently — with VULN-018 (free sessions) and VULN-036 (unthrottleable) — this is a
memory-exhaustion DoS. Sizes were kept modest (≤30 MB) to avoid disrupting the shared stack;
the absence of a 413 at 30 MB already proves no limit is enforced.

## Side effects
None. The body was invalid JSON / the request was unauthenticated, so no state changed.

## Research & references
- OWASP API Security Top 10 2023 — API4:2023 Unrestricted Resource Consumption; CWE-770.
- Hono docs — `bodyLimit` middleware is the intended control; its absence is the gap.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. (Actually crashing the process would require sustained concurrent large bodies; not
performed to protect the shared instance — the missing-limit primitive is proven.)
