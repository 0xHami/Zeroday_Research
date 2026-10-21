# VULN-019 — Unbounded export process-fork DoS

**Software**: NodeBB
**Repository**: https://github.com/NodeBB/NodeBB
**Affected version**: 4.16.0 (install/package.json:5; commit-pinned, untagged master)
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 20623201cbf2cc8a37612726cdf10ee82083c9c3
**Validated at**: 2026-09-28

## Preconditions
- Any registered user (self-export). The exploit creates 5 users and fires all 3 export types from
  each concurrently, sampling the container's /proc for export-*.js children.

## Request / Response
See `request.http` / `response.txt` / `run.log`:
```
15 export requests (5 users x 3 types) -> 202/202 (no rate limit)
peak concurrent export-*.js children  -> 18
same-(uid,type) rapid retry           -> 400 [[error:already-exporting]] (per-(uid,type) lock only)
```

## Observation
Confirmed. A small unprivileged burst spawned up to 18 concurrent Node child processes — more than one
account's 3, proving there is no global/per-uid cap and each request forks a heavyweight OS process
(`child_process.fork('./src/user/jobs/export-<type>.js')`, `src/api/users.js:744-769`). All 15 requests
returned 202 (the /api/v3 write chain has no rate limiter). The only guard is the per-(uid,type)
concurrency-1 lock (`already-exporting`), which is cleared on child exit — so the operation is
re-triggerable back-to-back and does not bound the amplification across types/accounts.

## Side effects
Creates 5 throwaway users; spawns short-lived export child processes that exit on their own (they write
small export files to the users' upload dirs). No restart needed; the forks self-terminate. Bounded burst
(15) used deliberately to avoid stressing the host — the DoS extrapolates to N accounts.

## Research & references
- OWASP WSTG-BUSL-09 / DoS testing; OWASP "Denial of Service" — bound expensive operations with a queue
  + global concurrency cap + per-actor rate limit.
- CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits).

## If FAILED
n/a — CONFIRMED.
