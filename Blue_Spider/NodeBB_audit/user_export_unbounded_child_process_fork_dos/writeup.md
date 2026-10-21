# VULN-019 — Unbounded server-side export process-fork DoS

| | |
|---|---|
| **ID** | VULN-019 |
| **Software** | NodeBB |
| **Repository** | https://github.com/NodeBB/NodeBB |
| **Affected version** | 4.16.0 (`install/package.json:5`; commit-pinned, untagged `master`) |
| **Commit** | `20623201cbf2cc8a37612726cdf10ee82083c9c3` |
| **Severity** | Medium — **CVSS 3.1 6.5** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any registered user (amplified by open self-registration). |
| **Attacker gains** | CPU / RAM / PID exhaustion on the app container → denial of service for all users. |

## Summary
Each `POST /api/v3/users/:uid/exports/:type` forks a full Node child process to build the export, guarded only by a per-`(uid,type)` concurrency-1 lock that is cleared the instant the child exits. The three export types are independent locks (3 concurrent forks per account), `canExportData` returns true for self, and the `/api/v3` write chain has no rate limiter. So N accounts × 3 = up to 3N concurrent OS processes. Confirmed dynamically: 5 unprivileged accounts firing all 3 types concurrently were all accepted (15/15 → 202) and spawned up to **18 concurrent** `export-*.js` child processes.

## How it works (mechanism & code trace)

`src/api/users.js:744-769` (excerpt):
```js
usersAPI.generateExport = async (caller, { uid, type }) => {
    if (!await privileges.users.canExportData(caller.uid, uid)) throw ...;   // true for self
    const validTypes = ['profile', 'posts', 'uploads'];
    if (!validTypes.includes(type)) throw ...;                                // allow-list -> no cmd injection
    const count = await db.incrObjectField('locks', `export:${uid}${type}`); // per-(uid,type) lock
    if (count > 1) throw new Error('[[error:already-exporting]]');
    const child = require('child_process').fork(`./src/user/jobs/export-${type}.js`, [], { env: process.env });
    child.send({ uid });
    child.on('exit', async () => { await db.deleteObjectField('locks', `export:${uid}${type}`); ... });  // lock cleared on exit
};
```

- **Fork per request.** `child_process.fork` spawns a whole OS process — expensive, and one per request.
- **Lock is weak.** It only prevents two *simultaneous* exports of the *same* `(uid,type)` and is released on exit, so the same `(uid,type)` is re-triggerable back-to-back; the three types are independent, giving 3 concurrent forks per account.
- **No rate limiter.** `setupApiRoute`'s common chain (`src/routes/helpers.js:57-78`) and the write index add no per-IP/per-uid throttle for `/api/v3`, and `canExportData` returns true for self — so any registered user drives it, and open self-registration multiplies it.

Dynamic confirmation: 15 concurrent requests across 5 accounts → all 202, peak 18 live `export-*.js` children (counted via `/proc/[0-9]*/cmdline` since the slim image has no `ps`). The per-`(uid,type)` lock showed `already-exporting` (400) only for a duplicate *same-type* request, confirming it does not bound the cross-type/cross-account amplification.

## Why it is a vulnerability (reasoning)
An unprivileged, unauthenticated-adjacent (open-registration) actor should not be able to make the server allocate unbounded heavyweight OS processes. The design relies solely on a concurrency-1 lock that is (a) scoped per `(uid,type)` and (b) released on exit — it caps neither the *rate* (no cooldown, no rate limiter) nor the *global concurrent* number of export workers. `child_process.fork` makes each unit of work maximally expensive. This is uncontrolled resource consumption (CWE-400/770), not a benign "missing rate limit": the amplification factor (3 per account × unlimited accounts × re-fire) is unbounded and the per-request cost is a full process. Confirmed the guard does not prevent 18 concurrent forks from a tiny burst.

## Reproduction
1. Create several users (open self-registration in production).
2. From each, concurrently `POST /api/v3/users/<self>/exports/{posts,profile,uploads}`.
3. Observe all requests return 202 and the container's process table fills with `export-*.js` children (peak 18 for 5 accounts here).
4. `./run.sh` automates it (5 users × 3 types, sampling `/proc`) and asserts >3 concurrent children with no rate limiting. Prints `[OK] exploit confirmed`. See `response.txt`/`run.log`.

## Impact
Application-wide DoS via OS-process/PID/CPU/RAM exhaustion, achievable by a small number of ordinary accounts and amplified to effectively-unauthenticated scale by the unthrottled `POST /register` (no core CAPTCHA). Availability-only (`type` is allow-listed, so no code injection / no C/I impact).

## Suggested fix
Add a per-uid **cooldown** (not merely a concurrency lock) between exports, and a **global cap** on concurrent export workers — a bounded queue/pool rather than fork-per-request. Add a generic rate limiter to the `/api/v3` write chain for expensive operations, and consider running exports in a shared worker pool instead of `child_process.fork` per request.

## References
- OWASP Denial of Service Cheat Sheet; WSTG-BUSL-09 (Test Upload/Resource limits).
- CWE-400 (Uncontrolled Resource Consumption); CWE-770 (Allocation of Resources Without Limits or Throttling).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `NodeBB user data export denial of service child process fork rate limit vulnerability` — only CVE-2023-26045 (export path traversal/RCE), CVE-2023-30591 (socket.io event-name DoS) and a community thread about slow exports; no fork-DoS match.
2. `NodeBB "exports" "already-exporting" OR generateExport DoS CVE resource exhaustion` — only CVE-2023-26045 again; no DoS/throttling advisory.
3. NodeBB GitHub security-advisories page + OpenCVE vendor listing (23 CVEs) — DoS entries limited to CVE-2023-30591; nothing on export workers or `/api/v3` throttling.
4. Upstream history of `src/api/users.js` (master) — export-related commits are authorization-only (`39299bd` "dont allow global mods gdpr export", `304665d` "refactor: canExportData check", Jun 2026); no commit mentioning rate limit, cooldown, fork, child process or DoS.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2023-30591 — unauthenticated DoS via crafted Socket.IO event names; different component and mechanism.
- CVE-2023-26045 / GHSA-vh2g-6c4x-5hmp — path traversal in the user-export code path; same feature, different class.
- NodeBB commits 39299bd / 304665d (4.14.x) — tightened *who* may trigger GDPR exports, not how many or how often.

**Reasoning:** No public disclosure describes the per-request `child_process.fork` export guarded only by a per-(uid,type) lock with no cooldown, global cap or `/api/v3` rate limiter. Resource-exhaustion findings of this kind are often treated as hardening without an advisory, so a non-public report is plausible, but nothing in CVE/GHSA/upstream history matches this component. Web-search quota was exhausted mid-triage; later checks were direct fetches of GitHub/OpenCVE pages.
