# VULN-018 — AOW_WorkFlow `DATE_ADD` / identifier SQL injection (admin-authored, scheduler-run)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:28:21Z (lab wall-clock, see run.log)

## Preconditions
- `./run.sh` authors the workflow as **admin** (`_common.admin_session()`) — matches the doc's own scope: workflow authoring is admin/role-gated by design, so this exploit does not claim otherwise.
- `flow_module=AOK_KnowledgeBase`: same reasoning as VULN-017 — a non-correlated `(SELECT SLEEP(N))` in this WHERE clause is evaluated once per candidate row in this lab's MySQL 8.0, so the base table needs to be small. The exploit reads the **live** row count (`get_row_count()`) immediately before timing rather than assuming a fixed count, because this lab is shared with other concurrent stage-10 sessions that insert rows into arbitrary tables mid-run (observed live: a sibling session's own exploit grew `aok_knowledgebase` from 1 to 2 rows between VULN-017's and VULN-018's runs — this run measured `row_count=2` and correctly scaled its expected delay to ~6s).
- An early draft payload also OR'd a bare `(1=1)` after the SLEEP subquery; MySQL's optimizer proved that disjunct constant-true and skipped the SLEEP entirely (measured <1s). Removing the trailing `(1=1)` (confirmed directly against the `db` container first) restored the reliable delay — recorded here because it's a real construction detail, not just "it worked."

## Request
Two HTTP steps (`request.http`):
1. `POST /index.php` `module=AOW_WorkFlow&action=Save` (admin session) — authors an Active workflow on `AOK_KnowledgeBase` with one Date condition whose `value` is `base64(serialize(['now','plus','1', "DAY), '%Y-%m-%d') OR (SELECT SLEEP(3))#"]))`.
2. `GET /index.php?module=AOW_WorkFlow&action=testFlow` — triggers `run_flows()` → `run_flow()` → `get_flow_beans()` → `build_flow_query_where()` → `build_query_where()`, which splices `params[2]`/`params[3]` raw into a `DATE_ADD(...)` expression and executes it. This is the **timed** request, sent **twice**: once as admin, once as a freshly created non-admin user (VULN-026 chaining).

## Response
`response.txt` — `HTTP/1.1 200`, body `Started<br />PASSED<...html...>` (the real `action_testFlow` response), captured with **6.10s wall-clock elapsed** alongside the headers.

## Observation
| checkpoint | who | workflow state | elapsed | delta |
|---|---|---|---|---|
| T0 | admin | (workflow doesn't exist yet) | 0.05s | — |
| T1 | admin | Active | 6.10s | **+6.05s** vs T0 |
| T2 | **non-admin** | Active | 6.06s | **+6.01s** vs T0 |
| T3 | admin | set **Inactive** | 0.05s | −6.05s vs T1 (back to T0) |

Live row count of `aok_knowledgebase` at measurement time was 2 (confirmed via the `db` container), so the expected delay for `SLEEP(3)` is `2 × 3s = 6s` — exactly what was observed, and reproduced with min-of-2 sampling at each checkpoint for stability against unrelated sibling activity in the shared lab. The delay appears exactly when the workflow is Active, disappears when deactivated, and — critically — fires **identically for the non-admin trigger** (T2), directly demonstrating that [VULN-026](../../vulns/VULN-026.md)'s missing ACL check on `action_testFlow` lets any authenticated user force this admin-authored injection to execute on demand rather than waiting for the scheduler.

## Side effects
- 1 `aow_workflow` + 1 `aow_conditions` row created (admin-owned), later set `status=Inactive` by the same script (no manual cleanup needed).
- 1 non-admin user created for the T2 trigger.
- Verified via `docker compose -p cvehunterlab_suitecrm exec -T db mysql ... -e "SELECT value FROM aow_conditions WHERE aow_workflow_id='<id>'"` that the stored `value` is byte-for-byte our base64 blob (read-only check, not part of the attack path — the attack is the two HTTP steps above).

## Research & references
- Technique: PortSwigger "Blind SQL injection with time delays" (https://portswigger.net/web-security/sql-injection/blind), applied to a `DATE_ADD(..., INTERVAL <op> <amount> <unit>)` interval-token injection rather than a typical value-context injection — `securexss()` never sees the payload because it lives inside a `base64(serialize(...))` blob until `unserialize(base64_decode())` inside `build_query_where()`.
- OWASP WSTG-INPV-05 — Testing for SQL Injection.
- [VULN-026](../../vulns/VULN-026.md) — the missing-ACL finding this exploit chains with for the non-admin trigger (T2).

## If FAILED
N/A — CONFIRMED.
