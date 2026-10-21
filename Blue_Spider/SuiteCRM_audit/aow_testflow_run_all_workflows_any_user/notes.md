# VULN-026 — `AOW_WorkFlow testFlow` lets any authenticated user run all active workflows

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28

## Preconditions
- Any authenticated user (exploit uses a disposable RegularUser, `is_admin=0`, no roles).

## Request
```
GET /index.php?module=AOW_WorkFlow&action=testFlow
Cookie: PHPSESSID=<low-priv session>
```

## Response
`HTTP 200`, body begins `Started<br />PASSED...` — `run_flows()` executed to completion for the non-admin (see `response.txt`). No access-denied, no admin-gate redirect.

## Observation
Matches the finding. `modules/AOW_WorkFlow/controller.php:633 action_testFlow()` calls `$workflow->run_flows()` (`:639`) with no `is_admin()`/`ACLAccess` check, and `AOW_WorkFlow` is not present in `$adminOnlyList` (`include/modules.php`). `run_flows()` is the same routine the scheduler uses to fire every *active* workflow, so any user forces out-of-schedule execution of all active workflows (mass updates, reassignments, email blasts). In this lab no destructive workflows are active, so completion (`PASSED`) is the proof the privileged routine ran; on a production instance with active workflows the side effects are real.

## Side effects
- Executes `run_flows()` once (idempotent-ish; runs whatever active workflows exist). Creates one disposable RegularUser. No data seeded by the exploit itself.

## Research & references
- OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization (BFLA); OWASP WSTG-ATHZ-02.
- CWE-862 (Missing Authorization).

## If FAILED
n/a — CONFIRMED.
## If NEEDS_MANUAL
n/a.
