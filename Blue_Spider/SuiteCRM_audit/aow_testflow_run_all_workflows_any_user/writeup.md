# VULN-026 — `AOW_WorkFlow testFlow` runs all active workflows for any authenticated user

## 1. Header
- **Title:** Any authenticated user can force execution of all active workflows via `testFlow`
- **ID:** VULN-026 · **Software:** SuiteCRM · **Repository:** https://github.com/SuiteCRM/SuiteCRM
- **Affected version:** 7.15.2 (`suitecrm_version.php`) — commit-pinned `forkedSuite` snapshot · **Commit:** `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
- **Severity:** High · **CVSS 3.1:** 7.1 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L`
- **Status:** CONFIRMED (dynamic) · **Auth required:** any authenticated user (RegularUser)
- **What an attacker gains:** on-demand, out-of-schedule execution of every active admin-authored workflow (mass field updates, record reassignment, automated email blasts).

## 2. Summary
The `AOW_WorkFlow` controller exposes `action_testFlow`, which calls `run_flows()` — the exact routine the scheduler uses to execute all *active* workflows — with no authorization check of any kind, and the module is not registered in the admin-only map. Any logged-in user can hit one URL to fire every active workflow immediately, turning an admin-scoped automation feature into a user-triggerable action.

## 3. How it works (mechanism & code trace)
Entry point / sink:
```php
// modules/AOW_WorkFlow/controller.php:633-642
protected function action_testFlow()
{
    echo 'Started<br />';
    require_once('modules/AOW_WorkFlow/AOW_WorkFlow.php');
    $workflow = BeanFactory::newBean('AOW_WorkFlow');
    if ($workflow->run_flows()) {          // :639  scheduler's "run every active workflow" routine
        echo 'PASSED';
    }
}
```
There is no `is_admin()` gate, no `ACLAccess()` call, and no `$this->action` whitelist. The module-level backstop that would force admin-only access does not cover it: `AOW_WorkFlow` is absent from `$adminOnlyList` (`include/modules.php`). `run_flows()` iterates all `AOW_WorkFlow` beans with `status='Active'` and `run_mode` scheduled and executes their actions — identical to a scheduler tick. Dispatch is case-insensitive, so `action=testFlow` reaches `action_testFlow()` for any caller.

Confirmed live: as a non-admin, `GET index.php?module=AOW_WorkFlow&action=testFlow` returned `Started<br />PASSED` (`response.txt`) — `run_flows()` ran to completion with no authorization.

## 4. Why it is a vulnerability (reasoning)
Workflow *authoring* is admin/role-gated, and workflow *execution* is intended to happen only on the scheduler's cadence — the trust model is "admins define automations; the system runs them on schedule." `testFlow` breaks that invariant by letting any user trigger the execution phase on demand. This is not by-design: it is a developer/test action (`echo 'Started'/'PASSED'`) that was left reachable without the authorization the rest of the admin surface enforces. A skeptic's "it only runs existing workflows" understates it: forcing off-schedule runs is itself the abuse (timing-sensitive automations, rate-limited email blasts, mass reassignments fired repeatedly).

## 5. Reproduction
1. Precondition (scripted): admin creates a RegularUser; log in as them.
2. `GET /index.php?module=AOW_WorkFlow&action=testFlow` with the session cookie.
3. Run `./run.sh` → expected:
```
[PROOF] response begins: 'Started<br />PASSED...'  (Started=True, PASSED=True, access-denied=False)
==> VULN-026: CONFIRMED — any authenticated user runs all active workflows via testFlow -> run_flows() (BFLA)
```
Observable proof: `Started ... PASSED` in the response (`response.txt`/`run.log`).

## 6. Impact
Any user repeatedly forces execution of all active workflows: mass updates/reassignments applied off-schedule, automated emails blasted on demand (spam/mail-bomb amplification, especially combined with VULN-059), and repeated invocation is a resource-exhaustion DoS. With admin-authored workflows that reassign ownership or change stages, a user can manipulate business state they otherwise cannot. Blast radius: every record any active workflow touches.

## 7. Suggested fix
Gate the action on admin, or (better) remove the test action from production:
```php
// modules/AOW_WorkFlow/controller.php  action_testFlow()
if (!is_admin($GLOBALS['current_user'])) { ACLController::displayNoAccess(true); sugar_cleanup(true); }
```
and add `'AOW_WorkFlow' => ['all' => 1]` (or the specific action) to `$adminOnlyList`. Principle: workflow execution is a privileged, scheduler-owned operation — never expose it as an unauthenticated-by-ACL controller action.

## 8. References
- OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization; OWASP WSTG-ATHZ-02 (Testing for Bypassing Authorization Schema).
- CWE-862 (Missing Authorization).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM AOW_WorkFlow testFlow run_flows any user missing authorization` — nothing on `testFlow`/`run_flows`; only workflow user docs and CVE-2026-108712 (DetailUserRole entry point).
2. `"SuiteCRM" "testFlow" workflow` — no security result; only product documentation and CData connector pages.
3. SuiteCRM 7.15.x release-notes security list + GitHub repo advisory titles (7.15.1, 7.15.2, 20 most recent) — AOW_WorkFlow appears only in GHSA-cx24-rr7r-mxrg / CVE-2026-71550 (LFI via `aow_action`); the only scheduler-related entry is GHSA-gx3x-3f4c-cjmx / CVE-2026-63111 (non-admin creates SchedulersJob).
4. GitHub issue search `repo:SuiteCRM/SuiteCRM testFlow workflow` — 0 results.
5. Upstream `hotfix` branch `modules/AOW_WorkFlow/controller.php` (2026-10-21): `action_testFlow()` at :633 still calls `run_flows()` with no `is_admin`/ACL check; `include/modules.php` `$adminOnlyList` still lacks `AOW_WorkFlow`.
6. NVD keyword query for SuiteCRM CVEs published 2026-04-01..2026-10-21 — only CVE-2026-108712 / CVE-2026-108713.

**Related but distinct public references** (same class or component, not this bug):
- GHSA-cx24-rr7r-mxrg / CVE-2026-71550 — same controller, but LFI/RCE via `aow_action` path traversal, not the ungated `testFlow` execution action.
- GHSA-gx3x-3f4c-cjmx / CVE-2026-63111 — non-admin can create SchedulersJob records (adjacent "trigger scheduled work" class, different module).
- CVE-2026-108712 — missing authorization on the `DetailUserRole` entry point (same BFLA class, different component).

**Reasoning:** No advisory, CVE, issue, or write-up mentions the `AOW_WorkFlow` `testFlow` action or any-user execution of `run_flows()`, and the action remains ungated upstream today despite the vendor patching a different vulnerability in the same controller in 7.15.2. The finding is judged undisclosed. Confidence is 85: the search terms are distinctive and returned no near-miss, with the residual uncertainty being an unindexed private report.
