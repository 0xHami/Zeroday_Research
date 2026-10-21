# VULN-027 — `Administration action=repair` global rebuild runnable by any authenticated user

## 1. Header
- **Title:** Any authenticated user can trigger the global `repairAndClearAll` (missing is_admin gate)
- **ID:** VULN-027 · **Software:** SuiteCRM · **Repository:** https://github.com/SuiteCRM/SuiteCRM
- **Affected version:** 7.15.2 (`suitecrm_version.php`) — commit-pinned `forkedSuite` snapshot · **Commit:** `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
- **Severity:** High · **CVSS 3.1:** 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H`
- **Status:** CONFIRMED (dynamic) · **Auth required:** any authenticated user (RegularUser)
- **What an attacker gains:** on-demand execution of the heaviest global maintenance routine (cache wipe + full extension/vardef/relationship rebuild) → low-effort resource-exhaustion DoS and an authorization-boundary break.

## 2. Summary
The Administration "repair" view runs `repairAndClearAll` — SuiteCRM's Quick-Repair-and-Rebuild that clears every cache and regenerates all compiled extensions — directly in `ViewRepair::display()` with no is_admin check. The `Administration` module is commented out of the `$adminOnlyList` map that would otherwise force admin-only access, so any authenticated user reaches it. Repeatedly invoking it is a cheap way to pin CPU and thrash the instance.

## 3. How it works (mechanism & code trace)
Sink:
```php
// modules/Administration/views/view.repair.php:50-56
require_once('modules/Administration/QuickRepairAndRebuild.php');
class ViewRepair extends SugarView {
    public function display() {
        $randc = new RepairAndClear();
        $randc->repairAndClearAll(array('clearAll'), array(translate('LBL_ALL_MODULES')), false, true); // no is_admin
        ...
```
`repairAndClearAll(['clearAll'], [all modules], ...)` rebuilds vardefs, relationships, extensions, JS/lang caches, and clears the file cache for every module — an expensive, global operation.

Missing gate:
```php
// include/modules.php:283-285
$adminOnlyList = [
    //'Administration' => ['all'=>1, 'SupportPortal'=>'allow'],   // <-- COMMENTED OUT
    ...
```
With `Administration` commented out, the framework's admin-only enforcement for the module is disabled, and `ViewRepair` itself adds none. Dispatch (`action=repair`) reaches `view.repair.php` for any user.

There is a *separate* control — the empty-Referer CSRF guard (`SugarApplication::checkHTTPReferer`) — which does fire for a cross-site (no-Referer) request. Confirmed live: the no-Referer control returned the XSRF template, while the same request with a valid same-origin `Referer` (which every real logged-in user's browser sends) returned the full 85 KB repair page with no access-denied — proving the *authorization* gap is the missing `is_admin`, not covered by CSRF.

## 4. Why it is a vulnerability (reasoning)
"Repair and rebuild" is an administrative maintenance function — the commented-out `$adminOnlyList` entry is direct evidence the developers intended it to be admin-only. Leaving it reachable by any authenticated user violates the least-privilege boundary between ordinary users and system administration, and hands every user a one-request global-rebuild primitive. A skeptic's "the CSRF guard protects it" is refuted by the control test: the guard only blocks the cross-site/no-Referer case; a normal authenticated user (or an attacker who controls a same-origin referer via the app's own pages) bypasses the missing authorization entirely.

## 5. Reproduction
1. Precondition (scripted): admin creates a RegularUser; log in as them.
2. Control: `GET index.php?module=Administration&action=repair` with **no** Referer → XSRF block (CSRF guard).
3. Attack: same GET **with** `Referer: http://localhost:33116/index.php?module=Home&action=index` → HTTP 200, ~85 KB repair page, no access-denied.
4. `./run.sh` → expected:
```
[PROOF] no-Referer repair: HTTP 200, csrf-guard-blocked=True
[PROOF] valid-Referer repair: HTTP 200, len=85836, xsrf=False, denied=False, repair-ran=True
==> VULN-027: CONFIRMED — any authenticated user triggers the global Administration repair/rebuild (BFLA -> DoS)
```

## 6. Impact
Availability: each call is a full global rebuild (heavy CPU/IO, cache thrash); a loop of these degrades or stalls the instance for all users — a low-effort authenticated DoS. Integrity (minor): forcing rebuilds can transiently expose inconsistent cache/extension state. It also confirms a systemic gap — the `Administration` module's admin-only enforcement is disabled, so other Administration views may share the exposure. Blast radius: whole instance.

## 7. Suggested fix
Restore the admin gate at both layers:
```php
// include/modules.php  — re-enable
$adminOnlyList['Administration'] = ['all' => 1, 'SupportPortal' => 'allow'];
// modules/Administration/views/view.repair.php  display() — defense in depth
if (!is_admin($GLOBALS['current_user'])) { ACLController::displayNoAccess(true); sugar_cleanup(true); }
```
Principle: privileged maintenance operations must be authorized by role, independent of (and in addition to) CSRF protection.

## 8. References
- OWASP API Security Top 10 — API5:2023 BFLA; OWASP WSTG-ATHZ-02.
- CWE-862 (Missing Authorization); CWE-400 (Uncontrolled Resource Consumption).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM Administration action=repair Quick Repair non-admin user denial of service vulnerability` — no advisory on non-admin repair; returned CVE-2026-29101 (directory traversal DoS, PR:H) and CVE-2024-36416 (v4 API log DoS).
2. `SuiteCRM "adminOnlyList" Administration module non-admin access repair rebuild vulnerability` — only CVE-2026-108712 (adminOnlyList keyed on request `module`, DetailUserRole) and CVE-2025-64490 (inconsistent RBAC); community threads are functional only.
3. SuiteCRM 7.15.x release-notes security list + GitHub repo advisory API — the only Administration-module entry is GHSA-rxx9-4rg7-c3qp / CVE-2026-100363 (any user performs CRUD on `Administration`/`ACLRoles`/`ACLActions` via the V8 REST API); nothing on the legacy `action=repair` view.
4. GitHub issue search `repo:SuiteCRM/SuiteCRM action=repair non-admin` — 0; `repairAndClearAll is_admin` — only CLI/Makefile issues (#6793, #6605).
5. Upstream `hotfix` branch (2026-10-21): `modules/Administration/views/view.repair.php` still runs `repairAndClearAll()` with no `is_admin` check; `include/modules.php` still has `'Administration'` commented out of `$adminOnlyList`.
6. NVD keyword query for SuiteCRM CVEs published 2026-04-01..2026-10-21 — only CVE-2026-108712 / CVE-2026-108713.

**Related but distinct public references** (same class or component, not this bug):
- GHSA-rxx9-4rg7-c3qp / CVE-2026-100363 — Administration module reachable by non-admins, but through the V8 REST module CRUD API, not the legacy repair view.
- CVE-2026-108712 — analysis of `$adminOnlyList` being keyed on the `module` parameter (DetailUserRole); different entry point.
- CVE-2026-29101 / GHSA-24pf-9cvh-ppcg — DoS via directory traversal in modules, admin-only (PR:H).
- CVE-2025-64490 — inconsistent role enforcement across Resource Calendar/Project screens.

**Reasoning:** No public source describes any authenticated user invoking `index.php?module=Administration&action=repair` (`ViewRepair::display()` -> `repairAndClearAll`) or the missing `is_admin` gate on that view, and the view and the commented-out `$adminOnlyList` entry are unchanged upstream. Related disclosures reach the Administration module only through the V8 API or concern other entry points. Confidence is 75 because the underlying systemic gap (Administration not in `$adminOnlyList`) is broad and visible, so other researchers may have reported sibling Administration views privately; no public near-miss for `repair` was found.
