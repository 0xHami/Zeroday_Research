# VULN-092 — CSV Import forges audit/provenance metadata + updates records by id with no row ACL

## 1. Header
- **Title**: CSV Import honors caller-mapped audit fields and updates existing rows by id with no per-row ACL check
- **ID**: VULN-092
- **Software**: SuiteCRM — **Repository**: https://github.com/SuiteCRM/SuiteCRM — **Affected version**: 7.15.2 — **Commit**: `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
- **Severity**: Medium — **CVSS 3.1**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5)
- **Status**: `CONFIRMED (dynamic)`
- **Auth required**: Any authenticated user holding the standard, widely-granted per-module `import` ACL (not admin).
- **What an attacker gains**: (a) the ability to forge any created record's `created_by`/`modified_user_id`/`date_entered`/`date_modified` to values the UI never exposes, and (b) the ability to overwrite **any existing record by id**, including ones outside the caller's own edit ACL/Role restrictions.

## 2. Summary
SuiteCRM's CSV Import lets the importing user map arbitrary CSV columns to arbitrary bean fields
via `colnum_N=<field>` — including the audit/provenance fields (`created_by`, `date_entered`,
`modified_user_id`, `date_modified`) that no UI EditView ever exposes as editable, and including
`id` itself. When `id` is mapped and the import runs in "update" mode, `Importer.php` locates the
existing row by that raw id and saves the caller's values over it with **no** `ACLAccess('edit')`,
owner, or SecurityGroup check on the *target row* — only a one-time, module-level `import`
permission is checked when the import starts. Both capabilities were dynamically confirmed against
a low-privilege user whose Role explicitly restricts ordinary Contact editing to records they own:
Import let that same user forge provenance on a new record and overwrite an admin-owned record by
id, while the identical user's *normal* edit attempt on that same record was correctly rejected.

## 3. How it works (mechanism & code trace)
**(a) Audit-stamp forgery** — `modules/Import/Importer.php:505-571` (`saveImportBean`), condensed
to the decisive flag flips:
```php
if ((!empty($focus->new_with_id) && !empty($focus->date_modified)) || (...)) {
    $focus->update_date_modified = false;      // :521 -- keep the CSV's date_modified
}
if (!empty($focus->date_entered)) {
    $focus->update_date_entered = true;        // :526 -- keep the CSV's date_entered
}
...
if (isset($focus->modified_user_id) && $focus->modified_user_id && !$hasDataChanges) {
    $focus->update_modified_by = false;        // :566 -- keep the CSV's modified_user_id
}
if (isset($focus->created_by) && $focus->created_by) {
    $focus->set_created_by = false;            // :570 -- keep the CSV's created_by
}
$focus->save(false);
```
These flags are populated on `$focus` purely because the caller's column mapping
(`$_REQUEST['colnum_N']=created_by` etc., read in `getImportColumns()`,
`Importer.php:710-730`) put a value into that property — the same `SugarBean::save()` flag
mechanism [VULN-081](../VULN-081/writeup.md) exploits via the V8 API, reached here through a
third, independent channel with no comparable strip anywhere in the Import pipeline.

**(b) Update-by-id, no row ACL** — `Importer.php:355-388` (`importRow`, condensed):
```php
if (!empty($focus->id)) {
    $focus->id = $this->_convertId($focus->id);
    $query = "SELECT * FROM {$focus->table_name} WHERE id='".$focus->db->quote($focus->id)."'";
    ($result = $focus->db->query($query)) || sugar_die(...);
    $dbrow = $focus->db->fetchByAssoc($result);
    if (isset($dbrow['id']) && $dbrow['id'] != -1) {
        ...
        $clonedBean = $this->cloneExistingBean($focus);   // :376 -- clones the EXISTING row
        $focus = $clonedBean;
        $newRecord = false;                                // -> $focus->save() UPDATES it
    }
}
```
`cloneExistingBean()` (`:477-491`) retrieves the row by id and overlays only the CSV-mapped
columns — at no point is `ACLAccess('edit')`, an owner check, or a SecurityGroup check performed
against *this specific row*. The only authorization gate in the whole Import flow is at controller
entry, `modules/Import/controller.php:80-86`:
```php
} elseif ($this->bean->bean_implements('ACL')) {
    if (!ACLController::checkAccess($this->bean->module_dir, 'import', true)) {  // module-level only
        ACLController::displayNoAccess();
        sugar_die('');
    }
}
```
— a **module-level** "may this user import into Contacts at all" check, entirely blind to which
specific row an `id`-mapped update targets.

**Dynamically proved as a genuine bypass, not just an open ACL**: a throwaway Role restricted the
test user `L`'s `Contacts` `edit` action to `ACL_ALLOW_OWNER`. A baseline legacy-REST `set_entry`
edit of an admin-owned Contact `V` — which exercises the identical `ACLAccess('save')` gate the
classic EditView uses — was rejected (`{"name":"Access Denied","number":40}`), and `V` was
confirmed unchanged in the db. The **same** `L`, via `Import` with `id` mapped to `V` and
`import_type=update`, then successfully changed `V.last_name` — `V.assigned_user_id` stayed
`admin`'s id throughout, proving this was an unauthorized cross-ownership write, not a side effect
of `L` somehow gaining ownership.

## 4. Why it is a vulnerability (reasoning)
Two related but distinct trust boundaries are violated. First: *system-stamped audit metadata must
not be caller-writable* — the same invariant [VULN-077](../../vulns/VULN-077.md) and
[VULN-081](../VULN-081/writeup.md) violate through other channels; three independent code paths
sharing the same gap is strong evidence this is a systemic pattern in how SuiteCRM's bean-save
"auto-stamp" mechanism was integrated, not a one-off. Second: *a caller's edit permissions on
module X must be checked per-record, not merely "may this user use feature Y at all"* — the module
`import` ACL is an *entry* gate (may you use the Import feature), not a *row* gate (may you modify
this specific record); conflating the two lets a widely-granted, low-stakes-seeming permission
("can import Contacts," typical for data-entry roles) silently subsume "can edit any Contact,"
which is not what granting `import` alone should imply.

## 5. Reproduction
Preconditions: `L` with a Role restricting `Contacts` `edit` to `ACL_ALLOW_OWNER`; victim Contact
`V` owned by admin.

Baseline (blocked):
```
POST /service/v4_1/rest.php
method=set_entry&rest_data=["<L sid>","Contacts",[{"name":"id","value":"<V>"},{"name":"last_name","value":"ShouldNotStick"}]]
  -> {"name":"Access Denied","number":40,"description":"You do not have access"}
```
Part (a) — audit forgery (two real requests: upload, then run):
```
POST /index.php  module=Import&action=Confirm&import_module=Contacts  + multipart userfile=<csv>
  csv: ForgedImp92_xxx,1,2010-01-01 00:00:00,1
POST /index.php  module=Import&action=Step4&import_module=Contacts&tmp_file=<scraped file_name>&
  columncount=4&colnum_0=last_name&colnum_1=created_by&colnum_2=date_entered&colnum_3=modified_user_id&
  importlocale_dateformat=Y-m-d&importlocale_timeformat=H:i:s&importlocale_timezone=UTC
```
Part (b) — update-by-id IDOR:
```
POST /index.php  module=Import&action=Confirm&import_module=Contacts  + multipart userfile=<csv: <V>,Overwritten92_xxx>
POST /index.php  module=Import&action=Step4&import_module=Contacts&tmp_file=<scraped file_name>&
  columncount=2&colnum_0=id&colnum_1=last_name&import_type=update
```
Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log` — expect `[OK]` then `==> VULN-092: CONFIRMED …`.
Observable proof: `run.log`/`evidence/db_rows.txt` show the new Contact's
`created_by=modified_user_id='1'` (admin) and `date_entered='2010-01-01 00:00:00'`; and `V`'s
`last_name` changed to the attacker's value while `V.assigned_user_id` stayed `1` (admin) — the
exact write the baseline request, moments earlier, was denied for.

## 6. Impact
**Integrity**: any user with the common `import` permission can (a) forge a record's authorship
and creation/modification dates — undermining audit trails, non-repudiation, and any compliance
process trusting `created_by`/`date_entered` — and (b) modify arbitrary existing records by id,
bypassing Role/SecurityGroup restrictions that correctly gate the same field via every other save
path. **Chaining**: combined with the read-IDOR cluster ([VULN-001](../../vulns/VULN-001.md),
[VULN-024](../../vulns/VULN-024.md)) for harvesting target ids, an attacker with only `import`
rights can tamper with records across ownership/team boundaries at will. **No privesc**: `Users`
import requires admin and `user_hash` is not importable, so this does not escalate to admin
account takeover — confirmed unaffected.

## 7. Suggested fix
- Do not honor caller-mapped `created_by`/`date_entered`/`date_modified`/`modified_user_id` for
  non-admin imports; keep `SugarBean`'s default auto-stamp flags regardless of which columns were
  mapped (mirror the V8 `updateRecord()` strip suggested in VULN-081).
- On the update-by-id branch (`Importer.php:355-388`), call `ACLAccess('edit')` plus an
  owner/SecurityGroup check on the **existing** target row before `cloneExistingBean()`/`save()`;
  treat a denied row as a per-record error, not a silent skip or a free pass.

## 8. References
- CWE-915 — Mass Assignment: https://cwe.mitre.org/data/definitions/915.html
- CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR): https://cwe.mitre.org/data/definitions/639.html
- OWASP Mass Assignment Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- OWASP WSTG-ATHZ-04 — Testing for IDOR: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- Sibling findings in the same forgery class: [VULN-077](../../vulns/VULN-077.md) (legacy
  `set_entry`), [VULN-081](../VULN-081/writeup.md) (V8 `createRecord`).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `suitecrm import` — CVE-2021-41595 / CVE-2021-41596 (directory traversal via the Import Step3 `file_name` parameter, fixed 7.10.33/7.11.22) and CVE-2020-15301 (CSV injection into exports); none concern audit-field mapping or update-by-id authorization.
2. GitHub Advisory Database query `suitecrm mass assignment` — 0 advisories.
3. Fetched GHSA-8rjm-vpj3-hch8 (CVE-2026-100364) and GHSA-jhhh-64wx-fj9c (CVE-2026-100361) — V8 JSON:API `id`-injection record overwrite and sensitive-field mass assignment, fixed 7.15.2; V8 only, not `modules/Import/Importer.php`.
4. Upstream v7.15.1..v7.15.2 diff of `modules/Import/Importer.php` — only primary-email reconciliation and a `=== false` sanitiser fix; the audit-flag flips in `saveImportBean()` and the ACL-free `cloneExistingBean()` update branch are unchanged.
5. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) — no Import-module advisory of any kind since 2021.
6. Scanner's own prior query `SuiteCRM Import Importer created_by date_entered audit forgery` — recorded as no match.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases, CVE.org records and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2021-41595 / CVE-2021-41596 — directory-traversal file read via Import Step3 `file_name`; same module, different class and parameter.
- CVE-2026-100364 / GHSA-8rjm-vpj3-hch8 — V8 API overwrite of any record by injecting `id` into attributes; the V8 analogue of the update-by-id branch, different channel.
- CVE-2026-100361 / GHSA-jhhh-64wx-fj9c — V8 mass assignment of `user_hash`/`external_auth_only`; different channel and fields.
- CVE-2020-15301 — CSV injection on export; opposite direction.

**Reasoning:** The Import module's only public advisories are 2021 path-traversal bugs; nothing describes mapping CSV columns to `created_by`/`modified_user_id`/`date_*` to defeat SugarBean auto-stamping, or `import_type=update` resolving a target row by caller-supplied `id` with only a module-level `import` ACL. Confidence is moderate because the same two defects were publicly reported against the V8 API in Oct 2026 (showing researchers are actively enumerating these channels), the Import behaviour is partly a long-standing SugarCRM design that may have been discussed as "expected" in forums, and no general web query could be run within this run's budget.
