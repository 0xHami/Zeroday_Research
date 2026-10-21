# VULN-092 — CSV Import forges audit/provenance metadata + updates records by id with no row ACL

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28

## Preconditions
- Low-priv RegularUser `L`, given a throwaway ACL Role restricting `Contacts` `edit` to
  `ACL_ALLOW_OWNER` (`_c1_common.restrict_role`) — models a realistic "data-entry user, own
  records only" deployment; needed so the update-by-id bypass (part b) demonstrates a genuine
  restriction violation rather than an already-open ACL.
- Admin creates victim Contact `V` (`assigned_user_id=admin`) — outside `L`'s edit ACL.
- The Import wizard is driven via its two functionally load-bearing HTTP steps only
  (source-verified, not guessed): `action=Confirm` (the only step that actually calls
  `UploadFile::final_move()` to place the CSV under `upload://`) and `action=Step4` (the only
  step that instantiates `Importer` and calls `->import()`). The intervening UI-only steps
  (Step2/Step3/DupCheck) are pure presentation and are not needed to trigger the bug.

## Gotcha discovered and worked around (recorded for reproducibility)
Driving `Step4` directly (skipping `Step3`) initially made every datetime-mapped column fail with
`"Invalid datetime"`, regardless of format (`2010-01-01 00:00:00` and `01/01/2010 00:00` both
failed) — confirmed via `upload/import/error_<uid>.csv` inside the app container. Root cause:
`ImportFieldSanitize`'s `dateformat`/`timeformat` are populated from
`$this->importSource->importlocale_dateformat`/`importlocale_timeformat`
(`modules/Import/Importer.php:735-739`), and `ImportDataSource::__get()`
(`modules/Import/sources/ImportDataSource.php:337-347`) resolves those **from `$_REQUEST` first**:
```php
public function __get($var)
{
    if (isset($_REQUEST[$var])) { return $_REQUEST[$var]; }
    ...
}
```
Since `Step4`'s view builds a bare `new ImportFile(...)` with no `setImportFileMap()` call, these
are otherwise undefined. Fix: pass `importlocale_dateformat=Y-m-d`, `importlocale_timeformat=H:i:s`,
`importlocale_timezone=UTC` as extra POST fields on the `Step4` request — after which plain
`Y-m-d H:i:s` values are accepted. This is incidental plumbing, not a security control.

## Request
See `request.http`. Baseline: legacy REST `set_entry` edit attempt on `V` as `L`. Part (a):
`Confirm` (multipart CSV upload) + `Step4` with `colnum_0..3 = last_name,created_by,date_entered,
modified_user_id`. Part (b): `Confirm` + `Step4` with `import_type=update`,
`colnum_0..1 = id,last_name`, CSV `<V's id>,<new last_name>`.

## Response
See `response.txt`. Baseline: legacy REST fault `{"name":"Access Denied","number":40,
"description":"You do not have access"}`. Both imports: `HTTP 200`.

## Observation
Exactly matches the static finding, and the baseline proves the bypass is real (not just "ACL was
never restrictive to begin with"):
- **Baseline**: `L`'s normal `set_entry` edit of `V` is rejected with `Access Denied` (fault 40),
  and `V.last_name` in the db is confirmed unchanged — the `ACL_ALLOW_OWNER` Role restriction is
  genuinely enforced on the normal save path.
- **(a) Audit forgery**: the newly imported Contact's db row shows `created_by='1'`,
  `modified_user_id='1'` (SuiteCRM admin's real id in this install), and
  `date_entered='2010-01-01 00:00:00'` — all three attacker-chosen — even though the record was
  actually created by `L`'s own import request. `Importer.php:521/526/566/570`'s flag flips
  (`update_date_modified=false` when `date_modified` populated;
  `update_date_entered=true` when `date_entered` populated; `update_modified_by=false`/
  `set_created_by=false` when those fields are populated) defeat `SugarBean::save()`'s normal
  auto-stamping.
- **(b) Update-by-id IDOR**: the SAME `L`, under the SAME Role that just blocked a normal edit,
  successfully changed `V.last_name` to the attacker-chosen value via the `import_type=update`
  path — `Importer.php:355-388`'s id-lookup-and-clone (`cloneExistingBean()`) performs no
  `ACLAccess('edit')`/owner check on the *existing* target row, only the one-time, module-level
  `import` ACL checked at `modules/Import/controller.php:80-86`. `V.assigned_user_id` stayed
  `1` (admin) throughout — confirming `L` never gained ownership, only an unauthorized write.

## Side effects
- Creates one throwaway RegularUser, one throwaway ACL Role (random-suffixed, scoped to that user
  only), one victim Contact (whose `last_name` ends up overwritten — cosmetic, harmless demo
  data), and one new Contact with forged provenance. No demo/seed data touched.
- DB verification (as the auditor): see `evidence/db_rows.txt` for the full before/after rows for
  both parts.

## Research & references
- CWE-915 (Mass Assignment) + CWE-639 (IDOR) — OWASP Mass Assignment Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- Same forgery class as [VULN-077](../../vulns/VULN-077.md) (legacy `set_entry`) and
  [VULN-081](../VULN-081/writeup.md) (V8 `createRecord`) — three independent channels.

## If FAILED
n/a — CONFIRMED (both sub-claims).

## If NEEDS_MANUAL
n/a.
