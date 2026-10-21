# VULN-077 — Legacy `set_entry`: Unbounded Property Mass-Assignment (Chosen-ID Insert, Audit-Trail Forgery)

**ID**: VULN-077
**Software / Repository**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2, commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`
**Status**: `CONFIRMED (dynamic)` — chosen-id insert + audit-field forgery. (The finding's
secondary "unchecked undelete" sub-claim was tested separately and did **not** reproduce; see
"Why it is a vulnerability" and `notes.md` for the honest correction and root cause.)
**Auth required**: Any authenticated web-service user (lowest privilege) — no special ACL needed;
the only gate (`ACLAccess('Save')`) is granted to everyone by default
**What an attacker gains**: The ability to insert a record under a primary key of their choosing
and to forge its author (`created_by`), last-modifier (`modified_user_id`), and creation/edit
timestamps to any value — none of which any legitimate UI form ever exposes.

## Summary

The legacy `set_entry`/`set_entries` web-service methods populate a `SugarBean` by iterating the
caller's `name_value_list` and assigning **every** name directly onto the bean object, with no
allow-list of real business fields. Because `SugarBean::save()` honors several internal control
flags (`new_with_id`, `set_created_by`, `update_modified_by`, `update_date_modified`) that are not
declared in any module's `field_defs`, the populate loop lets a caller set them too — turning
internal bookkeeping flags into request parameters. Live testing confirms: a low-privilege
authenticated user inserted an Account under an attacker-chosen GUID (not the framework's own
`create_guid()`) and set its `created_by`/`modified_user_id` to the admin user's id and its
`date_entered`/`date_modified` to an arbitrary historical timestamp — every one of these values
independently verified in the live `accounts` table.

## How it works (mechanism & code trace)

**Entry point**: `POST /service/v4_1/rest.php`, `method=set_entry`,
`rest_data=[session, "Accounts", name_value_list]`.

**The defect** — `service/core/SugarWebServiceImpl.php:480-492`:
```php
foreach ($name_value_list as $name=>$value) {
    if ($module_name=='Users' && $seed->id!=$current_user->id && $name=='user_hash') continue;   // :481
    if (!empty($seed->field_name_map[$name]['sensitive'])) continue;                              // :484
    if (!is_array($value)) $seed->$name = $value;                                                 // :488  raw property write
    else $seed->{$value['name']} = $value['value'];
}
```
There is no check that `$name` is a real `field_defs` column — any public property on the bean
object is fair game, including `SugarBean`'s own save-time control flags, which `save()` honors
verbatim:
```php
// data/SugarBean.php:2346
if ($this->new_with_id) { $isUpdate = false; }
...
// data/SugarBean.php:2358
if ($this->update_modified_by) {
    $this->modified_user_id = $current_user->id;   // only overridden if this flag is truthy
    ...
}
...
// data/SugarBean.php:2373 (only on insert, i.e. !$isUpdate)
if ($this->set_created_by) {
    $this->created_by = (isset($current_user)) ? $current_user->id : "";
}
if (!$this->new_with_id) {
    $this->id = create_guid();                     // only regenerated if new_with_id is falsy
}
```
By setting `new_with_id=1`, `set_created_by=0`, and `update_modified_by=0`, the caller disables
every one of the framework's own "I will pick this value, not you" safeguards, then supplies the
values itself. `date_entered` needs no flag at all on insert — it is only auto-filled `if
(empty($this->date_entered))`, so simply providing a non-empty value is enough.

**Live confirmation** (full transcript in `run.log`): a low-priv user sent
```
{"id":"<attacker GUID>","new_with_id":"1","name":"...",
 "set_created_by":"0","created_by":"<admin id>",
 "update_modified_by":"0","modified_user_id":"<admin id>",
 "update_date_modified":"0","date_modified":"2000-01-01 00:00:00","date_entered":"2000-01-01 00:00:00"}
```
and the resulting `accounts` row, read directly from the database, showed every one of those
values exactly as submitted — `id` equal to the attacker's own GUID, `created_by`/
`modified_user_id` equal to the admin's id (`1`) despite the actual caller being an unrelated
low-priv account, and both date columns forged to the arbitrary historical timestamp.

## Why it is a vulnerability (reasoning)

The trust boundary violated is "who gets to assert provenance." A record's `id` (for foreign-key/
relationship integrity), `created_by`/`modified_user_id` (the audit trail — who did what), and
`date_entered`/`date_modified` (when) are precisely the facts a CRM's audit trail exists to make
trustworthy and non-repudiable. No SuiteCRM EditView form exposes any of these as editable inputs
— they are populated by the framework itself specifically so a user cannot claim to be someone
else or backdate a record. The populate loop bypasses that boundary entirely because it operates
at the object-property level instead of the `field_defs`-declared level the rest of the framework
(the classic-MVC populate, per the finding's own contrast) already restricts itself to. This is
not a deliberate "trusted API clients may set provenance" design: the same control flags are
absent from every module's `field_defs`, meaning the framework's own metadata says these are not
data fields at all.

**Honest correction on scope**: the static finding also predicted that the same missing-ACL
pattern lets a caller "undelete a soft-deleted row" by sending `deleted=0` without needing Delete
ACL. Dynamic testing (see `notes.md` Part B) shows the API call *appears* to succeed (not blocked,
echoes `deleted:0`) but the database row is **unchanged** — `include/database/DBManager.php:2070-2073`
separately guards the SQL `UPDATE` to skip the `deleted` column whenever the new value is falsy
(`// no need to clear deleted since we only update not deleted records anyway`), so the undelete
never actually reaches the database regardless of ACL. The missing check is real, but this specific
consequence of it is inert against this commit. This does not diminish the confirmed
chosen-id/audit-forgery capability, which is unrelated to that guard and fully reproduced.

## Reproduction

1. **Preconditions**: any authenticated low-priv legacy-REST session (default install grants
   everyone `Save` access; no special Role needed for this half of the finding).
2. **Decisive request** (`request.http`):
   ```
   POST /service/v4_1/rest.php
   method=set_entry&input_type=JSON&response_type=JSON&rest_data=
     ["<low-priv session>","Accounts",[
       {"name":"id","value":"<attacker-chosen GUID>"},{"name":"new_with_id","value":"1"},
       {"name":"name","value":"..."},
       {"name":"set_created_by","value":"0"},{"name":"created_by","value":"<victim user id>"},
       {"name":"update_modified_by","value":"0"},{"name":"modified_user_id","value":"<victim user id>"},
       {"name":"update_date_modified","value":"0"},
       {"name":"date_modified","value":"2000-01-01 00:00:00"},{"name":"date_entered","value":"2000-01-01 00:00:00"}
     ]]
   ```
3. Run `./run.sh` (`run.log` has the full transcript, including the separately-tested Part B).
   Expected:
   ```
   ==> VULN-077: CONFIRMED — chosen id=... honored (not create_guid()'d); created_by/modified_user_id
   forged to admin(1) though the caller was low-priv user ...; date_entered/date_modified forged to
   2000-01-01 00:00:00; all DB-verified. Undelete sub-claim: tested, did NOT reproduce ...
   ```
4. **Observable proof**: `response.txt` / `evidence/partA_set_entry_response.json` show the API's
   own echo; the decisive evidence is the independent DB read in `run.log` (`SELECT id, created_by,
   modified_user_id, date_entered, date_modified FROM accounts WHERE id=...`), matching every
   forged value.

## Impact

Any authenticated user — the lowest privilege level — can plant records with a chosen primary key
(enabling id pre-planting/collision attacks against other IDOR findings that trust a GUID's
provenance, e.g. [VULN-001](../../vulns/VULN-001.md)) and forge the audit trail to frame another
user as the author/last-modifier of content they never touched, at an arbitrary historical
timestamp. This is an integrity/non-repudiation defeat: any process that trusts `created_by`,
`modified_user_id`, `date_entered`, or `date_modified` for accountability (audit logs, "who
approved this," compliance timelines) can be forged by the lowest-privilege account in the system.
It does not grant confidentiality or availability impact, and (per the correction above) does not
extend to reviving soft-deleted records via this path.

## Suggested fix

- Restrict the service populate loop (`SugarWebServiceImpl.php:480-492`) to keys present in
  `$seed->field_defs`, mirroring the classic-MVC populate's boundary.
- Explicitly block `new_with_id`, `set_created_by`, `update_modified_by`, `update_date_modified`,
  and `update_date_entered` from ever being set via request data — these are framework-internal
  save() flags, never business fields.
- Refuse to overwrite an existing `id` (reject `new_with_id` entirely on the service channel, or
  require admin).
- Separately: if a future fix wants `deleted:0` to actually work through this path, remove or
  correct the `empty($bean->deleted)` short-circuit in `DBManager::updateSQL()` — but pair that
  with requiring `ACLAccess('Delete')` for **both** directions of the `deleted` transition, not
  only `deleted==1`.

## References

- CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes
- CWE-472 — External Control of Assumed-Immutable Web Parameter
- OWASP Mass Assignment Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- Adjacent public issue class: CVE-2022-45186 ("recover arbitrary field" excessive-exposure/mass-assignment class in the same legacy service layer).
- Technique used: direct mass-assignment of SugarBean save-time control flags via the legacy REST populate loop, each forged value independently verified against the live database (not the API's own echo); a second, adversarial test specifically targeting the "undelete" sub-claim, which correctly identified a separate unrelated guard (`DBManager::updateSQL()`) that makes it inert.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `suitecrm set_entry` — 0 advisories.
2. GitHub Advisory Database query `suitecrm mass assignment` — 0 advisories (the V8 mass-assignment advisory GHSA-jhhh-64wx-fj9c is indexed by title only; fetched and compared, see below).
3. CVE record CVE-2022-45186 (cited by the scanner as adjacent) — "Authenticated users can recover an arbitrary field of a database" in 7.12.7: a *read*-side field-exposure bug (Orange Cyberdefense PoC), not the write-side control-flag mass assignment.
4. CVE record CVE-2021-45897 — "SuiteCRM before 7.12.3 allows remote code execution"; unrelated class.
5. Fetched GHSA-8rjm-vpj3-hch8 (CVE-2026-100364, "V8 JSON:API processAttributes() Missing ID Filter") and GHSA-jhhh-64wx-fj9c (CVE-2026-100361, "Mass Assignment in V8 API ... user_hash, external_auth_only") — both are the V8 JSON:API (`/Api/V8/module`, `updateRecord()/processAttributes()`), both fixed 7.15.2; neither concerns the legacy `service/core/SugarWebServiceImpl.php` populate loop or the `new_with_id` / `set_created_by` / `update_modified_by` / `update_date_modified` save-time flags.
6. Full SuiteCRM GHSA catalogue (77 published advisories through 2026-10-12) reviewed — no legacy-service mass-assignment / audit-forgery advisory.
7. GitHub commit history of `service/core/SugarWebServiceImpl.php` (API) — no security change to the populate loop since 2020 (only PHP-compat / rector commits).
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-100361 / GHSA-jhhh-64wx-fj9c — mass assignment of `user_hash`/`external_auth_only` via V8 `PATCH /Api/V8/module`; different API layer and different fields (the legacy loop already skips `user_hash`/sensitive fields).
- CVE-2026-100364 / GHSA-8rjm-vpj3-hch8 — V8 `processAttributes()` does not strip `id`, allowing overwrite of another record; V8 only, and an *update*-by-foreign-id bug rather than chosen-id insert / provenance forgery.
- CVE-2022-45186 — read-side "recover arbitrary field" in the legacy service; different direction and impact.
- The existing `user_hash` guard at `SugarWebServiceImpl.php:481` indicates an earlier (pre-2020) fix for cross-user password-hash assignment via `set_entry`; that historical issue covers a different property.

**Reasoning:** Every public mass-assignment / ID-injection advisory for SuiteCRM targets the V8 JSON:API or specific sensitive user fields; none describes the legacy `set_entry`/`set_entries` populate loop honouring SugarBean's internal save-control flags to insert under a chosen id and forge `created_by`/`modified_user_id`/timestamps. Confidence is moderate rather than high because the legacy service has a long history of related authorization fixes (the `user_hash` guard, CVE-2022-45186) and the V8 advisories from Oct 2026 show active researcher attention on exactly this class, so a parallel private report cannot be excluded.
