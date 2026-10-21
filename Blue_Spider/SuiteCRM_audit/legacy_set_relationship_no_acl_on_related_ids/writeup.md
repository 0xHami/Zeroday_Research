# VULN-078 — Legacy `set_relationship`: Relate/Detach Arbitrary Records With Only View on the Primary (BOLA)

**ID**: VULN-078
**Software / Repository**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2, commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 5.4** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
**Status**: `CONFIRMED (dynamic)`
**Auth required**: Any authenticated web-service user (lowest privilege) — needs only `view` on
the primary record, and literally nothing on the related record
**What an attacker gains**: The ability to create or destroy relationships between two arbitrary
records — e.g. adding themselves/a confederate to a Security Group or team, or linking records
across ownership boundaries — even when they cannot edit either record and cannot even read one of
them.

## Summary

The legacy `set_relationship`/`set_relationships` methods relate or detach two records by id. The
only authorization check anywhere in the call chain is `ACLAccess('DetailView')` (view, not edit)
on the **primary** record; the related record(s) passed in `$related_ids` receive no ACL check of
any kind. Live testing proves both halves of the gap in one test: a low-priv user whose Role
explicitly denies `edit` on the primary module and denies **all** access (view and edit) to the
related module still successfully created a real relationship row between two records neither of
which they could otherwise touch — while their direct attempts to edit the primary and read the
related record were both correctly denied by the same account, same session.

## How it works (mechanism & code trace)

**Entry point**: `POST /service/v4_1/rest.php`, `method=set_relationship`,
`rest_data=[session, module_name, module_id, link_field_name, related_ids, name_value_list?, delete?]`.
The outer method (`service/core/SugarWebServiceImpl.php:270-301`) only checks the session is valid,
then delegates straight to the helper.

**The defect** — `service/core/SoapHelperWebService.php:816-864` (`new_handle_set_relationship`):
```php
$mod = new $class_name();
$mod->retrieve($module_id);
if (!$mod->ACLAccess('DetailView')) {                                 // :832  VIEW-only, PRIMARY only
    return false;
}
if ($mod->load_relationship($link_field_name)) {
    if (!$delete) {
        ...
        $mod->$link_field_name->add($related_ids, $name_value_pair);   // :852  NO ACL on $related_ids
    } else {
        foreach ($related_ids as $id) {
            $mod->$link_field_name->delete($module_id, $id);           // :855  NO ACL on related id
        }
    }
    return true;
}
```
Two gaps in the same nine lines: (1) the gate on the primary checks `DetailView` (read), not the
`edit` access the UI's own EditView/subpanel-save actions require for the identical operation —
a channel divergence; (2) `$related_ids` — records the caller may have never even been allowed to
view — never passes through `checkACLAccess()` or any equivalent at all before `Link2::add()`/
`delete()` writes the relationship row.

**Live confirmation** (full transcript in `run.log`): a low-priv user's Role explicitly set
`Accounts` `edit = ACL_ALLOW_NONE` and `Contacts` `view = edit = ACL_ALLOW_NONE`. Over that user's
session:
- `set_entry` to rename the Account → `{"name":"Access Denied","number":40,"description":"You do
  not have access"}` (edit correctly denied).
- `get_entry` to read the Contact → the same "Access Denied" fault (view correctly denied — the
  user has *zero* access to this record).
- `set_relationship("Accounts", <account_id>, "contacts", [<contact_id>])` →
  `{"created":1,"failed":0,"deleted":0}`, and the live `accounts_contacts` table shows a real,
  non-deleted row linking exactly those two ids.

## Why it is a vulnerability (reasoning)

The trust boundary is the same "your access level gates what you may do to a record" contract
every other authorization control in SuiteCRM enforces. The UI's own EditView/subpanel-relate
actions require `edit` on the record being modified — relating a Contact to an Account changes
both records' relationship state, which the UI correctly treats as a write, not a read. The legacy
service channel checks only `view`, and only on one side of the relationship. There is no
legitimate reason a user who cannot see a Contact at all should be able to attach that Contact to
an Account — the whole point of denying `view` is that the record's existence and details should
not be knowable to this user, yet this API lets them manipulate its relationships blind. This is a
straightforward omission, not a deliberate "relating doesn't need edit rights" design choice — the
V8 REST API's equivalent relationship controller ACLs *both* sides correctly (per the static
finding's comparison), confirming the framework's authors know the correct behavior; the legacy
channel simply never enforces it.

## Reproduction

1. **Preconditions** (built by `automation.py`): a low-priv user with a Role denying the primary
   module's `edit` and the related module's `view`+`edit` entirely; an admin-owned primary record
   and an admin-owned related record.
2. **Decisive request** (`request.http`):
   ```
   POST /service/v4_1/rest.php
   method=set_relationship&input_type=JSON&response_type=JSON&rest_data=
     ["<low-priv session>","Accounts","<account_id>","contacts",["<contact_id>"]]
   ```
3. Run `./run.sh` (`run.log` has the full transcript, including both control denials). Expected:
   ```
   ==> VULN-078: CONFIRMED — low-priv user (Accounts edit=NONE, Contacts view=edit=NONE) related
   Account <id> <-> Contact <id> via set_relationship; accounts_contacts row confirmed in DB;
   direct edit/read of the same records via the same session were denied
   ```
4. **Observable proof**: `response.txt` / `evidence/set_relationship_response.json` show
   `{"created":1,"failed":0}`; the decisive evidence is the live `accounts_contacts` row captured
   in `run.log`, plus `evidence/control_edit_account.json` and `evidence/control_read_contact.json`
   showing the same user denied on both direct paths.

## Impact

A low-privilege authenticated user with only *view* on one shared record can relate or detach
records they have zero rights over. Concretely: add themselves (or a confederate account) into a
Security Group / team relationship to widen their own effective access, inject records into
another user's Prospect List (feeding mass-mail abuse via the campaign findings), or sever a
team/record relationship to disrupt collaboration — all while never being able to view or edit the
counter-party record directly. Chained with the enumeration primitives
([VULN-001](../../vulns/VULN-001.md) JSON-RPC `retrieve`, [VULN-003](../../vulns/VULN-003.md)
document IDOR) to harvest target ids first, an attacker operates entirely on records outside their
ACL. It is the relationship-layer analogue of the field-mass-assignment bug in
[VULN-077](../../vulns/VULN-077.md) and shares the same "populate/act without an allow-list" root
cause family as [VULN-001](../../vulns/VULN-001.md)/[VULN-003](../../vulns/VULN-003.md).

## Suggested fix

Require `ACLAccess('edit')` (not `DetailView`) on the primary bean, and call `checkACLAccess()` on
**each** related id (via `BeanFactory::getBean($related_module, $id)` + `ACLAccess('DetailView')`
at minimum, `edit` if the relationship action itself is a write both sides should approve) before
`->add()`/`->delete()`. Reject the whole operation if the caller lacks the required rights on
either end — matching the UI's EditView/subpanel authorization and the V8 relationship
controller's already-correct behavior.

## References

- CWE-639 — Authorization Bypass Through User-Controlled Key
- CWE-285 — Improper Authorization
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- PortSwigger — Access control vulnerabilities: https://portswigger.net/web-security/access-control
- Technique used: differential authorization testing — deny edit-on-primary and all access to the related record via a purpose-built Role, prove both are individually enforced by direct API calls, then show the relationship-write path ignores both, verified via a live join-table row.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched GHSA-qmh9-m7g7-pxxp (CVE-2026-61650) — V8 `POST /Api/V8/module/{m}/{id}/relationships/{link}` checks only view/list before creating a relationship; fixed 7.15.2. V8 only; does not touch `service/core/SoapHelperWebService.php::new_handle_set_relationship()`.
2. Fetched GHSA-6jf7-hh5p-8fcm (CVE-2026-100360) — V8 relationship delete bypasses object-level authorization on the related record; fixed 7.15.2. V8 only.
3. Fetched GHSA-m6x8-3hxp-qxwv (CVE-2026-29189) — "REST API V8 IDOR: Missing ACL Checks on User Preferences and Relationship Endpoints"; fixed 7.15.1. V8 only.
4. Fetched GHSA-3phg-q9w9-4pqw (CVE-2026-69134) — SQL injection in the legacy v4 `set_relationship` via the unsanitized `RAW_REQUEST` copy; same method, but a SQLi sink, not the missing ACL on `$related_ids`; fixed 7.15.2 without adding authorization.
5. Fetched GHSA-8qfx-h7pm-2587 (CVE-2024-45392, "Wrong deletion permission checks on API delete call") and inspected the v7.14.4..v7.14.5 diff — the fix is in `Api/V8/Service/ModuleService.php::updateRecord()` (`deleted` attribute now requires `ACLAccess('delete')`); V8 only.
6. GitHub issue search `repo:SuiteCRM/SuiteCRM set_relationship ACL related` — 0 results.
7. GitHub commit history of `service/core/SugarWebServiceImpl.php` — no authorization change to `set_relationship` since 2020 (#8824 argument-count fix only).
8. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) reviewed — every relationship-authorization advisory is V8-specific.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-61650 / GHSA-qmh9-m7g7-pxxp, CVE-2026-100360 / GHSA-6jf7-hh5p-8fcm, CVE-2026-29189 / GHSA-m6x8-3hxp-qxwv — the same BOLA pattern (relationship create/delete without edit/ACL on the counter-party) in the **V8 JSON:API**; the legacy v4/v4_1 `set_relationship` path is a different controller and remains unpatched in 7.15.2.
- CVE-2026-69134 / GHSA-3phg-q9w9-4pqw — SQL injection in the same legacy `set_relationship` method; different root cause and sink.
- CVE-2024-45392 / GHSA-8qfx-h7pm-2587 — V8 `updateRecord` delete-flag ACL; different API.

**Reasoning:** The vulnerability class (relationship writes without authorization on the related record) is now well documented for SuiteCRM, but every public advisory and fix targets the V8 API; none names the legacy `SoapHelperWebService::new_handle_set_relationship()` view-only guard or its unguarded `Link2::add()/delete()` of caller-supplied ids, which the dynamic test shows still works on 7.15.2. Confidence is moderate because three closely related advisories landed in 2026 (active researcher focus on this exact class), so a parallel report against the legacy channel is plausible even though nothing public matches.
