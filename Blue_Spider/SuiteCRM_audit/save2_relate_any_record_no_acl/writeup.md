# VULN-023 — `Save2`: create relationships / relate arbitrary records on any record (no ACL)

**ID**: VULN-023
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `forkedSuite`/hotfix snapshot)
**Severity**: High — **CVSS 3.1: 7.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — a fresh, unprivileged account is sufficient; no ownership, role, or Security-Group membership on the target parent record is needed.
**What an attacker gains**: the ability to force a relationship between any record the attacker controls (or names) and any *other* record in the instance, including ones the attacker has no ownership or ACL grant on — and, as a side effect of `SugarBean::save()`, to overwrite that other record's `modified_user_id`/`date_modified`.

## Summary
`include/generic/Save2.php` is the generic handler behind "relate a record to this parent via a subpanel" across the entire application. It performs the relate-and-save operation with **zero** authorization checks — no `ACLAccess`, `checkAccess`, `is_admin`, or `ACLController` call exists anywhere in the file. Any authenticated user can therefore attach an arbitrary record to any parent record, including ones they do not own, are not assigned to, and have no Security-Group overlap with.

## How it works (mechanism & code trace)

**Entry point / routing** — `action=Save2` is mapped by `action_file_map.php` straight to `include/generic/Save2.php`, bypassing the target module's own controller (`AccountsController`, etc.) — the same generic-dispatch pattern as `DeleteRelationship` ([VULN-022](../../vulns/VULN-022.md)) and `SubPanelViewer` ([VULN-024](../../vulns/VULN-024.md)).

**Sink** — `include/generic/Save2.php:118-204` (condensed to the relevant path):
```php
global $beanFiles, $beanList;
$bean_name = $beanList[$_REQUEST['module']];
require_once($beanFiles[$bean_name]);
$focus = new $bean_name();
$focus->retrieve($_REQUEST['record']);              // :124 -- loads the PARENT bean, no ACL check

...
if (!empty($_REQUEST['subpanel_field_name']) && !empty($_REQUEST['subpanel_id'])) {
    $relName = $_REQUEST['subpanel_field_name'];
    if ($focus->load_relationship($relName)) {
        $focus->$relName->add($_REQUEST['subpanel_id'], $add_values);   // :202 -- the relate
        $focus->save();                                                 // :203 -- persists the PARENT
    }
}
```
A grep for `ACLAccess`/`checkAccess`/`is_admin`/`ACLController`/`displayNoAccess` across this entire file returns nothing. `$focus`, `$relName`, and `$_REQUEST['subpanel_id']` are all attacker-controlled (`module`, `record`, `subpanel_field_name`, `subpanel_id` are ordinary POST fields); the file ends in `handleRedirect()`/a plain `header()` — no ACL-checked view is ever rendered that could catch this after the fact.

**The defect, precisely**: `$focus->retrieve($_REQUEST['record'])` loads *any* bean by id with no visibility check, and the subsequent `add()`/`save()` pair mutates that bean's relationship set and its own row unconditionally. There is no equivalent of the (broken, but at least present) `aclroles`-gated check that `DeleteRelationship.php` has — `Save2.php` has no ACL check of any kind, for any `linked_field`/`relName` value.

**Dynamic proof, showing the mutation crossed the ownership boundary in both directions**:
- A new `accounts_contacts` row appeared linking victim V's Account to attacker A's own Contact (a relationship that did not exist and that A had no standing to create on V's record).
- `SugarBean::save()` (triggered by `Save2.php:203` on **V's** Account bean) stamped **A's own user id** into `accounts.modified_user_id` for V's Account row — direct database evidence that attacker A's unauthorized request altered a column on a record A does not own:
  ```
  accounts.modified_user_id BEFORE: da2826bc-...  (V's own id)
  accounts.modified_user_id AFTER:  1eb995b3-...  (== attacker A's id)
  ```

## Why it is a vulnerability (reasoning)
Relating two records is, in SuiteCRM's own data model, an edit-equivalent operation on the parent — it changes the parent's relationship set and triggers `SugarBean::save()` on it, which is precisely why `EditView`/`DetailView` saves are ACL-checked everywhere else in the application. `Save2.php` is the one write path that skips this entirely, letting any authenticated user reach into a record they have never been granted access to and force new relationship data onto it — data other users may rely on for reporting, ACL/Security-Group inheritance (Team/Security-Group relationships follow the exact same code path), or business process (Campaign target lists). Nothing in the code or the product's documented behavior suggests this is an intentional "anyone can relate anything to anything" feature; it is the same class of oversight as its sibling delete-side bug, [VULN-022](../../vulns/VULN-022.md).

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates victim **V** and attacker **A** (`create_user`, no relationship between them). As **V**, create an Account (owned by V). As **A**, create A's own Contact (owned by A, unrelated to V's Account).
2. **Attack request**, as **A** (full request in `request.http`):
   ```
   POST /index.php?module=Accounts&action=Save2
   Cookie: PHPSESSID=<attacker session>
   Referer: http://localhost:33116/index.php?module=Accounts&action=DetailView&record=<V's account>
   Content-Type: application/x-www-form-urlencoded

   record=<V's account>&subpanel_field_name=contacts&subpanel_id=<A's contact>&subpanel_module_name=Contacts&refresh_page=1
   ```
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected terminal output ends with:
   ```
   [PROOF] V's Account AFTER attack (modified_user_id, date_modified): '1eb995b3-...\t2026-09-28 20:49:24'
   ==> VULN-023: CONFIRMED — non-owner A related Contact ... to V's Account ... via Save2, no ACL check
   ```
4. **Observable proof** — `evidence/db_before_after.txt` shows the new `accounts_contacts` row and V's Account's `modified_user_id` flipping to A's own id, both queried directly from the database, before and after the single attacker request.

## Impact
Any authenticated user, regardless of privilege, can:
- Attach arbitrary records they control (or, since `subpanel_id` accepts any GUID, potentially records they don't even own) to any parent record in the instance.
- Force Team or Security-Group relationship rows via the same code path where those memberships are represented as ordinary relationships, potentially widening their own or another account's data visibility.
- Add arbitrary records to Campaign target/prospect lists tied to campaigns they have no rights to.
- Cause `SugarBean::save()` side effects (modified_user_id/date_modified, and any `before_save`/`after_save` logic hooks configured for that module) to fire on records the attacker does not own, as demonstrated.

Chains with [VULN-001](../../vulns/VULN-001.md)/[VULN-024](../../vulns/VULN-024.md) for GUID discovery, and directly parallels [VULN-022](../../vulns/VULN-022.md) (the delete-side counterpart of this exact missing-ACL pattern).

## Suggested fix
Before the `add()`/`save()` block, verify `$focus->ACLAccess('edit')` (or `ACLController::checkAccess($bean_name, 'edit', true)`) on the retrieved parent bean, and separately authorize the related record itself (load it and check `ACLAccess('view')` at minimum) before relating it. Add CSRF-token validation to this and the other generic write handlers (`DeleteRelationship.php`, etc.) rather than relying solely on the Referer check.

## References
- CWE-284 — Improper Access Control.
- CVE-2026-61650 / CVE-2026-69134 class — relationship-BOLA pattern in SuiteCRM (per stage-07 known-issue cross-check); this generic `Save2` sink itself has no exact published advisory.
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (Testing for Insecure Direct Object References).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM Save2.php subpanel_field_name subpanel_id missing ACL relationship vulnerability` — nothing naming `Save2`, `subpanel_field_name` or `subpanel_id`; only unrelated CVEs (CVE-2020-8802, CVE-2020-28328, CVE-2022-27474, CVE-2026-29096).
2. `SuiteCRM "Save2" action vulnerability OR CVE OR advisory` — only CVE-2020-8802 / KIS-2020-03 (`HomeController::action_saveHTMLField` bean manipulation) and CVE-2026-29109; no `Save2` advisory.
3. `SuiteCRM improper access control relate records relationship any user CVE 2026 subpanel` — CVE-2026-29189, CVE-2026-32697, CVE-2026-108712, CVE-2025-64490, CVE-2024-45392; none is the generic `Save2` handler.
4. GitHub repo advisory API: `GHSA-qmh9-m7g7-pxxp` (CVE-2026-61650, "Incorrect Access Control in V8 relationship creation", `POST /Api/V8/module/{m}/{id}/relationships/{link}`), `GHSA-m6x8-3hxp-qxwv` (CVE-2026-29189, REST API V8), `GHSA-6jf7-hh5p-8fcm` (CVE-2026-100360, V8 API) — all V8 REST API code, not `include/generic/Save2.php`.
5. GitHub issue search `repo:SuiteCRM/SuiteCRM Save2 ACLAccess` — 0 results.
6. Upstream `hotfix` branch `include/generic/Save2.php` (2026-10-21): still no `ACLAccess`/`checkAccess`/`is_admin` call; `retrieve($_REQUEST['record'])` at :124 and `->add($_REQUEST['subpanel_id'])` at :202 unchanged. NVD keyword query for SuiteCRM CVEs 2026-04-01..2026-10-21 — no match.

**Related but distinct public references** (same class or component, not this bug):
- GHSA-qmh9-m7g7-pxxp / CVE-2026-61650 — identical impact (create a relationship on a record the caller cannot edit) but in the V8 REST relationship-creation endpoint; fixed 7.15.2 without touching `Save2.php`.
- GHSA-m6x8-3hxp-qxwv / CVE-2026-29189 — V8 REST relationship endpoints missing ACL checks (fixed 7.15.1).
- CVE-2020-8802 / KIS-2020-03 — legacy `action_saveHTMLField` allowed arbitrary bean modification; different handler and root cause.

**Reasoning:** Every published relationship-creation authorization bypass for SuiteCRM targets the V8 REST API; none names the legacy UI handler `include/generic/Save2.php` or its `subpanel_field_name`/`subpanel_id` parameters, and the vendor's 7.15.2 relationship fixes left this file unchanged. The finding is judged undisclosed. Confidence is 70 because the class (relationship BOLA) is heavily reported in this project and the legacy handler is an obvious sibling of the patched V8 endpoint, so a parallel private report is plausible.
