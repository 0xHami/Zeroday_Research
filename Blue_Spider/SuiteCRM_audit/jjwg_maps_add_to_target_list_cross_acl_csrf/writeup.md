# VULN-051 — jjwg_Maps `add_to_target_list`: cross-ACL add-to-list, CSRF-able

## 1. Header
- **Title**: jjwg_Maps `add_to_target_list` validates only id format, not authorization; CSRF-able
- **ID**: VULN-051
- **Software**: SuiteCRM — **Repository**: https://github.com/SuiteCRM/SuiteCRM — **Affected version**: 7.15.2 — **Commit**: `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
- **Severity**: Medium — **CVSS 3.1**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (5.4)
- **Status**: `CONFIRMED (dynamic)` — core Accounts/Contacts/Leads/Prospects bypass; the doc's "including Users" sub-claim is genuine in the code but config-gated (not reachable via this action under this lab's default `valid_geocode_modules`) — see §3/§5.
- **Auth required**: Any authenticated user; also CSRF-deliverable against any authenticated victim.
- **What an attacker gains**: association of arbitrary records — including ones the caller has zero `view` ACL on — into any ProspectList, from a second, independent code path from VULN-050 (same root-cause class, different module).

## 2. Summary
`jjwg_Maps` (the bundled Google-Maps integration) exposes `action_add_to_target_list()`, used by
its map view's "add pinned records to a list" feature. The handler checks that `list_id` and each
`selected_ids` entry are syntactically GUIDs (`is_guid()`), and that `display_module` is one of a
fixed set of module names — but never checks whether the caller may *view* or *edit* the target
list or the records being added. Any authenticated user can add arbitrary record ids (harvested
elsewhere, or simply guessed/enumerated) to any list, including records outside their own ACL. The
handler's own code also contains a branch to add `Users` records to a list — a materially more
sensitive capability — though, as verified dynamically, it is inert under this lab's out-of-the-box
configuration for reasons unrelated to security (see §3).

## 3. How it works (mechanism & code trace)
**Entry point**: `POST /index.php?module=jjwg_Maps&action=add_to_target_list` →
`jjwg_MapsController::action_add_to_target_list()`, `modules/jjwg_Maps/controller.php:320`.

Format-only validation (`:325-342`):
```php
$list_id = (!empty($_POST['list_id'])) ? $_POST['list_id'] : '';
$list = get_module_info('ProspectLists');
if (!empty($list_id) && is_guid($list_id)) {           // :328  format check ONLY
    $list->retrieve($list_id);
    ...
}
...
foreach ($_POST['selected_ids'] as $sel_id) {
    if (is_guid($sel_id)) { $selected_ids[] = $sel_id; } // :338  format check ONLY
}
```
`is_guid()` is a regex/format check (36-char GUID shape) — it says nothing about who may view,
edit, or relate the record it names.

The add loop (`:353-384`) — no ACL anywhere:
```php
if (!empty($list) && $list_id == $list->id && !empty($selected_ids) && !empty($this->display_object) &&
        in_array($this->display_object->module_name, array('Accounts', 'Contacts', 'Leads', 'Prospects', 'Users'))) {
    ...
    } elseif ($object_name == 'Contact') {
        $list->load_relationship('contacts');
        foreach ($selected_ids as $sel_id) {
            $list->contacts->add($sel_id);              // :365-367  relate, no ACL/owner check
        }
    } elseif ($object_name == 'User') {
        $list->load_relationship('users');
        foreach ($selected_ids as $sel_id) {
            $list->users->add($sel_id);                  // :380-382  Users, still no ACL
        }
    }
    ...
}
```
There is no `ACLAccess()` call on `$list`, on the bean behind each `$sel_id`, and no
SecurityGroup check — `add()` is a bare relationship-table insert.

**The `Users` branch's actual reachability (source-verified in this lab)**: `$this->display_object`
is set only at `:346-351`:
```php
if (!empty($_POST['display_module']) && in_array($_POST['display_module'], $this->settings['valid_geocode_modules'])) {
    $module_type = $_POST['display_module'];
    $this->display_object = get_module_info($module_type);
}
```
`$this->settings['valid_geocode_modules']` defaults, per `modules/jjwg_Maps/jjwg_Maps.php:62-64`,
to `['Accounts','Contacts','Leads','Opportunities','Cases','Project','Meetings','Prospects']` —
**no `'Users'`** — and this lab's `config` table has no `jjwg`-category override (`SELECT *
FROM config WHERE category LIKE '%jjwg%'` → 0 rows). So `display_module=Users` never populates
`$this->display_object`, the outer guard at `:353` (`!empty($this->display_object)`) evaluates
false, and the `elseif ($object_name == 'User')` code at `:378-382` — while syntactically present
and still missing an ACL check if ever reached — cannot execute via this action against this
lab's shipped configuration. Dynamically confirmed: the response for a `display_module=Users`
request is the literal `{"message":"Target List NOT Updated",...}`, and no `prospect_lists_prospects`
row with `related_type='Users'` is created.

**CSRF**: identical mechanism to VULN-050 — `add_to_target_list` is not `save*`/`delete*`,
`jjwg_Maps` is not in `$modifyModules`, and the action is not in `$globalModifyActions`
(`include/MVC/SugarApplication.php:478-500`), so `isModifyAction()` is false and the empty-Referer
guard never fires.

## 4. Why it is a vulnerability (reasoning)
Same trust boundary as VULN-050 — a module's ACL/SecurityGroup restriction must hold no matter
which feature touches the record — violated here by a second, independently-written handler in a
different module. That two unrelated code paths (`ProspectLists/TargetListUpdate.php` and
`jjwg_Maps/controller.php`) both "add to list" while both omitting the access check strongly
suggests this is a systemic gap in how SuiteCRM's list-membership features were built, not a
one-off decision: the format check (`is_guid`) that *is* present shows the author was thinking
about input validation, just not about authorization — a classic conflation of "well-formed" with
"permitted."

## 5. Reproduction
Preconditions (mirrors VULN-050): low-priv `L` with `Contacts` `view`/`list` denied via a
throwaway Role; admin-owned Contacts `C1`/`C2`; `L`'s own ProspectList `PL`.

```
POST /index.php?module=jjwg_Maps&action=add_to_target_list HTTP/1.1
Cookie: PHPSESSID=<L session>
Referer: http://localhost:33116/index.php?module=jjwg_Maps&action=index

list_id=<PL>&display_module=Contacts&selected_ids=<C1>
```
```
POST /index.php?module=jjwg_Maps&action=add_to_target_list HTTP/1.1
Cookie: PHPSESSID=<L session>
(no Referer header)

list_id=<PL>&display_module=Contacts&selected_ids=<C2>
```
Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log` — expect `[OK]` then
`==> VULN-051: CONFIRMED …`. Observable proof in `run.log`: both requests return
`{"message":"Target List Updated",...}`, and
`SELECT related_id,related_type FROM prospect_lists_prospects WHERE prospect_list_id='<PL>'`
returns both `C1` and `C2` with `related_type='Contacts'`. The third request
(`display_module=Users`) is also run and its factual `"Target List NOT Updated"` result is
recorded — see `response.txt` and `evidence/db_rows.txt`.

## 6. Impact
Same class of impact as VULN-050: cross-ACL list-membership tampering and a record-existence
oracle, CSRF-deliverable against any logged-in victim. The dormant `Users`-add branch is a
materially higher-impact latent risk (associating arbitrary user accounts, including admins, with
an attacker-controlled marketing list) that would activate the moment `valid_geocode_modules` is
reconfigured to include `Users` — worth fixing even though not exploitable out-of-the-box here.

## 7. Suggested fix
Add `ACLAccess('view')` + owner/SecurityGroup checks on `$list` and on every bean resolved from
`$selected_ids` before any `add()` call, mirroring the fix suggested for VULN-050. Independently,
remove `'Users'` from the accepted `object_name` branches (or gate it behind an explicit
capability) so that even a future configuration change cannot silently turn this into a
user-enumeration/list-poisoning primitive against accounts. Add a CSRF token to the request and
validate it server-side.

## 8. References
- OWASP WSTG-ATHZ-04 (IDOR): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- Same `jjwg_Maps` module as CVE-2026-69142 / GHSA-pjc8-2w2x-xcgf.
- See also [VULN-050](../VULN-050/writeup.md) — same root-cause class in a different module.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM jjwg_Maps add_to_target_list vulnerability ACL target list` — CVE-2020-8803 (`add_to_prospect_list` LFI), CVE-2026-29189 (REST API V8); no jjwg_Maps hit
2. `SuiteCRM "jjwg_Maps" CVE advisory` (extended) — only functional GitHub issue #4970; no CVE/GHSA names the module
3. `CVE-2026-63111 OR CVE-2026-69142 SuiteCRM jjwg_Maps` — neither scanner-hinted ID exists in any index
4. Fetched github.com/advisories/GHSA-pjc8-2w2x-xcgf (hinted) — HTTP 404, advisory does not exist
5. `SuiteCRM targetlistupdate OR TargetListUpdate "add to target list" ACL bypass CSRF vulnerability` and `SuiteCRM ProspectLists target list add records without permission IDOR ...` — no target-list membership ACL advisory for any module
6. `"SuiteCRM through 7.15.2 and 8.10.2" missing authorization CVE-2026` (extended) — only CVE-2026-108712 / CVE-2026-108713; neither concerns jjwg_Maps or ProspectLists

**Related but distinct public references** (same class or component, not this bug):
- CVE-2020-8803 / KIS-2020-04 — ProspectLists `add_to_prospect_list` LFI (<= 7.11.11); same "add to list" feature family, different module and bug class
- CVE-2023-3627 / GHSA-qg9r-8vq4-2gp4 — CSRF in SuiteCRM 8 core; same referer-allow-list weakness class, different code base
- 7.14.2 release commit (54bc56c3) — touched `modules/jjwg_Maps/controller.php` and `view.map_markers.php` for jQuery/XSS hygiene, not `action_add_to_target_list`
- VULN-050 (this audit) — same root-cause class in `TargetListUpdate.php`

**Reasoning:** No public advisory, CVE or GHSA references `jjwg_MapsController::action_add_to_target_list()`, its `is_guid()`-only validation, or the absence of ACL/owner checks before `$list->{relationship}->add()`. The jjwg_Maps module has no published security advisories at all, and the two IDs cited by the scanner are non-existent, so this specific sink is judged not publicly known; the general missing-ACL class remains common in SuiteCRM, which is the only caveat.
