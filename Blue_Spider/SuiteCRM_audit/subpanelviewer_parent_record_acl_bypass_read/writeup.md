# VULN-024 — SubPanelViewer: read any record's subpanel (parent-ACL bypass)

**ID**: VULN-024
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `forkedSuite`/hotfix snapshot)
**Severity**: High — **CVSS 3.1: 6.5** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — a fresh, unprivileged account created via the normal Users EditView is sufficient; no role, group, or special capability needed.
**What an attacker gains**: read access to the related Contacts/Activities/Documents/Quotes/History of *any* Account (or other subpanel-bearing) record in the instance, regardless of ownership, assignment, or Security-Group membership.

## Summary
SuiteCRM's subpanel AJAX endpoint (`action=SubPanelViewer`) renders the related-record list for a given parent (e.g. "Contacts" under an Account) but never checks whether the requesting user is allowed to *view the parent itself*. Any authenticated user who can guess or obtain a parent record's GUID can pull its subpanel contents — names, related-record fields, counts — for records they have no ownership of, are not assigned to, and are not a Security-Group member of.

## How it works (mechanism & code trace)

**Entry point / routing** — `include/MVC/Controller/action_file_map.php:41`:
```php
$action_file_map['subpanelviewer'] = 'include/SubPanel/SubPanelViewer.php';
```
`SugarController::handleActionMaps()` sees this map entry for `do_action='subpanelviewer'` and does a bare `require_once(...)` of the file — the module's own controller (`AccountsController`, etc.) is never consulted, so no module-specific `pre_action`/ACL hook has a chance to run.

**Sink** — `include/SubPanel/SubPanelViewer.php`:
```php
48: if (empty($_REQUEST['module'])) { die(...); }
52: if (empty($_REQUEST['record'])) { die(...); }
56: if (!isset($beanList[$_REQUEST['module']])) { die(...); }
60: if (!isset($_REQUEST['subpanel'])) { sugar_die(...); }
64: $subpanel = $_REQUEST['subpanel'];
65: $record   = $_REQUEST['record'];
66: $module   = $_REQUEST['module'];
...
86: $bean = BeanFactory::getBean($module);           // module-level bean shell, NOT the parent record
...
90: $subpanel_object = new SubPanel($module, $record, $subpanel, $aSubPanelObject, $layout_def_key, $collection);
...
96: $subpanel_object->display($countOnly);           // renders the related rows
```
Every check here is a *presence* check (`empty()`/`isset()`), never an *authorization* check. `$record` — the parent's GUID — is threaded straight into `SubPanel::__construct()` and then `display()`, which builds and runs the subpanel's SQL query and renders whatever rows match the relationship. At no point is a bean for `record` loaded and passed through `ACLAccess('DetailView')`, and no Security-Group visibility filter is applied to the parent.

**The defect, precisely**: the code implicitly assumes that because the *module-level* "list" ACL for the child module (e.g. Contacts) was satisfied elsewhere in the UI, showing rows related to an arbitrary parent is safe. It never re-validates that the caller may view *this specific parent record* — the missing line is, conceptually, `if (!BeanFactory::getBean($module, $record)->ACLAccess('DetailView')) { die(...); }` before line 90.

**Why the framework doesn't save it**: because dispatch happens via `action_file_map`, this file runs completely outside `SugarController::process()`'s normal per-module `hasAccess`/`ACLAccess` machinery for the *specific record* (the module-level list check some controllers perform is a different, coarser check and isn't present here at all — nothing gates `record`).

## Why it is a vulnerability (reasoning)
SuiteCRM's authorization model is meant to enforce, per record, "can this user view/edit this specific row" via `ACLAccess()` plus Security-Group row-level filtering — that's the entire point of the DetailView/ListView ACL checks used everywhere else in the product. `SubPanelViewer` is a *relationship-traversal* primitive: it lets a caller pivot from "a GUID I have" to "every row related to that GUID," which is exactly the kind of operation that must re-check the parent's visibility, because the parent GUID may have been obtained out-of-band (leaked in another response, guessed, enumerated) rather than through a screen that already vetted access. Skipping that check converts any parent-record GUID into a key that unlocks its entire relationship graph. This is not an intentional "public subpanel" feature — every other read path in SuiteCRM (DetailView, ListView, the legacy REST API) does call `ACLAccess`; this generic AJAX helper is the outlier.

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates victim **V** and attacker **A** (`create_user`, no relationship between them, no Roles configured in this lab). As **V**, create an Account and a Contact whose `account_id` points at that Account — both owned by V.
2. **Attack request**, as **A**, zero relation to either record:
   ```
   GET /index.php?module=Accounts&action=SubPanelViewer&record=<victim_account_id>&subpanel=contacts&inline=1&ajaxSubpanel=true
   Cookie: PHPSESSID=<attacker session>
   ```
   (full request in `request.http`)
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected terminal output ends with:
   ```
   [PROOF] victim Contact last_name marker 'V024Contact_438d4a1a' present in A's subpanel response: True
   ==> VULN-024: CONFIRMED — attacker read victim's related Contact (...) via SubPanelViewer with zero ACL prompt
   ```
4. **Observable proof** — `response.txt` records a `200 OK` whose body is the rendered subpanel `<table>`, containing a row for the victim's Contact (`evidence/leaked_subpanel_snippet.txt` isolates the exact leaked fragment). No login redirect, no "no access" string, no HTTP error.

## Impact
An attacker with any valid low-privilege account can:
- Enumerate related Contacts, Activities (Calls/Meetings/history), Documents, and Quotes for any Account/Opportunity/Case/etc. they can name a GUID for (GUIDs are frequently visible elsewhere: URLs, other list views, export files, or the read-IDOR cluster below).
- Harvest attacker-useful metadata (names, emails embedded in related rows, quote totals, document titles) that the ACL/Security-Group model was specifically configured to withhold.
- Chain with [VULN-001] (broad GUID enumeration) and [VULN-004]/[VULN-002] (further per-record read-IDORs) to pivot from "one leaked GUID" to "read most of the CRM's relationship graph."

Blast radius: confidentiality-only, but instance-wide (every module with a subpanel) and pre-authorization (post-authentication only — `PR:L`).

## Suggested fix
In `include/SubPanel/SubPanelViewer.php`, before constructing the `SubPanel` object (i.e. before line 90):
```php
$parentBean = BeanFactory::getBean($module, $record);
if (empty($parentBean) || empty($parentBean->id) || !$parentBean->ACLAccess('DetailView')) {
    sugar_die($GLOBALS['app_strings']['LBL_NO_ACCESS']); // or ACLController::displayNoAccess(true);
}
```
Apply the same Security-Group visibility filter used elsewhere to the parent lookup. Principle: every entry point that dereferences a caller-supplied record GUID — including "helper" AJAX endpoints reached via `action_file_map` — must independently authorize that specific record; module-level list access must never be treated as a substitute for record-level `ACLAccess`.

## References
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (Testing for Insecure Direct Object References).
- PortSwigger Web Security Academy — "Insecure direct object references" (IDOR via a related/child resource lookup that never re-validates the parent).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM SubPanelViewer action=SubPanelViewer access control bypass record IDOR` — no result names `SubPanelViewer`; returned CVE-2026-29189 (V8 REST), CVE-2026-32697 (8.x `RecordHandler::getRecord`), CVE-2025-64490, CVE-2020-8802.
2. `SuiteCRM "SubPanelViewer" vulnerability OR advisory OR huntr OR CVE` — no advisory, huntr report, or CVE mentions it.
3. `SugarCRM OR SuiteCRM "SubPanelViewer" subpanel ACL bypass advisory OR exploit OR CVE` — nothing for SugarCRM lineage either; only CVE-2025-64490, CVE-2026-32697, CVE-2026-29189.
4. SuiteCRM 7.15.x release-notes security list + GitHub repo advisory titles (7.15.1, 7.15.2, 20 most recent) — record-level bypasses listed are `changeReportPage` (GHSA-v624-ccrf-9v97 / CVE-2026-63218), `generatePdf` (GHSA-m5xj-rrwv-g3q3 / CVE-2026-63217) and `download.php` (GHSA-j2r4-r4wh-339v); none is the subpanel AJAX endpoint.
5. GitHub issue search `repo:SuiteCRM/SuiteCRM SubPanelViewer ACL` / `SubPanelViewer record access` — only unrelated UI/performance issues (#5313, #1952).
6. Upstream `hotfix` branch `include/SubPanel/SubPanelViewer.php` (2026-10-21): no `ACLAccess`/`checkAccess` on the parent `record`; unchanged. NVD keyword query for SuiteCRM CVEs 2026-04-01..2026-10-21 — only CVE-2026-108712/108713.

**Related but distinct public references** (same class or component, not this bug):
- GHSA-v624-ccrf-9v97 / CVE-2026-63218 — same class (direct controller action skips the per-record ACL that DetailView enforces) but for AOR_Reports `changeReportPage`.
- GHSA-m5xj-rrwv-g3q3 / CVE-2026-63217 — IDOR in the `generatePdf` entry point.
- CVE-2026-32697 — SuiteCRM 8 `RecordHandler::getRecord()` missing view ACL; different codebase layer.
- CVE-2026-29189 / GHSA-m6x8-3hxp-qxwv — V8 REST relationship read without ACL.

**Reasoning:** No public advisory, CVE, issue, or write-up names the `action=SubPanelViewer` / `include/SubPanel/SubPanelViewer.php` endpoint or its missing parent-record authorization, while the vendor has published and fixed several sibling record-level bypasses (changeReportPage, generatePdf, download.php) in the same release cycle without touching this file. The finding is judged undisclosed. Confidence is 80: the search space (record-level ACL bypass in SuiteCRM) is noisy and the endpoint is a long-standing SugarCRM-era component, so an unindexed private report is possible but no near-miss was found.
