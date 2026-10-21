# VULN-049 — Connectors module admin-gate bypass: non-admin writes global connector config

**ID**: VULN-049
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `forkedSuite`/hotfix snapshot)
**Severity**: Medium — **CVSS 3.1: 5.4** — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — a fresh, unprivileged account is sufficient; the action is meant to be admin-only.
**What an attacker gains**: the ability to overwrite the instance-wide Connectors field-mapping/display configuration used by every user's connector merge operations, with no administrator involvement.

## Summary
`ConnectorsController`'s single authorization mechanism, the `$admin_actions` allow-list checked once in `process()`, has two defects: a copy-paste typo (`'SavedModifyDisplay'` doesn't match the real action `SaveModifyDisplay`) and a plain omission (`'SaveModifyMapping'` is never listed at all). Both `action_SaveModifyMapping()` and `action_SaveModifyDisplay()` write global, instance-wide connector configuration files, and neither is gated for non-admins as a result.

## How it works (mechanism & code trace)

**Entry point** — `index.php?module=Connectors&action=SaveModifyMapping`, routed to `ConnectorsController::action_SaveModifyMapping()`.

**Gate that should apply but doesn't** — `modules/Connectors/controller.php:52-63`:
```php
public $admin_actions = array('ConnectorSettings', 'DisplayProperties', 'MappingProperties', 'ModifyMapping', 'ModifyDisplay', 'ModifyProperties',
                           'ModifySearch', 'SearchProperties', 'SourceProperties',
                           'SavedModifyDisplay', 'SaveModifyProperties', 'SaveModifySearch', 'RunTest');

public function process()
{
    if (!is_admin($GLOBALS['current_user']) && in_array($this->action, $this->admin_actions)) {
        $this->hasAccess = false;
    }
    parent::process();
}
```
`'SaveModifyMapping'` never appears in this array at all. `'SavedModifyDisplay'` (with an extra `d` — "Save**d**ModifyDisplay") is present, but the real action/method name dispatched by the framework is `SaveModifyDisplay` (`action_SaveModifyDisplay`, `:381`) — the string comparison in `in_array()` never matches, so this entry is dead weight that protects nothing.

**Sink (`SaveModifyMapping`)** — `modules/Connectors/controller.php:613-676` (condensed):
```php
public function action_SaveModifyMapping()
{
    $mapping_sources = explode(',', $_REQUEST['mapping_sources']);
    $mapping_values  = explode(',', $_REQUEST['mapping_values']);
    // ... builds $source_modules_fields[$source_id][$module][$field] = $value from mapping_values ...
    foreach ($source_modules_fields as $id => $mapping_entry) {
        $source = SourceFactory::getSource($id);
        $mapping = $source->getMapping();
        $mapping['beans'] = $mapping_entry;                       // caller-supplied mapping REPLACES the existing one
        $dir = $source_entries[$id]['directory'];
        if (!preg_match('/^custom\//', $dir)) { $dir = 'custom/' . $dir; }
        if (!file_exists($dir)) { mkdir_recursive($dir); }
        write_array_to_file('mapping', $mapping, "{$dir}/mapping.php");   // :664 -- the sink
        $source->saveMappingHook($mapping);
    }
    ConnectorUtils::updateMetaDataFiles();
    ...
}
```
`$_REQUEST['mapping_sources']`/`$_REQUEST['mapping_values']` flow, unauthenticated by role, straight into the array that is `var_export()`-serialized to `custom/modules/Connectors/connectors/sources/<vendor>/<source>/mapping.php` — a file every user's connector merge/search/display logic for that source reads from thereafter.

**The defect, precisely**: `'SaveModifyMapping'` is missing from `$admin_actions`; `'SavedModifyDisplay'` is present but misspelled relative to the actual action name `SaveModifyDisplay`. Both are simple string-list maintenance bugs in an allow-list whose surrounding entries (`'ModifyMapping'`, `'ModifyDisplay'`, `'ModifyProperties'`, …) show the intent was clearly to cover the entire Connectors admin workflow, including the save step.

**Dynamic proof** — after a non-admin POST with `mapping_values=ext_rest_insideview:Accounts:name=vuln049marker_70d1c808`, reading the file directly from the app container shows:
```php
<?php
// created: 2026-09-28 20:45:59
$mapping = array (
  'beans' =>
  array (
    'Accounts' =>
    array (
      'name' => 'vuln049marker_70d1c808',
      'id' => 'id',
    ),
  ),
);
```
— a brand-new, non-admin-authored file at `custom/modules/Connectors/connectors/sources/ext/rest/insideview/mapping.php`.

## Why it is a vulnerability (reasoning)
Every neighboring Connectors admin workflow step (`ModifyMapping` to view the form, `SaveModifyMapping` to persist it) is meant to sit behind the same admin wall — that's the entire purpose of grouping them into `$admin_actions`. A save action that persists attacker-controlled data to an instance-wide PHP config file, read by every subsequent user's connector operations, is exactly the class of action the allow-list exists to protect; a typo or omission in a hand-maintained string list is not a deliberate design choice; it is proven to be an oversight by the fact that its sibling `ModifyMapping` (the *view* half of the same workflow) **is** correctly listed and gated. Leaving the *save* half open lets any authenticated user tamper with configuration that legitimate admin users trust and never expect a non-admin to influence.

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates one fresh non-admin user **U** (`create_user`).
2. **Control request** (proves the gate mechanism works and U is unprivileged), as **U**:
   ```
   POST /index.php?module=Connectors&action=ConnectorSettings
   ```
   → denied with `<p class="error">Warning: You do not have permission to access this module.</p>`.
3. **Attack request**, as the same **U**, with a same-host `Referer` (required — these action names start with `"Save"` and are covered by SuiteCRM's separate Referer-based CSRF guard, which is intact and orthogonal to this access-control defect):
   ```
   POST /index.php?module=Connectors&action=SaveModifyMapping
   Referer: http://localhost:33116/index.php?module=Connectors&action=ModifyMapping
   Content-Type: application/x-www-form-urlencoded

   mapping_sources=ext_rest_insideview&mapping_values=ext_rest_insideview:Accounts:name=vuln049marker_70d1c808&from_unit_test=1
   ```
   (full request in `request.http`)
4. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected terminal output ends with:
   ```
   [PROOF] decisive line: "array (\n  'beans' => \n  array (\n    'Accounts' => \n    array (\n      'name' => 'vuln049marker_70d1c808',\n      'id' => '"
   ==> VULN-049: CONFIRMED — non-admin wrote marker vuln049marker_70d1c808 into custom/.../insideview/mapping.php via SaveModifyMapping
   ```
5. **Observable proof** — `evidence/mapping_php_after.txt` (full file content via `docker compose exec app cat`); `evidence/02_bonus_SaveModifyDisplay_response.txt` shows the companion `SaveModifyDisplay` typo-gap also running with no denial page.

## Impact
A non-admin user can overwrite the field-mapping (and, via the companion `SaveModifyDisplay` gap, the display) configuration for any registered Connectors source — corrupting or repointing what every user's connector-merge/search UI shows for Accounts/Contacts/Opportunities/Leads from that source. `write_array_to_file()` emits `var_export()`-escaped PHP (confirmed: attacker strings are always quoted PHP scalars, never raw code), so **RCE is not achievable** through this path — the impact is integrity/availability of the Connectors feature, not code execution. Pairs with [VULN-013](../../vulns/VULN-013.md) (the `CallConnectorFunc` gap in the same `$admin_actions` array) to show the Connectors module's admin boundary is systemically under-maintained.

## Suggested fix
Fix the string list directly: correct `'SavedModifyDisplay'` to `'SaveModifyDisplay'` and add `'SaveModifyMapping'`, then add a unit test that asserts every `action_*` method name whose action semantically requires admin rights is present verbatim in `$admin_actions` (a simple reflection-based test would have caught both bugs). More robustly, replace the hand-maintained denylist-of-admin-actions with a controller-wide `is_admin()` gate in `process()` plus a short, explicit allow-list of the few actions non-admins genuinely need — a typo in an allow-list fails open today; a typo in a short allow-list of *permitted* actions fails closed.

## References
- CWE-285 — Improper Authorization; CWE-863 — Incorrect Authorization.
- GHSA-mfj5-37v4-vh5w — "Authenticated RCE using connectors" (same Connectors subsystem; this specific gap does not itself reach RCE, per the `var_export()` analysis above).
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-02 (Testing for Bypassing Authorization Schema).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM Connectors "SaveModifyMapping" OR "SaveModifyDisplay" OR "SavedModifyDisplay" admin_actions non-admin` — only community/marketplace threads about "There is no action by that name" when saving mappings; no advisory
2. `SuiteCRM Connectors module missing authorization non-admin write mapping.php CVE advisory` — KIS-2016-04 (SugarCRM 6.5.18 Connectors `RunTest` missing admin check), CVE-2024-36414 (connectors file verification SSRF), CVE-2024-36418 (connectors RCE), CVE-2022-0755/0756 (missing authorization <7.12.5, component unpublished), CVE-2026-108712 (DetailUserRole); none name SaveModifyMapping/SaveModifyDisplay
3. Fetched github.com/salesagility/SuiteCRM/security/advisories/GHSA-mfj5-37v4-vh5w (CVE-2024-36418) — "Vulnerability in connectors allows authenticated user to do RCE attack", CWE-22, fixed 7.14.4/8.6.1; names no action, function, parameter or the `$admin_actions` list
4. `CVE-2024-36418 SuiteCRM connectors remote code execution description GHSA` and `... SourceFactory path traversal non-admin action RunTest SaveModifyProperties details` — no public technical detail beyond CWE-22
5. `CVE-2022-0755 CVE-2022-0756 SuiteCRM missing authorization huntr module component` — huntr CNA, fixed 7.12.5, component not published in any index
6. `"SuiteCRM through 7.15.2 and 8.10.2" missing authorization CVE-2026` (extended) + `haind03 hackmd SuiteCRM ...` — the only 7.15.2-era missing-authorization CVEs are CVE-2026-108712 (ACLRoles DetailUserRole) and CVE-2026-108713 (Campaigns setCampaignMarketingAndTemplate); neither is Connectors
7. Fetched seclists.org/fulldisclosure/2016/Jun/50 — Connectors `RunTest` only (that action is present in SuiteCRM's `$admin_actions`)

**Related but distinct public references** (same class or component, not this bug):
- KIS-2016-04 / Full Disclosure June 2016 — SugarCRM CE <= 6.5.18 Connectors controller `RunTest` missing admin check; same controller and same class, but a different action that SuiteCRM does gate
- CVE-2024-36418 / GHSA-mfj5-37v4-vh5w — authenticated RCE in connectors via path traversal (fixed 7.14.4); the public text does not describe which action was reachable or the `$admin_actions` typo/omission, and this finding is confirmed on 7.15.2 after that fix
- CVE-2022-0755 / CVE-2022-0756 — generic missing authorization prior to 7.12.5 (huntr), components not public
- CVE-2026-108712 / CVE-2026-108713 — missing authorization in other modules on 7.15.2 (same version, different components)

**Reasoning:** No public advisory names `SaveModifyMapping` as absent from `ConnectorsController::$admin_actions`, or the `SavedModifyDisplay` typo that leaves `SaveModifyDisplay` ungated. The Connectors controller has public history (2016 `RunTest`, 2024 RCE) and the 2024 RCE advisory's reachability details are unpublished, so it is possible that advisory relied on one of these ungated actions; this lowers confidence, but the specific authorization defect remains live on 7.15.2 and is not described anywhere public.
