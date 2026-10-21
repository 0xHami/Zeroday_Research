# VULN-050 — `targetlistupdate`: cross-ACL add-to-list (uids branch), CSRF-able

## 1. Header
- **Title**: ProspectList `targetlistupdate` `uids` branch bypasses record-level ACL; action is CSRF-able
- **ID**: VULN-050
- **Software**: SuiteCRM — **Repository**: https://github.com/SuiteCRM/SuiteCRM — **Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — **Commit**: `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
- **Severity**: Medium — **CVSS 3.1**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (5.4)
- **Status**: `CONFIRMED (dynamic)`
- **Auth required**: Any authenticated user (low privilege is sufficient — no special Role/ACL needed to *trigger* the bug; only the standard "log in" boundary); also CSRF-deliverable against any authenticated victim, including higher-privileged ones, with zero user interaction beyond loading an attacker page.
- **What an attacker gains**: the ability to associate arbitrary records from *any module that relates to ProspectLists* (Accounts/Contacts/Leads/Prospects/…) — including ones the caller has **no ACL visibility into at all** — with a list the caller controls, and to do so cross-site via a forged victim request.

## 2. Summary
`modules/ProspectLists/TargetListUpdate.php` powers the "Add to Target List" bulk action available from any related module's list view. It has two branches for selecting which records to add: `select_entire_list=1` (search-based, filtered through `buildAccessWhere('list')`) and the ordinary `uids` branch, which is what fires for a normal "select these rows, add to list" click. The `uids` branch trusts the attacker-supplied id list outright — it never applies an access filter, and the `retrieve()`/`add()` calls that follow perform no ACL, ownership, or SecurityGroup check either. Any authenticated user can therefore force *any* record id (guessed, enumerated, or leaked from elsewhere) into a ProspectList they own, even records they are explicitly denied `view` access to. Because the action name (`targetlistupdate`) and module (e.g. `Contacts`) are absent from SuiteCRM's hand-maintained CSRF allowlists, the request is also fully CSRF-reachable with zero token or Referer challenge.

## 3. How it works (mechanism & code trace)
**Entry point**: `POST /index.php?module=Contacts&action=targetlistupdate` (module can be any bean that relates to `ProspectLists` — Accounts/Contacts/Leads/Prospects) is routed by the classic MVC front controller straight to the standalone script `modules/ProspectLists/TargetListUpdate.php` (no `view.php`/dedicated controller class — the file itself *is* the handler).

Step 1 — branch selection, `TargetListUpdate.php:58-80`:
```php
$uids = array();
if ($_REQUEST['select_entire_list'] == '1') {
    ...
    $accessWhere = $focus->buildAccessWhere('list');        // :67  ACL filter -- ONLY this branch
    if (!empty($accessWhere)) { $ret_array['where'] .= ... $accessWhere; }
    ...
} else {
    $uids = explode(',', $_POST['uids']);                   // :79  raw attacker input, no filter
}
```
The `select_entire_list` branch is the only one that ever calls `buildAccessWhere()`. The ordinary `uids` branch — what the UI actually submits for a normal multi-select "add to list" — is a bare `explode()` of client-supplied text.

Step 2 — no per-id check, `:93-107`:
```php
if (!empty($relationship)) {
    foreach ($uids as $id) {
        $focus->retrieve($id);                               // :95  retrieve() performs no ACL
        ...
        $focus->load_relationship($relationship);
        $focus->$relationship->add($_REQUEST['prospect_list']); // :104  relate, no owner/ACL check
    }
}
handleRedirect();                                             // :109  redirect only, no ACL-rendered view
```
`SugarBean::retrieve()` loads a row by id unconditionally (it is a data-access primitive, not an authorization primitive — the codebase's ACL model expects *callers* to gate access, e.g. via `buildAccessWhere()` or an explicit `ACLAccess()` call, neither of which is present here). `$relationship->add()` then unconditionally inserts the join row.

**The exact defect**: the branch guarding the `uids` path is missing the same one line the `select_entire_list` branch has — an ACL/access-where filter applied to every `$id` before it is retrieved and related. There is no `ACLAccess('view')` check on `$focus` after `retrieve()`, no owner check, no SecurityGroup check.

**CSRF**: `include/MVC/SugarApplication.php:502-523`'s `isModifyAction()` returns `true` only if the action starts with `save`/`delete`, or the module is in `$modifyModules` (`:486-500`, which lists `Administration`, `Studio`, `Emails`, … and `Contacts` is not among them), or the action is in `$globalModifyActions` (`:478-481`, `massupdate/configuredashlet/import/importvcardsave/inlinefieldsave/wlsave/quicksave` — `targetlistupdate` is not among them). Since none apply, `isModifyAction()` returns `false`, so `checkHTTPReferer()`'s empty-Referer branch (`:553`, `$strong && empty($_SERVER['HTTP_REFERER']) && ... && $this->isModifyAction()`) never triggers — the request proceeds with **zero** Referer.

**Why the framework doesn't save it**: SuiteCRM's only cross-cutting authorization net for classic-MVC actions is the referer-based CSRF gate (keyed off a hand-maintained action/module allowlist, not the HTTP method) plus whatever the individual action author remembered to call. `TargetListUpdate.php` is a bare procedural script outside the `SugarController`/ACL-aware view hierarchy that most modules use, so neither net catches it.

## 4. Why it is a vulnerability (reasoning)
The trust boundary being violated is: *a user's ACL/SecurityGroup restriction on a module must hold regardless of which code path touches a record of that module.* SuiteCRM enforces this boundary for normal list/search/select-entire-list flows (`buildAccessWhere`) and for direct record views (`ACLAccess`), but the `uids` add-to-list path — which is the *default*, most commonly used path (a user ticks specific rows and clicks "Add to Target List") — enforces nothing. This is not a deliberate design choice: the sibling branch two lines above demonstrates the framework *intends* an access filter here; it was simply never applied to the more common branch. A skeptic can verify this is not "by design" by noting the asymmetry itself — if omitting the ACL filter on `uids` were intentional, the `select_entire_list` branch's `buildAccessWhere()` call would be redundant/inconsistent product behavior (list additions ACL'd only when you use "select all," not when you pick individual rows makes no coherent security argument).

## 5. Reproduction
Preconditions, from a clean lab (`http://localhost:33116`):
1. Admin creates low-priv user `L` (`Users&action=Save`, `is_admin=0`).
2. Admin assigns `L` a throwaway Role denying `Contacts` `view`+`list` (`ACL_ALLOW_NONE`) — models a real deployment where `L` cannot see certain records; without a restrictive Role, a fresh SuiteCRM install defaults every module's ACL to "allow all" for every authenticated user, which would make the bypass invisible (not because it isn't there, but because nothing was denied to begin with).
3. Admin creates Contacts `C1`, `C2` (`assigned_user_id=admin`).
4. `L` creates ProspectList `PL` (owned by `L`).

Exact requests (see `request.http` / full detail in `automation.py`):
```
POST /index.php?module=Contacts&action=targetlistupdate HTTP/1.1
Cookie: PHPSESSID=<L's session>
Referer: http://localhost:33116/index.php?module=Contacts&action=index
Content-Type: application/x-www-form-urlencoded

uids=<C1>&prospect_list=<PL>
```
```
POST /index.php?module=Contacts&action=targetlistupdate HTTP/1.1
Cookie: PHPSESSID=<L's session>
Content-Type: application/x-www-form-urlencoded
(no Referer header at all)

uids=<C2>&prospect_list=<PL>
```
Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log` — expect `[OK]` then `==> VULN-050: CONFIRMED …`.
Observable proof: `run.log` shows `L`'s baseline `DetailView(C1)` does **not** reveal the Contact's
name (ACL correctly blocks normal viewing), yet
`SELECT related_id,related_type FROM prospect_lists_prospects WHERE prospect_list_id='<PL>'`
returns both `C1` and `C2` with `related_type='Contacts'`, `deleted=0` — including the one added
with zero Referer header. Full transcript in `run.log`; DB snapshot in `evidence/db_rows.txt`.

## 6. Impact
An attacker with only a login (any Role) can force arbitrary, otherwise-invisible-to-them
records into a list they control — a cross-ACL data-integrity/membership-tampering primitive that
also functions as a record-existence oracle (association succeeding confirms the id exists). Via
CSRF, an attacker-controlled page can perform this against **any logged-in victim**, including an
administrator, with no interaction beyond a page visit — polluting or manipulating marketing/target
list membership on the victim's behalf. Chains with [VULN-051](../../vulns/VULN-051.md) (same
root cause in `jjwg_Maps`) and the read-IDOR cluster ([VULN-001](../../vulns/VULN-001.md),
[VULN-024](../../vulns/VULN-024.md)) for id harvesting.

## 7. Suggested fix
In `TargetListUpdate.php`, apply the same access filter to the `uids` branch that the
`select_entire_list` branch already uses — either `buildAccessWhere('list')` pre-filtering the
`$uids` array, or (preferably, since `uids` are already concrete ids) an explicit
`$focus->ACLAccess('view')` check per id after `retrieve()`, skipping/erroring on denial:
```php
foreach ($uids as $id) {
    $focus->retrieve($id);
    if (empty($focus->id) || !$focus->ACLAccess('view')) {
        continue; // or log + error, per product decision
    }
    ...
}
```
Then add a per-request CSRF (synchronizer) token to the "Add to Target List" form/action and
validate it server-side — do not rely solely on the action-name-keyed Referer allowlist, which is
denylist-shaped and easy to miss for new/refactored actions (allowlist-by-default is the
principle: require an explicit "this is safe to skip" annotation instead of "this is an action we
remembered to guard").

## 8. References
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- OWASP Cross-Site Request Forgery Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger — CSRF where Referer validation depends on a header being present: https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses
- Adjacent SuiteCRM CSRF class: CVE-2023-3627 / GHSA-qg9r-8vq4-2gp4 (same referer-allowlist root cause, different action).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM targetlistupdate OR TargetListUpdate "add to target list" ACL bypass CSRF vulnerability` — CVE-2020-8803 / KIS-2020-04 (`add_to_prospect_list` LFI), CVE-2021-41597 (UpgradeWizard CSRF), CVE-2025-64490, CVE-2026-29189; none name `targetlistupdate`
2. `SuiteCRM ProspectLists target list add records without permission IDOR prospect_lists_prospects advisory` — only CVE-2020-8803 again and community threads; no IDOR/ACL advisory for list membership
3. Fetched github.com/advisories/GHSA-qg9r-8vq4-2gp4 (CVE-2023-3627) — CSRF in `salesagility/suitecrm-core` prior to 8.3.1 (SuiteCRM 8 Angular front end); no component named, not the 7.x `TargetListUpdate.php` script
4. `"SuiteCRM through 7.15.2 and 8.10.2" missing authorization CVE-2026` (extended) — only CVE-2026-108712 (DetailUserRole) and CVE-2026-108713 (setCampaignMarketingAndTemplate) target 7.15.2; neither concerns ProspectLists
5. `SuiteCRM jjwg_Maps add_to_target_list vulnerability ACL target list` — same results (CVE-2020-8803, CVE-2026-29189); nothing on target-list membership ACL

**Related but distinct public references** (same class or component, not this bug):
- CVE-2020-8803 / KIS-2020-04 — `add_to_prospect_list` (ProspectLists) local file inclusion via `parent_module`/`parent_type` (<= 7.11.11); same feature area, entirely different bug (LFI vs missing ACL on `uids`)
- CVE-2023-3627 / GHSA-qg9r-8vq4-2gp4 — CSRF in SuiteCRM 8 core (fixed 8.3.1); same referer-allow-list class, different code base/action
- CVE-2026-29189 — REST API V8 missing ACL checks (fixed 7.15.1); different interface
- CVE-2026-108713 — missing authorization on 7.15.2 in Campaigns `setCampaignMarketingAndTemplate`; same version and class, different component

**Reasoning:** No CVE, GHSA or advisory describes `modules/ProspectLists/TargetListUpdate.php` applying `buildAccessWhere()` only on the `select_entire_list` branch while the `uids` branch relates arbitrary ids without ACL, nor its absence from the referer-based CSRF allow-lists. Missing-ACL issues are common in SuiteCRM and third-party researchers are actively filing 7.15.2 CVEs of this class (Oct 2026), so a parallel report is plausible, but nothing public matches this component.
