# VULN-028 — SavedSearch: read / delete / hijack any user's saved search (IDOR)

**ID**: VULN-028
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1: 5.4** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — no special role.
**What an attacker gains**: read any other user's stored search criteria/column layout, and delete (or overwrite/re-own) it, purely by guessing or observing its GUID.

## Summary
SuiteCRM's SavedSearch module filters *by owner* only in the dropdown-listing query. Every other operation that takes a saved-search id from the request — reading it back, deleting it, or overwriting it — trusts that id with no ownership check at all. Any authenticated user who obtains another user's SavedSearch GUID can read, delete, or hijack it.

## How it works (mechanism & code trace)

**Entry point** — `modules/SavedSearch/index.php:47-84`:
```php
47: if (!empty($_REQUEST['saved_search_action'])) {
48:     $ss = BeanFactory::newBean('SavedSearch');
50:     switch ($_REQUEST['saved_search_action']) {
        case 'update': $ss->handleSave('', true, false, $_REQUEST['saved_search_select'], $savedSearchBean); break;
        case 'save':   $ss->handleSave('', true, false, null, $savedSearchBean); break;
60:     case 'delete': $ss->handleDelete($_REQUEST['saved_search_select']); break;
    }
63: } elseif (!empty($_REQUEST['saved_search_select'])) {
82:     $ss->returnSavedSearch($_REQUEST['saved_search_select'], $searchFormTab, $show);
```
The dispatcher reads `saved_search_select` straight from `$_REQUEST` for all four operations (read via `returnSavedSearch`, create via `save`, update via `update`, remove via `delete`). No `current_user` comparison anywhere in this file.

**Read sink** — `SavedSearch.php:493-497`:
```php
public function retrieveSavedSearch($id)
{
    parent::retrieve($id);
    $this->contents = unserialize(base64_decode($this->contents), ['allowed_classes' => false]);
}
```
A bare `retrieve()` by primary key. (The `allowed_classes => false` hardening rules out PHP object-injection — this is purely an authorization gap, not a deserialization one.)

**Delete sink** — `SavedSearch.php:336-338`:
```php
public function handleDelete($id)
{
    $this->mark_deleted($id);
    ...
```
Again, `$id` comes straight from the dispatcher's `$_REQUEST['saved_search_select']` with no ownership check.

**The one owner check that exists, and why it doesn't help** — the module's *listing* query (`SavedSearch.php:~97-102`) does add `WHERE ... assigned_user_id = '<current_user>'`, which is what makes the per-module "saved searches" dropdown show only your own — creating the appearance that SavedSearch records are already user-partitioned. But that WHERE clause is local to the listing SQL; `retrieveSavedSearch()`, `handleDelete()`, and the update branch of `handleSave()` never call it or anything equivalent. **The defect is precisely that the id-scoped operations don't share the listing query's filter.**

## Why it is a vulnerability (reasoning)
A SavedSearch record is inherently personal — it stores one user's filter criteria and list-view column layout, and the UI's own dropdown enforces "you only see your own." An attacker who can act on *any* id via the exact same dispatcher breaks that boundary entirely: nothing in the trust model says "SavedSearch ids, once known, are public" — quite the opposite, the listing filter demonstrates the developers' intent that they are private per-user objects. The correct invariant — "a caller may retrieve/mutate/delete a SavedSearch row only if `assigned_user_id == current_user->id` (or the caller is an admin)" — is enforced in exactly one of the four code paths that need it (the listing query) and is simply absent from the other three.

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates **V** and **A** (unrelated). As **V**, save a private search on Accounts with a unique name and a unique `name_basic` filter value; capture the resulting `saved_search_select` GUID from the `Location` redirect header.
2. **Attack requests**, as **A** (id known here only because the harness created it; in the wild it's obtained via GUID leakage/enumeration, e.g. [VULN-001]):
   ```
   GET /index.php?module=SavedSearch&action=index&saved_search_select=<victim_ss_id>&search_module=Accounts
   GET /index.php?module=SavedSearch&action=index&saved_search_action=delete&saved_search_select=<victim_ss_id>&search_module=Accounts
   ```
   (full requests in `request.http`)
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected tail:
   ```
   [PROOF] V's filter marker 'MARK028_...' reflected into A's own Accounts ListView: True
   [PROOF] V's saved_search_name 'V028SS_...' reflected: True
   [PROOF] db state after attacker delete: ... deleted=1
   ==> VULN-028: CONFIRMED — attacker read V's search name/criteria and mark_deleted() V's row (...) purely by id
   ```
4. **Observable proof** — `response.txt` shows the victim's search name and filter marker rendered into the attacker's own Accounts ListView page (READ), and the `db` container shows the victim's `saved_search` row's `deleted` column flip `0 → 1` after the attacker's delete-by-id call, with no ownership check anywhere in between.

## Impact
- **Confidentiality (horizontal)**: any user's stored search criteria and column layout — often revealing business logic such as pipeline filters, target-account lists, and deal-stage segmentation — can be read by any other authenticated user.
- **Integrity/availability (horizontal)**: any user's saved search can be deleted (disruptive: a colleague's daily working view vanishes) or, via the `update` action with the victim's id, overwritten and re-assigned to the attacker (`SavedSearch.php`'s `handleSave()` sets `assigned_user_id = current_user->id` unconditionally on save, so the update path also constitutes an ownership hijack, not exercised destructively here to keep the run non-destructive beyond the harness's own seeded row).
- No direct CRM-record exfiltration on this path — the impact is confined to the saved-search objects themselves, and the boundary crossed is strictly horizontal user-to-user, hence Medium rather than High.

## Suggested fix
Scope every by-id operation to the owner, mirroring the listing query's filter:
```php
public function retrieveSavedSearch($id)
{
    parent::retrieve($id);
    global $current_user;
    if ($this->assigned_user_id !== $current_user->id && !$current_user->isAdmin()) {
        $this->id = ''; // or throw / redirect to no-access
        return;
    }
    $this->contents = unserialize(base64_decode($this->contents), ['allowed_classes' => false]);
}
```
Apply the equivalent check at the top of `handleDelete($id)` and in the `update` branch of `handleSave()` before any read/mutate/delete proceeds. Principle: never let a listing-only filter stand in for record-level authorization on the corresponding by-id operations.

## References
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (IDOR).
- PortSwigger Web Security Academy — "Insecure direct object references."

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM SavedSearch saved_search_select IDOR delete other user saved search vulnerability` — no IDOR/ownership advisory; only CVE-2026-29109 (unsafe deserialization of `saved_search.contents`, SuiteCRM 8, admin-only) and CVE-2026-32697.
2. `SuiteCRM "SavedSearch" OR "saved search" IDOR OR "access control" huntr OR CVE assigned_user_id` — same two CVEs plus CVE-2026-29189 and CVE-2026-108712; nothing on `saved_search_select` or cross-user read/delete.
3. `huntr SuiteCRM IDOR report subpanel OR "saved search" OR workflow OR oauth token OR repair` — no huntr SavedSearch report; only aggregator pages for the 2026 CVEs above.
4. SuiteCRM 7.15.x release-notes security list + GitHub repo advisory titles (7.15.1, 7.15.2, 20 most recent) — no SavedSearch entry.
5. GitHub issue search `repo:SuiteCRM/SuiteCRM SavedSearch other user delete` — 0 results.
6. Upstream `hotfix` branch `modules/SavedSearch/{index.php,SavedSearch.php}` (2026-10-21): owner filter still exists only in the listing queries (:100, :220); `returnSavedSearch`, `handleDelete` and the `update` branch still take `saved_search_select` with no ownership comparison. NVD keyword query for SuiteCRM CVEs 2026-04-01..2026-10-21 — no match.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-29109 — same module (SavedSearch) but PHP object injection via `unserialize()` of `saved_search.contents` in SuiteCRM 8's FilterDefinitionProvider; not an authorization gap (and this code path uses `allowed_classes => false`).
- GHSA-m6x8-3hxp-qxwv / CVE-2026-29189 — any user reads other users' preferences via the V8 REST API (horizontal IDOR class, different component).
- CVE-2026-32697 — SuiteCRM 8 `RecordHandler::getRecord()` missing view ACL.

**Reasoning:** The only public SavedSearch advisory is a deserialization RCE with a different root cause, and no CVE, GHSA, issue, huntr report, or write-up describes reading, deleting, or re-owning another user's saved search by `saved_search_select` id; the by-id operations remain unscoped upstream today. The finding is judged undisclosed. Confidence is 80 given the horizontal-IDOR class is common in this project and a low-severity report could exist unindexed.
