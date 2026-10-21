# VULN-028 — SavedSearch: read / delete / hijack any user's saved search (IDOR)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:22Z

## Preconditions
- Admin creates victim **V** and attacker **A** (fresh, unrelated low-priv users, `create_user`).
- As **V**: `module=SavedSearch&action=index&saved_search_action=save&search_module=Accounts&saved_search_name=<rand>&searchFormTab=basic_search&name_basic=<marker>` — saves a private search on Accounts with a unique name and a unique `name_basic` filter value. Response is a 301 redirect containing `saved_search_select=<new id>` — this is the victim's SavedSearch GUID (in a real attack, obtained via GUID enumeration/leakage per [VULN-001], not handed to the attacker; here the harness observes it because it is the same script driving both roles).

## Request
See `request.http` (both the READ and DELETE requests). Summary:
```
# READ
GET /index.php?module=SavedSearch&action=index&saved_search_select=<victim_ss_id>&search_module=Accounts
Cookie: PHPSESSID=<attacker session>

# DELETE
GET /index.php?module=SavedSearch&action=index&saved_search_action=delete&saved_search_select=<victim_ss_id>&search_module=Accounts
Cookie: PHPSESSID=<attacker session>
```

## Response
See `response.txt`. READ: attacker's Accounts ListView response (after the SavedSearch redirect chain) contains both the victim's `saved_search_name` (echoed in `saved_search_select_name=` on the final redirected URL and in the page body) and the victim's unique `name_basic` filter marker (pre-filled into the search form) — i.e. the victim's private search criteria rendered into the *attacker's own* browsing session. DELETE: 301 redirect (success path), and the `db` container confirms the row's `deleted` column flipped `0 → 1`.

## Observation
Matches the static finding: `modules/SavedSearch/index.php:47-84` dispatches `update`/`save`/`delete`/plain-read purely on `$_REQUEST['saved_search_action']` + `$_REQUEST['saved_search_select']`, with **no** comparison against `current_user->id` anywhere in the dispatch or in `retrieveSavedSearch()` (`SavedSearch.php:493`, a bare `parent::retrieve($id)`) or `handleDelete()` (`SavedSearch.php:336`, a bare `$this->mark_deleted($id)`). The owner filter the module *does* have (`assigned_user_id = current_user` in the listing query, `SavedSearch.php:~97-102`) only shapes the dropdown UI — it is never consulted by the by-id operations, exactly as the finding describes ("illusion of user-partitioning").

One incidental observation: the `assigned_user_id` column on the saved row reads empty in our DB check (see `db state after attacker delete` in run.log) rather than the victim's GUID, even though `handleSave()` sets `$focus->assigned_user_id = $current_user->id` (`SavedSearch.php:~421`) on the save path. This does not affect the finding — the by-id READ/DELETE paths never consult this column regardless of its value, which is the entire point of the vulnerability — but is noted for completeness; it may be an artifact of driving `save` via a bare GET-style dispatch rather than the JS-driven form SuiteCRM's own UI uses.

## Side effects
- One `saved_search` row created by V, then `mark_deleted` (soft-deleted, `deleted=1`) by A. Verified via:
  `docker compose -p cvehunterlab_suitecrm exec -T db mysql -uroot -pSuiteRoot!2026x suitecrm -e "SELECT id,name,assigned_user_id,deleted FROM saved_search WHERE id='<id>';"`
  → `deleted=1` after the attacker's unauthenticated-by-ownership delete call. See `evidence/db_before_after.txt`.
- Two new low-priv Users created (random-suffixed, harmless, non-destructive).

## Research & references
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References.

## If FAILED
N/A — CONFIRMED.
