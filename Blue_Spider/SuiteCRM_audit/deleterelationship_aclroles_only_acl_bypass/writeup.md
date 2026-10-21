# VULN-022 — `DeleteRelationship`: delete any relationship on any record (`aclroles`-only ACL copy-paste bug)

**ID**: VULN-022
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `forkedSuite`/hotfix snapshot)
**Severity**: High — **CVSS 3.1: 7.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — a fresh, unprivileged account is sufficient; no ownership, role, or Security-Group membership on either record is needed.
**What an attacker gains**: the ability to sever any relationship (related records, team/security-group memberships, campaign-list links, …) between any two records in the instance, regardless of who owns them.

## Summary
`include/generic/DeleteRelationship.php` is the single generic handler behind every "remove related record" action in SuiteCRM's UI. Its only ACL check exists in two duplicated copies — and both copies are wrapped in `if ($linked_field === 'aclroles')`, so for every relationship type *other than* `aclroles` (i.e. essentially all of them — Accounts↔Contacts, Accounts↔Opportunities, Team memberships, Campaign-list membership, …) no authorization check runs at all before the relationship row is deleted.

## How it works (mechanism & code trace)

**Entry point / routing** — `include/MVC/Controller/action_file_map.php:44`:
```php
$action_file_map['deleterelationship'] = 'include/generic/DeleteRelationship.php';
```
Like `SubPanelViewer` ([VULN-024](../../vulns/VULN-024.md)) and `Save2` ([VULN-023](../../vulns/VULN-023.md)), this bypasses the target module's own controller (`AccountsController`, etc.) entirely — no module-specific `pre_action`/ACL hook ever runs.

**The copy-paste bug** — `include/generic/DeleteRelationship.php:74-84`:
```php
if ($linked_field === 'aclroles') {
    if (!ACLController::checkAccess($bean_name, 'edit', true)) {
        ACLController::displayNoAccess();
        sugar_cleanup(true);
    }
} if ($linked_field === 'aclroles') {          // <-- the SAME condition, duplicated
    if (!ACLController::checkAccess($bean_name, 'edit', true)) {
        ACLController::displayNoAccess();
        sugar_cleanup(true);
    }
}

$focus->retrieve($record);                      // :86 -- no ACL
...
$focus->$linked_field->delete($record, $linked_id);   // :96 -- the sink, reached for ANY $linked_field != 'aclroles'
```
Both copies test the exact same condition — clear evidence this was meant to be (at minimum) an unconditional check, or a check for a different, broader condition, and a copy-paste left it testing the same narrow special case twice.

**The defect, precisely**: `$linked_field` is only ever `'aclroles'` when deleting a *role* assignment; for the overwhelmingly common case — detaching a Contact from an Account, removing a user from a Team, dropping a record from a Campaign list — `$linked_field` is `'contacts'`, `'accounts'`, `'campaign_contacts'`, etc., and the `if` never fires. `$focus->retrieve($record)` (loading the parent bean) performs no ACL check of its own, and `$focus->$linked_field->delete($record, $linked_id)` (the actual relationship-table `DELETE`) is a bare structural operation with no authorization gate.

**Dynamic proof** — attacker A, with zero ownership/ACL/Security-Group relation to victim V's Account or Contact, sent a single GET to `action=DeleteRelationship` with `linked_field=contacts`, and the `accounts_contacts` join-table row V created flipped from `deleted=0` to `deleted=1` — confirmed by direct database query before and after the request.

## Why it is a vulnerability (reasoning)
SuiteCRM's authorization model is meant to require an `edit`-level ACL check (at minimum) before any state-changing operation on a record's relationships — exactly what the (broken) `aclroles` branch demonstrates was *intended* to happen generally. A relationship is shared state between two records; deleting one is an edit-equivalent operation on both, yet the code path that performs it never asks "is the caller allowed to edit this?" for the relationship types that make up the vast majority of real-world usage. This is not an intentional "anyone may unlink related records" feature — no UI surface, documentation, or comment suggests that, and the exact same authorization primitive (`ACLController::checkAccess($bean_name, 'edit', true)`) is available and used one condition away; it simply never executes for `$linked_field != 'aclroles'`.

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates victim **V** and attacker **A** (`create_user`, no relationship between them). As **V**, create an Account and a Contact related to it (`account_id` set on the Contact save) — both owned by V.
2. **Attack request**, as **A**, zero relation to either record (full request in `request.http`):
   ```
   GET /index.php?module=Accounts&action=DeleteRelationship&record=<V's account>&linked_field=contacts&linked_id=<V's contact>&refresh_page=1
   Cookie: PHPSESSID=<attacker session>
   Referer: http://localhost:33116/index.php?module=Accounts&action=DetailView&record=<V's account>
   ```
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected terminal output ends with:
   ```
   [PROOF] accounts_contacts row AFTER attack: '...\t1\t2026-09-28 20:47:52'
   ==> VULN-022: CONFIRMED — non-owner A deleted V's accounts_contacts relationship ... via DeleteRelationship, no ACL check
   ```
4. **Observable proof** — `evidence/db_before_after.txt` records the `accounts_contacts.deleted` column flipping `0 → 1` for the exact relationship row V's real UI-equivalent actions created, timestamped to the attacker's own request — a genuine database-level side effect, not merely an HTTP 200.

## Impact
Any authenticated user, however unprivileged, can:
- Detach Contacts/Opportunities/Documents/etc. from Accounts (and the reverse) they have no rights to.
- Remove users from Teams or records from Security Groups where the relationship is represented the same generic way, altering row-level visibility for other users.
- Strip records from Campaign target lists, disrupting marketing/campaign operations.

Confidentiality impact is limited to confirming a relationship's existence (`C:L`); integrity impact is high and broad (`I:H`) — an attacker who can enumerate or guess `record`/`linked_id` GUIDs (via [VULN-001](../../vulns/VULN-001.md) or [VULN-024](../../vulns/VULN-024.md)) can systematically sever relationship data across the entire instance. Pairs directly with [VULN-023](../../vulns/VULN-023.md) (the same missing-ACL defect on the *add*/create side of relationships, in `Save2.php`).

## Suggested fix
Apply the `ACLController::checkAccess($bean_name, 'edit', true)` check **unconditionally** (not only when `$linked_field === 'aclroles'`), immediately after `$focus->retrieve($record)`, and verify `$focus->ACLAccess('edit')` on the loaded parent bean itself (covering owner/Security-Group-aware ACL implementations, not just the role-based check). Remove the duplicated dead branch entirely rather than leaving two copies of the same narrow condition.

## References
- CWE-284 — Improper Access Control; CWE-639 — Authorization Bypass Through User-Controlled Key.
- CVE-2024-45392 class (deletion-permissions in this same generic-relationship-delete family, per stage-07 known-issue cross-check).
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (Testing for Insecure Direct Object References).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM DeleteRelationship.php missing access control linked_field vulnerability` — nothing naming the file's ACL gap; only CVE-2024-45392 (API record deletion, fixed 7.14.5) and CVE-2020-8802.
2. `SuiteCRM "DeleteRelationship" CVE OR advisory OR GHSA` — only CVE-2024-50332 / GHSA-53xh-mjmq-j35p (blind SQL injection in `DeleteRelationShip`, fixed 7.14.6) and CVE-2024-45392.
3. `SuiteCRM improper access control relate records relationship any user CVE 2026 subpanel` — CVE-2026-29189, CVE-2026-32697, CVE-2026-108712, CVE-2025-64490; all different components.
4. GitHub repo advisory API for the 7.15.1/7.15.2 relationship-ACL advisories: `GHSA-m6x8-3hxp-qxwv` (CVE-2026-29189, REST API V8 relationships), `GHSA-qmh9-m7g7-pxxp` (CVE-2026-61650, V8 relationship creation), `GHSA-6jf7-hh5p-8fcm` (CVE-2026-100360, V8 relationship delete) — every one is the `/Api/V8/module/.../relationships` API, not `include/generic/DeleteRelationship.php`.
5. GitHub issue search `repo:SuiteCRM/SuiteCRM DeleteRelationship ACL check` — 0 results.
6. Upstream `hotfix` branch `include/generic/DeleteRelationship.php` (2026-10-21): the duplicated `if ($linked_field === 'aclroles')` guards at :74/:79 and the ungated `->delete()` at :96 are unchanged. NVD keyword query for SuiteCRM CVEs 2026-04-01..2026-10-21 — no match.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-50332 / GHSA-53xh-mjmq-j35p — same file, but SQL injection (CWE-89) rather than the missing authorization check.
- GHSA-6jf7-hh5p-8fcm / CVE-2026-100360 — same impact (delete a relationship without authorization on the related record) but in the V8 REST API handler.
- GHSA-m6x8-3hxp-qxwv / CVE-2026-29189 — V8 REST relationship endpoints missing ACL checks.
- CVE-2024-45392 / GHSA-8qfx-h7pm-2587 — record deletion via API with insufficient access control.

**Reasoning:** The legacy UI handler `include/generic/DeleteRelationship.php` has one published advisory (SQLi) and none describing its `aclroles`-only authorization check; all 2026 relationship-authorization advisories are confined to the V8 REST API and the vendor left the legacy handler unchanged while patching those. The component and root cause here are therefore judged undisclosed. Confidence is 70 rather than higher because relationship-ACL bypasses are a very active class in this project and the V8 fixes show the vendor has been receiving many reports in the area.
