# VULN-022 — `DeleteRelationship`: delete any relationship on any record (`aclroles`-only ACL copy-paste bug)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:47Z

## Preconditions
- `automation.py` creates two fresh, unrelated low-priv users via admin (`create_user`): victim **V** and attacker **A**.
- As **V**: creates an Account (`module=Accounts&action=Save`) and a Contact related to it via `account_id`/`account_name` (`module=Contacts&action=Save`) — both owned by V, using V's own real session (not DB seeding). A has no ACL grant, Security-Group membership, or relationship to either record.
- **Gotcha hit and fixed**: the first attempt sent no `Referer` and was rejected by SuiteCRM's own Referer-based XSRF guard (`"Possible Cross Site Request Forgery (XSRF) Attack Detected" ... Attempted action (DeleteRelationship)`) — this is a *different*, intact defense (not the access-control bug under test). Adding a same-host `Referer: .../module=Accounts&action=DetailView&record=<acct_id>` header resolved it, consistent with `TARGET_FACTS.md`'s guidance to always send a same-host Referer for modify actions.
- **Non-destructive discipline honored**: only the two just-created records/relationship are touched; no demo data is read or modified. `refresh_page=1` is passed to skip the trailing `handleRedirect()` (which would 302 to a return URL we don't need) — the delete itself still runs identically since that parameter only affects the post-delete redirect, not the delete logic (verified: `include/generic/DeleteRelationship.php:147` checks `refresh_page` only *after* the delete at `:96`).

## Request
See `request.http`. As **A** (zero relation to V's records):
```
GET /index.php?module=Accounts&action=DeleteRelationship&record=<V's account>&linked_field=contacts&linked_id=<V's contact>&refresh_page=1
Cookie: PHPSESSID=<attacker session>
Referer: http://localhost:33116/index.php?module=Accounts&action=DetailView&record=<V's account>
```

## Response
See `response.txt` — HTTP 200, `Content-Length: 0` (the file `exit;`s immediately after the delete when `refresh_page` is set, confirming the delete logic executed with no error).

## Observation
Matches the static finding exactly. `include/generic/DeleteRelationship.php:74-84` contains the file's only ACL check, duplicated, both copies gated behind `if ($linked_field === 'aclroles')`:
```php
if ($linked_field === 'aclroles') {
    if (!ACLController::checkAccess($bean_name, 'edit', true)) { ... }
} if ($linked_field === 'aclroles') {
    if (!ACLController::checkAccess($bean_name, 'edit', true)) { ... }
}
```
Our request used `linked_field=contacts` — neither `if` fires, so execution falls straight through to `:86` (`$focus->retrieve($record)`, no ACL) and `:96` (`$focus->$linked_field->delete($record, $linked_id)`), which is the real sink.

**DB proof of the real effect** (not just HTTP 200):
```sql
-- BEFORE the attacker's request:
SELECT id, deleted FROM accounts_contacts WHERE account_id='<acct_id>' AND contact_id='<contact_id>';
-- => b0b3d685-0134-4bf1-819e-832f667eda4f   0

-- AFTER:
SELECT id, deleted, date_modified FROM accounts_contacts WHERE id='b0b3d685-0134-4bf1-819e-832f667eda4f';
-- => b0b3d685-0134-4bf1-819e-832f667eda4f   1   2026-09-28 20:47:52
```
`deleted` flipped 0 → 1, `date_modified` updated to the moment of the attacker's request — the relationship row victim V created was torn down entirely by attacker A, who held no edit rights, no ownership, and no Security-Group overlap with either record.

## Side effects
Two new Users, one Account, one Contact created (random-suffixed, harmless) — all created by this run, and the only relationship touched is the one this run seeded. No demo/pre-existing data affected.

## Research & references
- CWE-284 (Improper Access Control) / CWE-639 (Authorization Bypass Through User-Controlled Key) — OWASP A01:2021-Broken Access Control.
- Same non-destructive dynamic-verification pattern as [VULN-024](VULN-024.md) (seed-your-own-records, verify via DB), applied here to a write/delete sink instead of a read sink.
