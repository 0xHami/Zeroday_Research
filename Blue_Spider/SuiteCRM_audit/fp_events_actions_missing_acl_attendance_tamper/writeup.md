# VULN-030 — `FP_events`: systemic missing ACL on event actions (attendance tamper / email harvest / mass invite)

**ID**: VULN-030
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `forkedSuite`/hotfix snapshot)
**Severity**: Medium — **CVSS 3.1: 5.4** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — a fresh, unprivileged account is sufficient; no organiser/owner/delegate relationship to the event is needed.
**What an attacker gains**: the ability to tamper with any event's attendance/invite/accept status, add records to any event's delegate list, and (via `sendinvitemails`) mass-email an event's delegate roster using the system mailer — all on events the attacker has no ownership of.

## Summary
Every action method in `FP_eventsController` (`markasinvited`, `markasattended`, `markasnotattended`, `markasnotinvited`, `markasaccepted`, `markasdeclined`, `add_to_list`, `sendinvitemails`) operates on an event identified purely by a request-supplied `event_id`/`record`, with no access-control check of any kind. This report dynamically confirms `action_markasattended`; the remaining seven share the identical missing-check pattern (same controller, same `$db->query()`-on-request-id shape), confirmed by source review.

## How it works (mechanism & code trace)

**Entry point** — `index.php?module=FP_events&action=markasattended`, routed to `FP_eventsController::action_markasattended()` by the standard MVC dispatch.

**Sink** — `modules/FP_events/controller.php:84-101`:
```php
public function action_markasattended()
{
    $db = DBManagerFactory::getInstance();
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
            // (identical UPDATEs repeated for the Leads and Prospects/Targets join tables)
        }
    } elseif ($entire_list == '1') {
        // same UPDATE with no contact filter -- flips EVERY delegate on the event
    }
}
```
`$eventIDQuoted`/`$contact` are `$db->quote()`'d, so injection is not the issue (matching the finding's own framing); the issue is that **nothing above this code checks who is allowed to run it**. `FP_eventsController extends SugarController` but never overrides `process()` to add a gate, and none of the eight `action_*` methods loads the `FP_events` bean and calls `ACLAccess()`/`checkAccess()`/compares `assigned_user_id` before touching the database.

**The defect, precisely**: the missing line is, conceptually, `$event = BeanFactory::getBean('FP_events', $_POST['event_id']); if (!$event->ACLAccess('edit')) { ACLController::displayNoAccess(); return; }` before the `UPDATE`s — present nowhere in any of the eight actions.

**Dynamic proof** — attacker A, who is not the event's organiser and has never been added as a delegate, sent a single POST naming victim V's event and delegate contact, and the database shows:
```
fp_events_contacts_c.invite_status BEFORE: Not Invited   (the schema default, from the legitimate Save2 relate)
fp_events_contacts_c.invite_status AFTER:  Attended       (attacker A's forged check-in state)
```

## Why it is a vulnerability (reasoning)
Attendance/invite state on an event is exactly the kind of record-scoped data SuiteCRM's ACL model exists to protect — it reflects real-world facts (who showed up, who accepted) that only the event's organiser (or an admin) should be able to assert. Every other state-changing view in the product funnels through `ACLAccess()`-checked `EditView`/`Save`/`massupdate` paths; `FP_eventsController`'s bespoke `action_*` methods go straight to `$db->query()` instead, skipping that machinery entirely. There is no product documentation or UI affordance suggesting arbitrary users may mark other organisers' events as attended — this is a straightforward oversight in a module that reimplements its own persistence layer instead of using the bean/ACL-aware save path.

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates organiser **V** and attacker **A** (`create_user`, no relationship). As **V**, create an `FP_events` event and a Contact, then relate the Contact to the event via the legitimate `Save2` flow (creates the delegate row with `invite_status='Not Invited'`).
2. **Attack request**, as **A** (full request in `request.http`):
   ```
   POST /index.php?module=FP_events&action=markasattended
   Cookie: PHPSESSID=<attacker session>
   Referer: http://localhost:33116/index.php?module=FP_events&action=DetailView&record=<event_id>
   Content-Type: application/x-www-form-urlencoded

   event_id=<V's event>&id=<delegate contact id>&entire_list=0
   ```
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected terminal output ends with:
   ```
   [PROOF] invite_status AFTER attack: 'Attended'
   ==> VULN-030: CONFIRMED — non-owner A tampered attendance on V's FP_events event ..., invite_status Not Invited->Attended
   ```
4. **Observable proof** — `evidence/db_before_after.txt` records the `fp_events_contacts_c.invite_status` transition, queried directly from the database before and after the single attacker request.

## Impact
Any authenticated user, however unprivileged, can, for any event GUID they can name or enumerate:
- **Integrity** — flip invite/accept/attendance status for any/all delegates on any event (`markasinvited`/`markasattended`/`markasnotattended`/`markasnotinvited`/`markasaccepted`/`markasdeclined`), corrupting the organiser's records of who actually attended.
- **Confidentiality** — harvest delegate names/e-mail addresses via `action_sendinvitemails` (`:359-…`), which additionally loads the invite `EmailTemplates` with `disable_row_level_security = true`, bypassing row-level restrictions on template selection too.
- **Availability/reputation** — trigger `sendinvitemails` to blast the organisation's Contacts/Leads/Targets with real outbound e-mail via the system mailer, producing spam/backscatter attributable to the CRM instance, for any event the attacker can name.
- **Data at risk** — every `FP_events` record and its related Contacts/Leads/Targets in the instance.

This shares its missing-per-record-ACL root cause with the broader cluster in [VULN-035](../../vulns/VULN-035.md); the CSRF-normalization angle affecting these same POST-driven `markas*` actions is tracked separately as VULN-088.

## Suggested fix
Add a per-record ACL check to every `FP_eventsController` action, before any database write:
```php
$event = BeanFactory::getBean('FP_events', $_POST['event_id']);
if (empty($event->id) || !$event->ACLAccess('edit')) {
    ACLController::displayNoAccess();
    return;
}
```
(`ACLAccess('view')` for the read-oriented actions.) Add CSRF-token validation to all eight state-changing actions. Do not load the invite `EmailTemplates` with `disable_row_level_security` for a non-admin caller in `sendinvitemails`.

## References
- CWE-285 — Improper Access Control.
- Related component advisories: GHSA-2g8f-gjrr-x5cg (Alerts), GHSA-jh8v-wqgj-hhc2 (Project/Resource-Calendar) — same broken-object-level-authorization class in sibling SuiteCRM modules; no FP_events-specific advisory found.
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (Testing for Insecure Direct Object References).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM FP_events markasattended OR markasinvited OR sendinvitemails vulnerability access control` — only CVE-2024-36412 (unauthenticated SQLi in the events *response* entry point) and CVE-2025-54784 (email viewer XSS); no advisory names the `markas*`/`sendinvitemails` actions
2. `SuiteCRM FP_events CVE events module authorization bypass` — CVE-2025-64490 (Resource Calendar), CVE-2026-108713 (setCampaignMarketingAndTemplate), CVE-2026-108712 (DetailUserRole); none mention FP_events
3. `SuiteCRM Events module invite status tamper missing ACL controller.php FP_events advisory 2025 2026` (extended) — docs, 2016 feature requests (#1704/#1706, PR #1085) about narrowing delegate-edit rights; no vulnerability report
4. Reviewed all 8 pages of github.com/SuiteCRM/SuiteCRM/security/advisories (77 advisories, 2024-06 to 2026-10) — no FP_events access-control advisory

**Related but distinct public references** (same class or component, not this bug):
- GHSA-xjx2-38hv-5hh8 / CVE-2024-36412 — unauthenticated SQL injection in the FP_events `responseEntryPoint` (accept/decline link); same module, but a SQLi in a different entry point, fixed 7.14.4
- GHSA-jh8v-wqgj-hhc2 / CVE-2025-64490 — role-level bypass in Projects/Resource Calendar; same broken-authorization class, different module
- GitHub issue #1706 (2016) — feature request to "narrow user rights for editing delegates"; a wish-list item, not a security report

**Reasoning:** No public disclosure describes the missing per-record ACL in `FP_eventsController`'s `action_markas*`/`add_to_list`/`sendinvitemails` methods. The only public FP_events advisory is a SQL injection in the unauthenticated response entry point, which is a different sink and root cause. Missing-authorization bugs are extremely common in SuiteCRM and several advisories are worded at module level only, so an undisclosed or vaguely described report could exist.
