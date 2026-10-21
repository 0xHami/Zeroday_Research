# VULN-029 — Calendar shared view reads any user's Meetings/Calls/Tasks (IDOR)

**ID**: VULN-029
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1: 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Status**: CONFIRMED (dynamic) — via a corrected entry point; see "How it works" for the reproduction-path note.
**Auth required**: any authenticated user (`PR:L`) — no special role.
**What an attacker gains**: full read of any other user's Meetings, Calls, and Tasks (subject, description, time, invitees) without that user ever sharing their calendar.

## Summary
SuiteCRM's "shared calendar" feature lets a user view other users' calendars — but only after those users explicitly share. The server-side implementation never checks for that consent: it takes a list of target user ids straight from the request and returns their activities. Any authenticated user can view any other user's private Meetings/Calls/Tasks by supplying that user's GUID.

## How it works (mechanism & code trace)

**Entry point** — `modules/Calendar/index.php:68-79` (the Calendar module's main page controller):
```php
68: $cal = new Calendar($_REQUEST['view'], array(), $views);
70: if ($cal->view == "sharedMonth" || $cal->view == "sharedWeek") {
72:     $cal->init_shared();
73:     global $shared_user;
74:     $shared_user = BeanFactory::newBean('Users');
75:     foreach ($cal->shared_ids as $member) {
76:         $shared_user->retrieve($member);
77:         $cal->add_activities($shared_user);
78:     }
79: }
```

**Reproduction-path note**: the static finding's originally-cited sink, `CalendarController::action_getActivities()` (`modules/Calendar/controller.php:307`, the AJAX `action=getActivities&view=shared` path), is **not reachable** for the shared case: `Calendar::__construct()` resets any `$view` argument that isn't a whitelisted key (`agendaDay/basicDay/basicWeek/agendaWeek/month/sharedMonth/sharedWeek`) back to `agendaWeek` — the literal string `'shared'` is not on that list — so `$cal->view` can never equal `'shared'`, the exact string `action_getActivities()` tests for. This was confirmed dynamically (instrumented a copy of the file inside the running container; the shared branch's log line never fired for any `view` value tried; `jsonData` was always `[]`). The *identical* vulnerable code (`init_shared()` / `add_activities()`) is live and reachable through `modules/Calendar/index.php` shown above, which is what a real "Shared" tab click in the UI actually sends (`view=sharedWeek`/`sharedMonth`, the whitelisted names). The defect, mechanism, and impact described in the static finding are unchanged — only the exact URL differs from what was originally written down.

**Sink #1** — `modules/Calendar/Calendar.php:367-380`:
```php
367: public function init_shared()
368: {
        global $current_user;
372:    $user_ids = $current_user->getPreference('shared_ids');
373:    if (!empty($user_ids) && ... && !isset($_REQUEST['shared_ids'])) {
374:        $this->shared_ids = $user_ids;
        } else {
376:        if (isset($_REQUEST['shared_ids']) && ... > 0) {
377:            $this->shared_ids = $_REQUEST['shared_ids'];     // <-- attacker-controlled, unvalidated
378:            $current_user->setPreference('shared_ids', $_REQUEST['shared_ids']);
            } else {
380:            $this->shared_ids = array($current_user->id);
            }
        }
    }
```
`$_REQUEST['shared_ids']` — an array of arbitrary user GUIDs — is copied into `$this->shared_ids` with no check whatsoever that the current user has a sharing/delegation relationship with any of them.

**Sink #2** — `include/utils/activity_utils.php:45-60` (`build_related_list_by_user_id`, reached via `CalendarActivity::get_activities()` for each `Meetings`/`Calls`/`Tasks` type):
```php
57: $auto_where .= " {$bean->rel_users_table}.{$bean_id_name}={$bean->table_name}.id
                     AND {$bean->rel_users_table}.user_id='{$user_id}'
                     AND {$bean->table_name}.deleted=0 AND {$bean->rel_users_table}.deleted=0";
```
`$user_id` here is one of the ids from `$cal->shared_ids` — i.e. attacker-controlled. The query is keyed **only** on that id; there is no additional ACL or Security-Group predicate, so it faithfully returns every Meeting/Call/Task the target user is an invitee of.

**The exact defect**: `init_shared()` is missing a check along the lines of "is `$member` a user who has added `current_user` to *their* shared/delegate list", before trusting `$_REQUEST['shared_ids']`.

## Why it is a vulnerability (reasoning)
"Shared calendar" is explicitly an opt-in feature — a user must choose to let specific colleagues see their schedule. The one authorization check present, `ACLController::checkAccess('Calendar', 'list', true)` (`modules/Calendar/index.php:44`), only gates "can this user use the Calendar module at all" — a coarse, module-level check that says nothing about *whose* calendar is being requested. The per-target-user decision is exactly the missing piece, and it's the piece that actually matters here: without it, "shared calendar" degrades from an opt-in visibility feature into "any authenticated user may view any other user's private schedule," silently defeating the feature's own purpose.

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates **V** and **A** (unrelated, A never granted calendar sharing). As **V**, create a Meeting scheduled for "today" with a unique name and description; SuiteCRM auto-adds V as an invitee (`meetings_users`).
2. **Attack request**, as **A**:
   ```
   GET /index.php?module=Calendar&action=index&view=sharedWeek&shared_ids[]=<victim_user_id>
   Cookie: PHPSESSID=<attacker session>
   ```
   (full request in `request.http`)
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected tail:
   ```
   [PROOF] victim meeting name '...' present in attacker's shared-view response: True
   [PROOF] victim meeting description '...' present in attacker's shared-view response: True
   ==> VULN-029: CONFIRMED — attacker read V's Meeting (...) via Calendar shared_ids[] with no consent check
   ```
4. **Observable proof** — `response.txt` / `evidence/leaked_calendar_items.txt` show the victim's Meeting `name` and `description` embedded verbatim in a `calendar_items = {...}` JS object inside the attacker's own rendered calendar HTML page — data that could only have come from the victim's `meetings`/`meetings_users` rows.

## Impact
- **Confidentiality (horizontal, high)**: complete read of any/every user's Meetings, Calls, and Tasks — subject, description, start/end time, duration — by simply naming their user GUID (visible throughout the UI in assignment dropdowns, so not a hard value to obtain).
- Meeting/Call text frequently carries sensitive business content (deal names, escalation notes, dial-ins, candidate names) — an attacker can script a sweep over every known user GUID to reconstruct the organization's entire private schedule.
- No integrity/availability impact on this path; chains with the broader GUID-enumeration cluster ([VULN-001], [VULN-024]) for target selection.

## Suggested fix
In `init_shared()`, before accepting `$_REQUEST['shared_ids']`, validate each id against an actual sharing/delegation relationship the target user granted to `current_user` (SuiteCRM already has the scaffolding for this via `getPreference('shared_ids')` on the *sharer's* own account — that preference should be checked on the *target* user, not trusted verbatim from the viewer's request). Alternatively, push a proper ACL/Security-Group predicate into `build_related_list_by_user_id()` so the query itself cannot return rows the caller isn't entitled to see, independent of what `shared_ids` claims.

## References
- CWE-862 — Missing Authorization.
- GHSA-jh8v-wqgj-hhc2 — "Inconsistent RBAC Enforcement [Resource Calendar]" (same subsystem, broader family).
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (IDOR).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM Calendar shared_ids IDOR vulnerability shared calendar any user meetings` — only CVE-2026-32697 (v8 getRecord ACL bypass), CVE-2026-29189 (V8 API IDOR) and CVE-2025-64490 (Resource Calendar RBAC); nothing on `shared_ids`
2. `GHSA-jh8v-wqgj-hhc2 SuiteCRM Inconsistent RBAC Enforcement Resource Calendar` — docs and old SecuritySuite community threads only
3. `SuiteCRM CVE Calendar module init_shared shared_ids missing authorization` — CVE-2025-64490, CVE-2025-54786 (iCal), CVE-2026-108712 (DetailUserRole); no `init_shared` match
4. `"SuiteCRM" "shared_ids" calendar vulnerability OR advisory OR CVE` (extended) — no result mentions `shared_ids` or the shared calendar view
5. `SuiteCRM calendar view other users calendar without sharing IDOR huntr OR exploit-db OR hackerone` — only CVE-2025-54786 (unauthenticated legacy iCal feed)
6. Fetched github.com/SuiteCRM/SuiteCRM/security/advisories/GHSA-jh8v-wqgj-hhc2 — describes Projects/Project Tasks/Resource Calendar role bypass (CVE-2025-64490, fixed 7.14.8); does not mention the Calendar module shared view, `shared_ids`, or reading other users' Meetings/Calls/Tasks
7. Reviewed all 8 pages of github.com/SuiteCRM/SuiteCRM/security/advisories (77 advisories, 2024-06 to 2026-10) — no advisory for the Calendar module shared view

**Related but distinct public references** (same class or component, not this bug):
- GHSA-jh8v-wqgj-hhc2 / CVE-2025-64490 — role-level bypass in the Projects "Resource Calendar"/Project Task views (different module and code path, fixed in 7.14.8, before 7.15.2)
- GHSA-rf2v-4mv3-qcgm / CVE-2025-54786 — unauthenticated legacy iCal service (`vcal_server`) returns a user's meetings by username; different entry point, fixed in 7.14.7
- GHSA-m6x8-3hxp-qxwv / CVE-2026-29189 — V8 REST API user-preference/relationship IDOR; different API surface, fixed 7.15.1

**Reasoning:** No public advisory, CVE, or report describes `Calendar::init_shared()` trusting `$_REQUEST['shared_ids']` or the `modules/Calendar/index.php` sharedWeek/sharedMonth path returning other users' activities. The closest advisories concern the Projects Resource Calendar role bypass and the unauthenticated iCal feed, both different components and both fixed before 7.15.2. SuiteCRM has a very dense IDOR/ACL advisory history and some advisories are described only at the "area" level, so a private or vaguely-worded report cannot be fully excluded.
