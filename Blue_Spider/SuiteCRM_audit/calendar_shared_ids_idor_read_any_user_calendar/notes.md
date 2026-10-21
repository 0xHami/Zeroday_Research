# VULN-029 — Calendar shared view reads any user's activities (IDOR)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:30Z

## Preconditions
- Admin creates victim **V** and attacker **A** (fresh, unrelated low-priv users).
- As **V**: `module=Meetings&action=Save` creates a Meeting for "today" (app-container clock, `date_start` formatted `m/d/Y` per `config.php:153 default_date_format`, `time_start` in 24h `H:i` per `config.php:179 default_time_format` — an `am/pm` time string silently fails to parse and leaves `date_start` NULL, which was caught during validation), assigned to V. SuiteCRM auto-adds the assigned user as an invitee (`meetings_users` row, verified via db), which is what the shared-view query joins on.

## IMPORTANT — reproduction path correction (found during this validation)
The static finding cites `modules/Calendar/controller.php:307` (`CalendarController::action_getActivities()`, reached via `module=Calendar&action=getActivities&view=shared&shared_ids[]=...`) as the sink. Dynamic testing showed **this specific entry point is unreachable for the shared case**:

1. `Calendar::__construct()` (`modules/Calendar/Calendar.php:114-121`) resets `$this->view` to `'agendaWeek'` whenever the constructor argument isn't a key of `$this->views` (`agendaDay/basicDay/basicWeek/agendaWeek/month/sharedMonth/sharedWeek`). The literal string `'shared'` is **not** one of those keys, so `new Calendar($_REQUEST['view'])` with `view=shared` silently becomes `agendaWeek`.
2. `action_getActivities()`'s own branch test is `elseif ($cal->view == 'shared')` — a literal-string comparison that therefore can never be true through this constructor call, for *any* input (passing `view=sharedWeek` avoids the reset in step 1, but then fails step 2's exact-string check instead).

This was confirmed by temporarily instrumenting a copy of `controller.php` inside the running container (`docker compose exec app`, not the host checkout — reverted immediately after, see "Side effects") with `error_log()` calls: for every value of `view` tried (`shared`, `sharedWeek`, `sharedMonth`, `day`, `week`, `month`), the shared branch's log line never fired, and `jsonData` was always `[]`.

**The underlying vulnerability is real and live**, reachable instead via the Calendar module's *main page* controller, `modules/Calendar/index.php:70-79`:
```php
$cal = new Calendar($_REQUEST['view'], array(), $views);
if ($cal->view == "sharedMonth" || $cal->view == "sharedWeek") {   // the CORRECT, whitelisted names
    $cal->init_shared();
    ...
    foreach ($cal->shared_ids as $member) {
        $shared_user->retrieve($member);
        $cal->add_activities($shared_user);
    }
}
```
identical downstream sink (`Calendar.php:376-378` `init_shared()` trusting `$_REQUEST['shared_ids']`; `include/utils/activity_utils.php:57` raw query keyed only on `user_id`). This script uses `module=Calendar&action=index&view=sharedWeek&shared_ids[]=<victim_id>` — a corrected, dynamically-verified reproduction of the same root cause described in the static finding.

## Request
See `request.http`:
```
GET /index.php?module=Calendar&action=index&view=sharedWeek&shared_ids[]=<victim_user_id>
Cookie: PHPSESSID=<attacker session>
```

## Response
See `response.txt`. HTTP 200, ~142 KB HTML page containing a `calendar_items = {...}` JS object keyed by the victim's user id, whose value is a JSON array with one entry: `"name":"V029Meeting_... Low Stage...","description":"SECRETDESC029_...",...` — the victim's private Meeting subject and description, verbatim, inside the attacker's own rendered calendar page. See `evidence/leaked_calendar_items.txt`.

## Observation
Matches the underlying static finding's root cause exactly (once the entry point is corrected as above): `init_shared()` copies `$_REQUEST['shared_ids']` with no validation that the caller and the named user(s) have any sharing relationship, and `build_related_list_by_user_id()` (`include/utils/activity_utils.php:45-60`) queries strictly by `rel_users_table.user_id = '<requested id>'` — it faithfully returns whichever user's activities are asked for, authenticated or not to that specific user's calendar.

## Side effects
- One Meeting + its `meetings_users` invitee row created by V (random-suffixed, harmless).
- Two new low-priv Users created (harmless).
- Debug instrumentation used to trace the dead-code branch was applied **only inside the running `app` container's ephemeral filesystem** via `docker compose cp` (the container has no bind mount to the host checkout — confirmed: container's `modules/Calendar/controller.php` differs in byte size from any host edit until explicitly `docker compose cp`'d in). The container was restarted after `docker compose cp`-ing the **original, unmodified** `controller.php` back in, and `grep -c DEBUG_GETACT modules/Calendar/controller.php` inside the container returned `0` before proceeding — confirmed clean. No host file under `targets/SuiteCRM/` was ever left modified (edits made there during the same investigation were reverted via `diff -q` before this).

## Research & references
- CWE-862 — Missing Authorization.
- GHSA-jh8v-wqgj-hhc2 — "Inconsistent RBAC Enforcement [Resource Calendar]" (same module, broader RBAC-enforcement family per stage-05 known-issue cross-check).
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References.

## If FAILED
N/A — CONFIRMED (via the corrected entry point documented above).
