#!/usr/bin/env python3
"""VULN-012 — Public Function URL grants lambda:InvokeFunction to Principal:* (world direct-invoke).

Vulnerable code : targets/Zappa/zappa/core.py:67-70 (rule table) + core.py:1633-1649 (update_function_url_policy)
Vulnerability   : CWE-284 Improper Access Control / CWE-732 (over-broad resource policy).
Surface         : B enabler (config) — the reachability spine of the headline cross-account RCE chain.

Mechanism (plain English)
-------------------------
When a public Function URL is configured (`authorizer == "NONE"`), Zappa adds
*two* Lambda resource-policy statements from a rule table:

    FUNCTION_URL_PUBLIC_PERMISSION_RULES = (
        ("FunctionURLAllowPublicAccess",       "lambda:InvokeFunctionUrl", True),
        ("FunctionURLAllowPublicAccessInvoke", "lambda:InvokeFunction",     False),
    )

The first (InvokeFunctionUrl, requires_auth_type=True) is the legitimate public-URL
grant, scoped with `FunctionUrlAuthType`. The **second** grants the far broader
`lambda:InvokeFunction` to `Principal:"*"` with **no** `FunctionUrlAuthType`, no
`SourceArn`, and no `SourceAccount`. A public-URL Lambda resource policy with
`Principal:"*"` and no conditions means **any AWS account can direct-invoke the
function with an arbitrary event** — which turns Zappa's Surface-B code-exec
sinks (VULN-001/002/024/VULN-030) into cross-account RCE.

What a successful run proves
----------------------------
Driving the real `update_function_url_policy` with `authorizer: NONE` emits an
`add_permission` call for `lambda:InvokeFunction` with `Principal:"*"` and no
auth-type condition.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_python, log, verdict

VULN = "VULN-012"

# Drive the real Zappa.update_function_url_policy with a mock lambda client that
# captures add_permission calls (no AWS needed — we inspect the policy Zappa builds).
_DRIVER = r"""
import json
from zappa.core import Zappa
calls = []
class FakeLambda:
    def add_permission(self, **kw): calls.append(kw); return {}
z = Zappa.__new__(Zappa)                 # bypass __init__ (needs AWS); we only exercise the policy logic
z.lambda_client = FakeLambda()
z.list_function_url_policy = lambda fn: []   # simulate a fresh function (no existing statements)
Zappa.update_function_url_policy(z, "victim-func", {"authorizer": "NONE"})
print(json.dumps(calls))
"""


def main():
    banner(VULN, "Public Function URL grants InvokeFunction to Principal:* (world invoke)",
           "zappa/core.py:1633-1649 update_function_url_policy (authorizer==NONE)")

    log("STEP", "driving update_function_url_policy for a public Function URL (authorizer=NONE)")
    cp = lab_python(_DRIVER)
    calls = json.loads(cp.stdout.decode().strip().splitlines()[-1])
    for kw in calls:
        log("INFO", f"add_permission Sid={kw.get('StatementId')} Action={kw.get('Action')} "
                    f"Principal={kw.get('Principal')} AuthType={kw.get('FunctionUrlAuthType', '<none>')}")

    # The dangerous statement: InvokeFunction to * with NO auth-type condition.
    world_invoke = [
        kw for kw in calls
        if kw.get("Action") == "lambda:InvokeFunction"
        and kw.get("Principal") == "*"
        and "FunctionUrlAuthType" not in kw
    ]

    if world_invoke:
        log("PROOF", "Zappa emitted add_permission(Action='lambda:InvokeFunction', Principal='*') with no "
                     "FunctionUrlAuthType / SourceArn / SourceAccount — any AWS principal can direct-invoke "
                     "the function with an arbitrary event, opening the Surface-B RCE sinks cross-account.")
        log("OK", "exploit confirmed — world-invocable lambda:InvokeFunction statement generated")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — public Function URL adds unscoped InvokeFunction to Principal:*")
        return 0
    log("FAIL", "no unscoped InvokeFunction->Principal:* statement found")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
