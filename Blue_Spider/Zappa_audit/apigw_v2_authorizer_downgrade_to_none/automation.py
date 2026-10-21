#!/usr/bin/env python3
"""VULN-028 — HTTP API v2 silently downgrades a non-IAM authorizer to NONE and ignores api_key.

Vulnerable code : targets/Zappa/zappa/core.py:2091-2103 ($default route auth), :2043-2049 (api_key_required ignored)
Vulnerability   : CWE-285 Improper Authorization (auth control silently dropped).
Surface         : A (config) — the app is served unauthenticated while the operator believes it is protected.

Mechanism (plain English)
-------------------------
`create_api_gateway_v2_routes` builds the `$default` route for an HTTP API (v2).
Its authorization handling is:

    if authorization_type == "AWS_IAM":
        route.AuthorizationType = "AWS_IAM"
    elif authorization_type != "NONE":
        logger.warning("HTTP API v2 currently only supports AWS_IAM and NONE ... Using NONE.")
        route.AuthorizationType = "NONE"        # <-- any other authorizer downgraded to NONE
    else:
        route.AuthorizationType = "NONE"

So an operator who configures a JWT/Lambda/custom authorizer (anything other than
`AWS_IAM`) gets a route with **no** authorization — only a log warning. Separately,
`api_key_required` is accepted as a parameter (:2047) but **never applied** to the
v2 route, so an operator relying on an API key is also served unauthenticated.

What a successful run proves
----------------------------
Driving the real route builder with a non-IAM authorizer + `api_key_required=True`
produces a `$default` route whose `AuthorizationType` is `NONE` and with no
`ApiKeyRequired` — i.e. the app is exposed unauthenticated.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_python, log, verdict

VULN = "VULN-028"

_DRIVER = r"""
import json, troposphere
from zappa.core import Zappa
z = Zappa.__new__(Zappa)
z.cf_template = troposphere.Template()
# Operator intends a protected API: a custom/JWT authorizer AND an API key.
z.create_api_gateway_v2_routes(
    lambda_arn="arn:aws:lambda:us-east-1:000000000000:function:victim",
    api_key_required=True,
    authorization_type="CUSTOM",          # a non-IAM authorizer the operator believes is enforced
    authorizer={"type": "JWT"},
)
route = [r for r in z.cf_template.resources.values() if r.__class__.__name__ == "Route"][0]
print(json.dumps({
    "auth_type": getattr(route, "AuthorizationType", "<unset>"),
    "api_key_required_attr": getattr(route, "ApiKeyRequired", "<unset>"),
}))
"""


def main():
    banner(VULN, "HTTP API v2 downgrades non-IAM authorizer to NONE, ignores api_key",
           "zappa/core.py:2091-2103 (create_api_gateway_v2_routes $default)")

    log("STEP", "building the v2 $default route with a CUSTOM authorizer + api_key_required=True")
    cp = lab_python(_DRIVER)
    res = json.loads(cp.stdout.decode().strip().splitlines()[-1])
    log("INFO", f"generated route AuthorizationType = {res['auth_type']!r}")
    log("INFO", f"generated route ApiKeyRequired    = {res['api_key_required_attr']!r} (never set for v2)")

    downgraded = res["auth_type"] == "NONE"
    apikey_ignored = res["api_key_required_attr"] in ("<unset>", None, False)

    if downgraded and apikey_ignored:
        log("PROOF", "the operator asked for a CUSTOM authorizer and an API key, but the generated $default "
                     "route has AuthorizationType='NONE' and no ApiKeyRequired — the HTTP API is served "
                     "unauthenticated while the operator believes it is protected (only a log warning is emitted).")
        log("OK", "exploit confirmed — v2 authorizer downgraded to NONE, api_key ignored")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — v2 $default route serves app unauthenticated (auth->NONE)")
        return 0
    log("FAIL", f"downgraded={downgraded} apikey_ignored={apikey_ignored}")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
