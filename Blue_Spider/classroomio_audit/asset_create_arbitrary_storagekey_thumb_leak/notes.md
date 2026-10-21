**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 3.1 8.1)
**Validated at**: 2026-09-27

## Preconditions
- Any authenticated org member (a STUDENT) — provisioned via `make_student`.
- A known/guessable `videos`-bucket object key belonging to another user/tenant. For the
  end-to-end proof a victim video is seeded into MinIO at a **foreign org prefix**
  (`videos/44444444-…/private-lecture-<rand>.mp4`) using the admin `mc` client inside the
  `cio-minio` container — this stands in for another tenant's private object; the attacker
  never uploaded it and it lies outside the attacker's org prefix.
- OpenAI is not configured here (`OPENAI_API_KEY` empty) → the transcript-exfil half is out of
  scope for this run; the thumbnail-exfil half needs no key and is what is demonstrated.

## Request
See `request.http`. Decisive request:
```
POST http://localhost:21527/organization/assets
Content-Type: application/json
cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
Cookie: classroomio.session_token=<attacker STUDENT session>

{"kind":"video","provider":"upload","storageKey":"44444444-4444-4444-8444-444444444444/private-lecture-<rand>.mp4","byteSize":10890,"mimeType":"video/mp4","durationSeconds":2}
```
Then anonymously fetch the worker-published frame:
`GET http://localhost:21528/media/thumbnails/<assetId>/middle-<ts>.jpg`

## Response
See `response.txt` / `run.log`.
- Create asset → `HTTP 201` with the asset id; DB `assets` row =
  `storage_key = 44444444-…/private-lecture-<rand>.mp4 | organization_id = 48bbdff8-… (attacker org) | created_by = <attacker>`.
- Anonymous thumbnail GET → `HTTP 200`, `8820` bytes, valid JPEG (magic `FF D8`), saved to
  `evidence/stolen-thumbnail.jpg` (320×240 frame of the foreign video).

## Observation
`POST /organization/assets` accepts a client `storageKey` with no prefix/ownership check
(`assets.ts:24` — `storageKey: z.string().min(1).optional()`), stores it verbatim
(`buildAssetValues`), and — because `kind:'video', provider:'upload'` — enqueues media
post-processing (`scheduleAssetBackgroundWork`). The thumbnail worker then downloaded
`videos/<foreign-key>`, extracted frames, and uploaded them to the anonymous-read `media`
bucket, recording their public URLs in `assets.thumbnail_candidates`. Worker log:
`generate-thumbnail-done … candidateCount:3`. (`thumbnail_url` stayed null only because this
ffmpeg build's `signalstats YAVG` luma probe failed, so every frame was conservatively flagged
"black"; the frames were still published — the exfil does not depend on the "chosen" URL.)

## Side effects
- Creates one attacker-owned `assets` row per run (random title/key) pointing at the foreign
  object; publishes 3 JPEG frames into the public `media` bucket under `thumbnails/<assetId>/`.
  No victim data is modified. Seed objects use random keys.

## Research & references
- OWASP API1:2023 BOLA / API3 (excessive server-side trust of client-named resources).
- CWE-639 IDOR; CWE-441 Unintended Proxy / Confused Deputy (server processes attacker-named objects).
- The team knows the correct check: `finalizeHlsAssetService` enforces
  `data.manifestKey.startsWith(prefix)`; this path omits the equivalent guard.

## If FAILED
n/a — CONFIRMED (core IDOR + thumbnail exfil both observed).

## If NEEDS_MANUAL
The **transcript** exfil half (`GET /organization/assets/:id/transcript`) needs
`OPENAI_API_KEY` set for the audio-extract/transcribe workers (`media-jobs.ts:196,234`); it is
not exercised here. The core IDOR and the public-frame republish (the confidentiality break)
are fully confirmed above without it.
