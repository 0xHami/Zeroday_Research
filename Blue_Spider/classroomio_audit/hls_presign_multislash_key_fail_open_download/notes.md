**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 3.1 7.1)
**Validated at**: 2026-09-27

## Preconditions
- Any authenticated org member with a session (a STUDENT — provisioned via `make_student`);
  the presign auth middleware applies **no role check** to browser sessions.
- A target multi-slash HLS key in the `videos` bucket. For the end-to-end proof a victim object
  is seeded at a **foreign org prefix** with ≥2 slashes
  (`videos/22222222-…/hls/master-<rand>.m3u8`) via the admin `mc` client — a foreign private
  object the attacker's org does not own.

## Request
See `request.http`. Two requests demonstrate the fail-open split:
```
# control — single-slash foreign key: guard REJECTS
POST http://localhost:21527/course/presign/video/download
Content-Type: application/json
cio-org-id: 48bbdff8-2ad5-46a3-a259-2ca3d52677dd
Cookie: classroomio.session_token=<attacker STUDENT session>

{"keys":["33333333-…/private-<rand>.mp4"]}

# attack — multi-slash HLS foreign key: guard ALLOWS (fail open)
{"keys":["22222222-…/hls/master-<rand>.m3u8"]}
```

## Response
See `response.txt` / `run.log`.
- single-slash foreign key → `HTTP 403 {"error":"One or more requested keys do not belong to this organization"}`
- multi-slash HLS foreign key → `HTTP 200 {"success":true,"urls":{"22222222-…/hls/master-<rand>.m3u8":"http://localhost:21528/videos/…?X-Amz-…"}}`
- fetching the signed URL → `HTTP 200`, 82 bytes = the exact seeded manifest bytes.

## Observation
`readOrganizationIdFromFileKey` (`upload.ts:43-52`) matches only `<uuid>/<segment-with-no-slash>`
(exactly one slash), so the HLS key (2 slashes) returns `null` → it is treated as a "legacy"
key. `getAssetOrganizationIdsByStorageKeys` returns an **empty** owner set (HLS objects record
their location in `hls_manifest_key`, not `storage_key`), and the guard only flags a key when
`ownerOrgIds.length > 0` (`presign-auth.ts:81`) → the key is never added to `unauthorizedKeys`
→ the presign proceeds (fail open). The single-slash control key resolves to a foreign org id
and is correctly rejected — proving the guard works when owner resolution succeeds and fails
open when it does not. The presign auth middleware applies no role gate to sessions
(`presign-auth.ts:35-42`).

## Side effects
- Read-only. Seeds one foreign HLS object per run (random key); no state changed.

## Research & references
- CWE-636 Not Failing Securely ("Failing Open"); CWE-639 IDOR; OWASP API1:2023 BOLA.
- OWASP ASVS V4 access control — deny by default; fail closed when an authorization input
  (here, the object owner) cannot be resolved.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. (Cross-tenant impact is inherent to the fail-open logic; demonstrated here on the single
instance with a foreign-org-prefixed key that no asset row claims — exactly the ownerless case
the guard lets through.)
