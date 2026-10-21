# VULN-011 — Unvalidated `storageKey` at asset creation → server processes/publishes arbitrary storage objects

| | |
|---|---|
| **ID** | VULN-011 (raw F-08) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 8.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any org member (STUDENT) |
| **What an attacker gains** | A viewable frame (and, with OpenAI, the full transcript) of any private `videos` object whose key is known — cross-user here, cross-tenant in cloud — plus OpenAI/CPU resource abuse |

## Summary

`POST /organization/assets` lets any org member create an asset whose `storageKey` is an
arbitrary, client-chosen object key with **no prefix or ownership validation**. The value is
stored verbatim and, for `kind:'video'` uploads, enqueued for background media processing. The
thumbnail worker downloads `videos/{storageKey}`, extracts frames, and republishes them to the
**anonymous-read `media` bucket**, recording their public URLs on the attacker's asset. So a
student can name any private video object and receive a public frame of it. Confirmed live: a
STUDENT created an asset pointing at a foreign-org key `44444444-…/private-lecture-<rand>.mp4`;
the DB row stored that key under the attacker's org, the worker published three JPEG frames to
the public bucket, and the attacker fetched one anonymously (HTTP 200, valid JPEG,
`evidence/stolen-thumbnail.jpg`).

## How it works (mechanism & code trace)

**Entry — `apps/api/src/routes/organization/assets.ts:89`.** `orgMemberMiddleware` = any
org member (a STUDENT populates `orgRoles`):

```ts
.post('/', authMiddleware, orgMemberMiddleware, zValidator('json', ZAssetCreateUpload), async (c) => {
  const orgId = c.req.header('cio-org-id')!;
  const asset = await createAssetFromUploadService(orgId, user.id, c.req.valid('json'));
  ...
})
```

**Missing guard — `packages/utils/src/validation/assets/assets.ts:24`.** `storageKey` is
free-form; the schema only later requires it to be *present* for uploads, never that it is
*owned*:

```ts
storageKey: z.string().min(1).optional(),
```

**Verbatim store + enqueue — `packages/core/src/services/assets/assets.ts:437,462-469`.**

```ts
function buildAssetValues(orgId, profileId, data) {
  return { organizationId: orgId, ..., storageKey: data.storageKey ?? null, createdByProfileId: profileId };
}
...
if (asset.kind === 'video' && asset.provider === 'upload' && asset.storageKey) {
  void enqueueMediaPostProcessingForAsset({ organizationId: orgId, assetId: asset.id, storageKey: asset.storageKey, ... });
}
```

The upsert conflict target is `[organizationId, provider, storageKey]`
(`packages/db/src/queries/assets/assets.ts`), so the attacker's own org always yields a fresh
row pointed at the victim's object.

**Sink — `apps/jobs/src/processors/media/generate-thumbnail.ts:187,202-228`.** The worker
reads the attacker-named key from the private `videos` bucket and uploads frames to the
anonymous-read `media` bucket:

```ts
localPath = await downloadObjectToTempFile(videosBucket(), storageKey, 'thumb-source.bin');
...
const key = `thumbnails/${assetId}/${slot}-${Date.now()}.jpg`;
await uploadBufferToBucket(mediaBucket(), key, capture.buffer, 'image/jpeg', 'public, max-age=31536000');
await updateAsset(assetId, actorContext.organizationId, { thumbnailUrl: publicUrl, thumbnailCandidates: candidateUrls });
```

**Why the framework doesn't save it.** The correct check exists elsewhere —
`finalizeHlsAssetService` enforces `data.manifestKey.startsWith(prefix)` for the caller's org —
but this create path omits it entirely. Frames land in a bucket served with a public-download
policy, so the derived image needs no auth to retrieve.

## Why it is a vulnerability

The server acts as a confused deputy: it trusts a client-supplied object key and hands it to a
pipeline that *reads the referenced private object and republishes a derivative to a public
location*. The trust boundary "an org may only process objects it owns" is broken —
`readOrganizationIdFromFileKey(storageKey)` would show the key belongs to a different org, but
it is never consulted here. Result: confidentiality break on any private video whose key is
known (keys circulate to uploaders, to every course tutor, via public-course HLS prefixes, and
through the other object-storage IDORs VULN-012/016/033).

## Reproduction

1. As a STUDENT org member, `POST /organization/assets` with
   `{"kind":"video","provider":"upload","storageKey":"<foreign videos key>","byteSize":N,"mimeType":"video/mp4","durationSeconds":2}` → **201**.
2. DB `assets` row shows `storage_key = <foreign key>`, `organization_id = <attacker org>`,
   `created_by_profile_id = <attacker>` — an arbitrary key accepted with no ownership check.
3. Within seconds the media worker publishes frames; `assets.thumbnail_candidates` holds
   `http://<media-public>/thumbnails/<assetId>/<slot>-<ts>.jpg` URLs.
4. Fetch a candidate URL with **no credentials** → HTTP 200, a JPEG frame of the foreign video.
5. `./run.sh` → `[OK]`, exit 0. Frame saved to `evidence/stolen-thumbnail.jpg`.

## Impact

- **Confidentiality (C:H):** a viewable frame of any private `videos` object given its key
  (and, with `OPENAI_API_KEY`, the full transcript via `GET /organization/assets/:id/transcript`).
- **Scope (S:C):** reads/republishes objects owned by another user/tenant.
- **Resource abuse:** attacker-triggered ffmpeg/transcription work on the operator's workers.
- **Chaining:** key disclosure via VULN-016/033/011; the anon-read bucket (VULN-047) and the
  presign IDORs (VULN-012/019) compound the object-storage exposure.

## Suggested fix

1. In `createAssetFromUploadService` / `buildAssetValues`, reject any `storageKey` whose org
   prefix (`readOrganizationIdFromFileKey`) ≠ the caller's org, or verify via `HeadObject` that
   this org's presigned upload wrote it — mirroring `finalizeHlsAssetService`:
   ```ts
   const owner = readOrganizationIdFromFileKey(data.storageKey);
   if (data.provider === 'upload' && owner !== orgId) {
     throw new AppError('storageKey does not belong to this organization', ErrorCodes.FORBIDDEN, 403);
   }
   ```
2. Do not publish derived thumbnails to an anonymous-read bucket; presign-gate derivative
   retrieval so a leaked/guessed URL is not world-readable.

## References

- OWASP API Security Top 10 — API1:2023 (BOLA); CWE-639 IDOR; CWE-441 Confused Deputy.
- OWASP SSRF/Confused-Deputy guidance — never let a client name the resource a privileged
  backend will fetch and re-expose.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — only the 9 known ClassroomIO CVEs; none concern the assets service or storage keys.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; the only upload-adjacent ones are the SVG stored-XSS CVEs; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio assets storageKey vulnerability thumbnail video private bucket media worker` — no results on storage keys, buckets or the media worker; only CVE-2025-65675/65676 (SVG XSS) and the IDOR CVEs.
5. Direct read of the repo issue list filtered for security — no issue mentions assets, storage keys, thumbnails or the jobs worker.
6. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — no assets coverage.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-65675 / CVE-2025-65676 (GHSA-gfvq-wmqw-q9j2, GHSA-rxc6-c5mm-j9vx) — stored XSS via SVG profile/cover uploads in 0.1.13; upload-adjacent but a different class and a different (pre-Hono) component.
- CVE-2026-111368 — submission IDOR in the same API; different component.

**Reasoning:** Nothing public mentions `POST /organization/assets` (`apps/api/src/routes/organization/assets.ts`), `createAssetFromUploadService`, the unvalidated `storageKey`, or the thumbnail worker (`apps/jobs/src/processors/media/generate-thumbnail.ts`) republishing frames to the public `media` bucket. The media/asset pipeline is new and absent from all public ClassroomIO disclosures. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
