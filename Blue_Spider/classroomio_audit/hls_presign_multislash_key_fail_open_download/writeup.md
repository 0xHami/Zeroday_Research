# VULN-019 — HLS multi-slash keys misclassified "legacy" → cross-org presigned download (fail open)

| | |
|---|---|
| **ID** | VULN-019 (raw F-19) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 7.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any signed-in org member (no role gate on the presign path) |
| **What an attacker gains** | A signed GET for any multi-slash HLS object in the private `videos` bucket — cross-entitlement here, cross-tenant in cloud |

## Summary

The video-download presign route is meant to stop a caller presigning objects their org does
not own, via `findUnauthorizedDownloadKeys`. That guard resolves ownership with a regex that
requires **exactly one** slash. HLS keys look like `<assetId>/hls/master.m3u8` (≥2 slashes), so
owner resolution returns `null`, the key is treated as an ownerless "legacy" key, the fallback
asset lookup returns an **empty** owner set, and the guard — which only flags keys with a
*non-empty* owner set — lets it through. Any signed-in member can therefore mint a signed GET
for any multi-slash object in the private `videos` bucket. Confirmed live: the guard **rejected**
a single-slash foreign-org key (403) but **allowed** a foreign multi-slash HLS key (200), and
the returned URL downloaded the exact private manifest bytes.

## How it works (mechanism & code trace)

**Owner regex — `packages/core/src/utils/upload.ts:43-52`.** Only single-slash keys resolve to
an owner:

```ts
const ORGANIZATION_PREFIXED_KEY = /^([0-9a-f]{8}-...-[0-9a-f]{12})\/[^/]+$/i;   // EXACTLY one slash
export function readOrganizationIdFromFileKey(fileKey) {
  return ORGANIZATION_PREFIXED_KEY.exec(fileKey)?.[1] ?? null;                  // HLS key -> null
}
```

**Fail-open guard — `apps/api/src/middlewares/presign-auth.ts:64-84`.**

```ts
for (const key of keys) (readOrganizationIdFromFileKey(key) ? prefixedKeys : legacyKeys).push(key);  // HLS -> legacyKeys
...
const legacyOwners = await getAssetOrganizationIdsByStorageKeys(legacyKeys);   // HLS location is in hls_manifest_key, NOT storage_key -> empty
for (const key of legacyKeys) {
  const ownerOrgIds = legacyOwners.get(key) ?? [];
  if (ownerOrgIds.length > 0 && !ownerOrgIds.every(o => allowedOrgIds.includes(o))) {  // empty set => condition false
    unauthorizedKeys.push(key);                                                        // => NOT flagged (fail open, line 81)
  }
}
return unauthorizedKeys;
```

**No role gate — `apps/api/src/middlewares/presign-auth.ts:35-42`.** For browser sessions the
middleware sets the caller's member-org ids and continues; there is no STUDENT/TUTOR check.

**Route — `apps/api/src/routes/course/presign.ts:180-222`.** `rejectUnauthorizedKeys` → the
empty `unauthorizedKeys` → `generateVideoDownloadPresignedUrls(keys)` signs the GET.

**Why the framework doesn't save it.** Owner resolution fails **open**: a key whose owner
cannot be determined is treated as authorized rather than denied. The single-slash control key
in the run resolves to a foreign org id and *is* rejected — which proves the guard is real and
that the multi-slash allow is a genuine fail-open, not a missing guard.

## Why it is a vulnerability

The ownership control that should scope video downloads to the owning org is a no-op for the
exact key shape HLS uses. Any authenticated member (the presign path has no role gate) can sign
a GET for arbitrary HLS objects in the private `videos` bucket — cross-entitlement within the
org here, cross-tenant in the multi-tenant cloud build. HLS key layouts leak to unauthenticated
users through public-course lesson players, so a "known key" is realistic.

## Reproduction

1. As any signed-in org member, `POST /course/presign/video/download` with
   `{"keys":["<foreign-uuid>/hls/master.m3u8"]}` → **200** with a signed URL to the private
   `videos` bucket.
2. Control: the same call with `{"keys":["<foreign-uuid>/single.mp4"]}` (one slash) → **403**.
3. Fetch the signed URL from step 1 → **200**, the object's bytes (here the seeded manifest).
4. `./run.sh` → `[OK]`, exit 0 (asserts 403-vs-200 split and byte-for-byte download).

## Impact

- **Confidentiality (C:H):** signed downloads of arbitrary private/paid HLS video objects given
  a key (manifest and, by the same logic, every segment key).
- **Scope (S:C):** reads objects owned by another org/tenant.
- **Chaining:** key disclosure via VULN-011/016/033; part of the object-storage IDOR cluster
  (VULN-011/012/047).

## Suggested fix

1. Resolve ownership of multi-segment HLS keys via `hls_manifest_key`/`hls_audio_key` + asset
   lookup instead of falling through to "legacy".
2. **Fail closed**: when a key's owner cannot be resolved, deny (don't allow):
   ```ts
   // presign-auth.ts findUnauthorizedDownloadKeys — legacy branch
   const ownerOrgIds = legacyOwners.get(key) ?? [];
   - if (ownerOrgIds.length > 0 && !ownerOrgIds.every(o => allowedOrgIds.includes(o))) unauthorizedKeys.push(key);
   + if (ownerOrgIds.length === 0 || !ownerOrgIds.every(o => allowedOrgIds.includes(o))) unauthorizedKeys.push(key);
   ```
3. Apply a role/entitlement check to the download-presign path in addition to org membership.

## References

- CWE-636 Not Failing Securely ("Failing Open"); CWE-639 IDOR.
- OWASP API Security Top 10 — API1:2023 BOLA; OWASP ASVS V4 (deny by default).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — 9 known ClassroomIO CVEs; none concern presigned URLs, HLS or object storage.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; none storage/presign related; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio HLS presign video download "legacy" key fail open cross-organization presigned URL` — no ClassroomIO results; only generic CloudFront/Cloudflare Stream/PeerTube presign material.
5. Direct read of the repo issue list filtered for security — #1204 "[public API] Automation-key video routes live on the in-app API with no rate limit" (closed 2026-10-21) concerns rate limiting of video routes, not presign ownership checks; nothing on `presign-auth.ts` or HLS keys.
6. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — no presign/HLS coverage.

**Related but distinct public references** (same class or component, not this bug):
- GitHub issue classroomio/classroomio#1204 — video routes lacking rate limits; same video subsystem, different defect (availability/abuse, not an ownership fail-open).
- CVE-2026-111368 — submission IDOR in the same API; different component.

**Reasoning:** No public reference describes `findUnauthorizedDownloadKeys` (`apps/api/src/middlewares/presign-auth.ts`), the single-slash `ORGANIZATION_PREFIXED_KEY` regex in `readOrganizationIdFromFileKey`, or the empty-owner-set fail-open for multi-slash HLS keys on `POST /course/presign/video/download`. The HLS/presign pipeline is new and absent from every public ClassroomIO disclosure. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
