# VULN-021 — `isCustomDomainVerified` mass-assignment → instance-wide credentialed-CORS trust

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED (mass-assignment + CORS trust poisoning observed end-to-end in this process)
**Severity (static)**: Medium (High in cloud) — CVSS 3.1 6.5 `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N`
**Validated at**: 2026-09-27

## Preconditions
- An org ADMIN session (the manifest admin qualifies). No DNS/ownership of the injected hostname is needed — that is the bug.

## Request
See `request.http`. `PUT /organization` with `{"customDomain":"<EVIL>","isCustomDomainVerified":true}`, plus before/after CORS probes `GET /` with `Origin: http://<EVIL>`.

## Response
- Baseline `GET /` `Origin: http://<EVIL>` → **no** `Access-Control-Allow-Origin`.
- `PUT /organization` → **200**; DB `organization.customDomain=<EVIL>`, `isCustomDomainVerified=t`.
- Post-poison `GET /` `Origin: http://<EVIL>` → `Access-Control-Allow-Origin: http://<EVIL>` **and** `Access-Control-Allow-Credentials: true`.
- After restore → `<EVIL>` no longer reflected; DB back to `customDomain=<null>, isCustomDomainVerified=f`.

## Observation
`ZUpdateOrganization` accepts client `customDomain` + `isCustomDomainVerified` (`packages/utils/src/validation/organization/organization.ts:147-148`); `updateOrg` persists them and, when both are truthy, calls `trustCustomDomainHostname(hostname)` with **no** verification (`apps/api/src/services/organization.ts:825-829`) into a **process-wide** `Set` (`packages/db/src/utils/custom-domain/trusted-origin.ts:8`) consulted by `sessionCors` (`cors.ts:25-29` → `origins.ts:16` → `trusted-origin.ts:95`). Because `NODE_ENV=production` here, the local-host CORS bypass (`trusted-origin.ts:87`) is inactive, so the untrusted `<EVIL>` origin is reflected **only** as a result of the mass-assignment. A page on `<EVIL>` can therefore read authenticated (`credentials:true`) API responses cross-origin.

## Side effects
Temporary: `<EVIL>` added to the trust set + written to `organization.customDomain`/`isCustomDomainVerified`. The exploit **restores** the org (customDomain=null, isCustomDomainVerified=false) and `untrustCustomDomainHostname` removes the entry; verified post-run.

## Research & references
- CWE-915 mass-assignment; CWE-346 origin validation error; OWASP CORS misconfiguration (credentialed reflection).
- Correct path contrast: `apps/api/src/routes/domain/domain.ts:31-36` sets the flag from the Approximated provider's real verification.
- Weaponization (F-02): the reflected origin must be attacker-registrable (cloud); on this local instance the CORS reflection itself is proven with a synthetic origin.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
Full cross-tenant credential theft requires an attacker-registrable domain hosting the malicious page; the CORS trust poisoning that enables it is confirmed here.
