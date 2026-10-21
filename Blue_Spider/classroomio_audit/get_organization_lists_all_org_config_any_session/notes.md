# VULN-033 — GET /organization discloses full org config to any/anon session

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Status**: CONFIRMED
**Severity (static)**: Medium — CVSS 3.1 5.3 `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
**Validated at**: 2026-09-27

## Preconditions
- Any session. The exploit uses an **anonymous** better-auth session (VULN-018), so it is effectively unauthenticated (no account/signup/invite/org membership).

## Request
See `request.http`: baseline `GET /organization` with no cookie; then `POST /api/auth/sign-in/anonymous`; then `GET /organization` with the anonymous cookie.

## Response
- No cookie → `HTTP 401`.
- Anonymous session → `HTTP 200` returning a **list** of full org config rows. See `response.txt`.

## Observation
The 401→200 differential is the proof: `authOrApiKeyMiddleware` (`apps/api/src/routes/organization/organization.ts:103`) treats any session as authorized, so the anonymous session passes. With no query filters the underlying query's `whereClause` is `undefined` (`packages/db/src/queries/organization/organization.ts:841`), so it returns **every** organization row (auth-posture flags `disableEmailPassword`/`disableGoogleAuth`/`disableSignup`, `settings`, `customCode`, `aiTutorSettings` incl. escalation email, `landingpage`, custom-domain config, plan data). Live it returned **2** orgs (`probe3f8bad`, `cve-hunt-academy`) to an actor who is a member of neither — a cross-org enumeration.

**Scope correction (be precise):** in this self-hosted-style build the plan `subscriptionId` is a synthetic `selfhosted-*` and `customerId` is null, so the local impact is **org config / auth-posture disclosure + cross-org enumeration**, not real billing data. In cloud the same query returns the full tenant roster with real billing IDs.

## Side effects
- Read-only. One anonymous `user`/`profile`/`session` row per run (harmless orphan; VULN-018 side effect).

## Research & references
- OWASP API5:2023 Broken Function Level Authorization + API2:2023 Broken Authentication (anonymous session). CWE-284 / CWE-200.
- Chains: VULN-018 (anon session) unlocks it; leaked `orgId`/`siteName` feed VULN-034.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
- The **billing-ID** dimension (real `subscriptionId`/`customerId`, full multi-tenant roster) is only observable on a **cloud** multi-org deployment; not reproducible on this build. The config/auth-posture disclosure and cross-org enumeration are fully confirmed here.
