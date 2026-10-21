# VULN-018 — Unauthenticated session via `anonymous()` plugin

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Validated at**: 2026-09-27

## Preconditions
- None. Fully unauthenticated.

## Request
See `request.http`: `POST /api/auth/sign-in/anonymous` with body `{}`.

## Response
`HTTP 200` + `Set-Cookie: classroomio.session_token=…`; `get-session` returns a real
`user` with `isAnonymous: true` and empty `orgRoles`.

## Observation
Baseline (no cookie): `GET /account/profile` → 401, `GET /organization` → 401.
After minting the anonymous session, both return **200** with the same cookie. So an
unauthenticated client obtained a session that satisfies `authMiddleware` /
`authOrApiKeyMiddleware`. This matches the static finding exactly: the plugin is
registered (`packages/db/src/auth.ts:137`) with no frontend caller (grep-confirmed —
only unrelated posthog/i18n hits), and `signupGuard` (`apps/api/src/app.ts:114`) wraps
only `/api/auth/sign-up/*`, so the anonymous sign-in bypasses the self-hosted signup
control. The `GET /organization` 200 also demonstrates the VULN-033 chain (any session
reads org config).

## Side effects
- One `user`+`profile`+`session` row created per run (random ids). No cleanup needed;
  harmless orphan anonymous users. Optional: delete `user` rows where `is_anonymous`.

## Research & references
- better-auth `anonymous` plugin docs — it is intended for opt-in guest carts, not a
  general auth surface; leaving it registered with no gating creates free sessions.
- OWASP WSTG-ATHN — testing for unauthenticated access / weak authentication schemas;
  the 401-without-cookie vs 200-with-anon-cookie differential is the standard proof.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.
