# VULN-006 — Registration mass-assignment sets emailChecked=true / arbitrary email

**Target name:** PublicCMS
**Target URL:** https://github.com/sanluan/PublicCMS
**Software version:** V5.202608.a
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: e85ab023a22b19bff5b5b0c944440ab614df467f
**Validated at**: 2026-09-19

## Preconditions
- None (anonymous). Registration open (default). Per-IP register lockout allows several
  registrations per 6h window (`DEFAULT_OPERATE_MAX_COUNT=5`), so a single PoC is unaffected.

## Request
See `request.http`. `POST /doRegister` with `name`, `nickname`, `password`, `repassword`,
`email`, and the injected `emailChecked=true`. Then `GET /api/login?username=<email>&...`.

## Response
See `response.txt` / `evidence/api_login_response.json`.
- Register → `302 Location: /` (success; no `error=` marker).
- `/api/login` by email → `{"authToken":"…","user":{"email":"exploit_…@example.invalid","emailChecked":true,"id":"3",…}}`.

## Observation
Matches the static finding. Direct DB confirmation on the first manual run:
`sys_user` row `email_checked=1`, arbitrary `email`, `superuser=0`, `disabled=0` — i.e. the
privilege fields were correctly reset but `email`/`emailChecked` were bound straight from the
request. Impact confirmed end-to-end: login-by-email works, and `findByEmail` only returns rows
with `emailChecked=true`, so the forged verified state is the thing that makes the login resolve.

**Correction to the report's reproduction:** the report used `username=` in the `doRegister`
body. The Spring command object is `SysUser entity`, whose bean property is `name` — `username=`
binds nothing and the account is silently NOT created (302 back to the register page). The working
parameter is `name=`. Verified: `username=` created 0 rows; `name=` created the account.

## Side effects
Creates ONE web user per run (random `poc_<suffix>` / `exploit_<suffix>@example.invalid`),
`superuser=0`. Additive, non-destructive. Cleanup hint in the script footer.

## Research & references
- CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes /
  mass assignment); CWE-345 (Insufficient Verification of Data Authenticity).
- OWASP "Mass Assignment" Cheat Sheet — technique: submit extra fields matching sensitive
  entity properties that the server-side allowlist forgets to reset. Applied to `emailChecked`.
- OWASP WSTG-IDNT / WSTG-ATHN — verified-email as an authentication-state invariant.

## If FAILED
n/a — CONFIRMED.
