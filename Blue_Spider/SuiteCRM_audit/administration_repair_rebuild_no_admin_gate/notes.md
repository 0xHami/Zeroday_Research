# VULN-027 — `Administration action=repair` global rebuild runnable by any authenticated user

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28

## Preconditions
- Any authenticated user (exploit uses a disposable RegularUser, `is_admin=0`). A same-origin `Referer` (which any real logged-in user's browser sends) is needed to pass the separate empty-Referer CSRF guard; that guard is not the authorization control at issue.

## Request
```
GET /index.php?module=Administration&action=repair
Referer: http://localhost:33116/index.php?module=Home&action=index
Cookie: PHPSESSID=<low-priv session>
```

## Response
`HTTP 200`, len ≈ 85 KB — the full repair page (standard admin chrome + repair output), NOT an access-denied page or admin-gate redirect (see `response.txt`). Control (no Referer) → the XSRF template (CSRF guard fired), confirming the only barrier is the referer check.

## Observation
Matches the finding. `modules/Administration/views/view.repair.php:53` runs `RepairAndClear()->repairAndClearAll(['clearAll'], [all modules], false, true)` — wipe all caches + rebuild all extensions/vardefs/relationships — inside `display()` with no `is_admin()` check. The `Administration` module is **commented out** of `$adminOnlyList` (`include/modules.php:285` `//'Administration' => [...]`), so the module-level admin gate that protects other Administration actions does not apply. A non-admin therefore reaches the global repair. The empty-Referer CSRF guard blocks the pure cross-site vector, but a legitimately-authenticated low-priv user (whose browser supplies a same-origin Referer) bypasses the *authorization* control — the missing `is_admin`.

## Side effects
- Runs `repairAndClearAll` once: clears/rebuilds caches (recoverable; transient slowdown). Creates one disposable RegularUser. Repeated invocation is the DoS vector (each call is a heavy global rebuild).

## Research & references
- OWASP API Security Top 10 — API5:2023 BFLA; OWASP WSTG-ATHZ-02.
- CWE-862 (Missing Authorization); the DoS angle is CWE-400 (Uncontrolled Resource Consumption).

## If FAILED
n/a — CONFIRMED.
## If NEEDS_MANUAL
n/a.
