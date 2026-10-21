# VULN-034 — Non-admin writes to global config (`config_override.php`) via ungated Administration/Configurator actions

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:38Z

## Preconditions
- `automation.py` creates one fresh low-priv (non-admin) user **U** via admin (`create_user`).
- No relationship/role assignment needed — the bug requires nothing but a valid session.

## Request
See `request.http`. In short, as **U** (non-admin):
```
POST /index.php?module=Administration&action=UpdateAjaxUI
Cookie: PHPSESSID=<U session>
Content-Type: application/x-www-form-urlencoded

disabled_modules=["StageTenBannedModule_e097ad22"]
```

## Response
See `response.txt` (HTTP 200). The server's own rendered page echoes the accepted state back:
```
SUGAR.config.stockAjaxBannedModules = [...,"StageTenBannedModule_e097ad22"];
SUGAR.config.addAjaxBannedModules = ["StageTenBannedModule_e097ad22"];
```

## Observation
Matches the static finding exactly: `modules/Administration/controller.php:146-153` (`action_UpdateAjaxUI`) builds a `Configurator`, sets `$cfg->config['addAjaxBannedModules']` straight from `$_REQUEST['disabled_modules']`, and calls `$cfg->handleOverride()` — with **no** `is_admin($current_user)` check anywhere in the method. Contrast with the sibling `action_savetabs` (`:56-58`) in the exact same controller/file, which does:
```php
if (!is_admin($current_user)) {
    sugar_die($app_strings['ERR_NOT_ADMIN']);
}
```
**Control test performed**: the script first POSTs to `action=savetabs` as the same non-admin user U and captures the response — it is the literal string `Unauthorized access to administration.` (the `ERR_NOT_ADMIN` language string), 38 bytes, HTTP 200 (`sugar_die` renders this string and stops, it does not itself change the status code) — see `evidence/control_savetabs_response.txt`. This proves the admin gate is present, works, and rejects U in this exact lab/session — and that `UpdateAjaxUI`, reached by the identical non-admin U in the identical session, has no equivalent gate.

## Side effects
`docker compose exec app cat /var/www/html/config_override.php` (captured in `evidence/config_override_after.php`) now contains:
```php
$sugar_config['addAjaxBannedModules'][0] = 'StageTenBannedModule_e097ad22';
```
This is a durable, instance-wide configuration change (survives page loads, affects every user) written entirely by a non-admin account. The marker value is a harmless nonexistent module name — it does not disable any real module or break the app; `addAjaxBannedModules` only suppresses modules from a dropdown *if* they match a real module key, which `StageTenBannedModule_e097ad22` never will. No cleanup needed; left in place as evidence, harmless.

## Research & references
- CWE-285 (Improper Authorization) / CWE-1220 (Insufficient Granularity of Access Control) — OWASP A01:2021-Broken Access Control.
- Technique: differential testing against an in-file "control" (a sibling action in the same controller that *does* enforce `is_admin`), proving the gap is an oversight, not by-design — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation.
