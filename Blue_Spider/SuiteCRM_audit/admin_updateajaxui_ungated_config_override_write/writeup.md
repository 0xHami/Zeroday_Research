# VULN-034 — Non-admin writes to global config (`config_override.php`) via ungated Administration actions

**ID**: VULN-034
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `forkedSuite`/hotfix snapshot)
**Severity**: Medium — **CVSS 3.1: 6.5** — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — a fresh, unprivileged account created via the normal Users EditView is sufficient; no role, admin flag, or special capability needed.
**What an attacker gains**: the ability to durably rewrite instance-wide SuiteCRM configuration (`config_override.php`) with no administrator involvement — a low-priv user attains an admin-only write primitive.

## Summary
`modules/Administration/controller.php` gates its sensitive, config-mutating actions with a per-method `if (!is_admin($current_user)) { sugar_die(...); }` check. Three actions in the Administration/Configurator controllers — `action_savelanguages`, `action_UpdateAjaxUI`, and `Configurator::action_historyContactsEmailsSave` — simply omit that check while still calling `Configurator::handleOverride()`, the routine that persists settings into `config_override.php`. Any authenticated non-admin user can therefore flip system-wide settings that every other user in the instance is subject to. This report dynamically confirms `action_UpdateAjaxUI`.

## How it works (mechanism & code trace)

**Entry point** — `index.php?module=Administration&action=UpdateAjaxUI`, routed by the standard MVC controller dispatch to `AdministrationController::action_UpdateAjaxUI()` (no special `action_file_map` entry needed; `SugarController::process()` calls any public `action_<name>` method it finds).

**Reachability** — `AdministrationController::process()` is inherited unmodified from `SugarController` (the class defines no override), so there is no controller-wide admin gate for this controller at all; authorization is left entirely to each `action_*` method to self-enforce.

**Sink** — `modules/Administration/controller.php:146-153`:
```php
public function action_UpdateAjaxUI()
{
    require_once('modules/Configurator/Configurator.php');
    $cfg = new Configurator();
    $disabled = json_decode(html_entity_decode((string) $_REQUEST['disabled_modules'], ENT_QUOTES));
    $cfg->config['addAjaxBannedModules'] = empty($disabled) ? false : $disabled;
    $cfg->addKeyToIgnoreOverride('addAjaxBannedModules', $disabled);
    $cfg->handleOverride();
    $this->view = "configureajaxui";
}
```
`$_REQUEST['disabled_modules']` is decoded and stored directly into `Configurator::$config['addAjaxBannedModules']`, then `handleOverride()` (`modules/Configurator/Configurator.php:240-…`) diffs it against the live `$sugar_config`, merges the diff into the on-disk override array, and rewrites `config_override.php` from scratch — **no caller identity or role is ever consulted** in this call chain.

**The defect, precisely**: the missing line is the same one-liner present four lines away in a sibling method of the identical file:
```php
// modules/Administration/controller.php:56-58 (action_savetabs — the secure sibling)
if (!is_admin($current_user)) {
    sugar_die($app_strings['ERR_NOT_ADMIN']);
}
```
`action_UpdateAjaxUI` (and `action_savelanguages` at `:78-97`, and `Configurator::action_historyContactsEmailsSave` at `modules/Configurator/controller.php:209-263`) never call this. This is not a differently-scoped-by-design action — `addAjaxBannedModules` is exactly the kind of instance-wide UI-configuration setting `action_savetabs`/`action_saveglobalsearchsettings` already treat as admin-only in the same file.

**Why the framework doesn't save it**: `Administration` is a plain MVC module with no `ACLAccess`-bearing bean backing these actions and (per VULN-027) is not listed in `$adminOnlyList`, so nothing upstream of the method body enforces admin-only access; each action is fully responsible for its own gate, and this one forgot it.

## Why it is a vulnerability (reasoning)
SuiteCRM's trust model treats "who may change system-wide configuration" as an admin-only boundary — enforced explicitly, repeatedly, in the very same controller class, for settings of comparable or lesser sensitivity (enabled tabs, global search settings). `config_override.php` is not a per-user preference; it is loaded on every request for every user and tenant in the instance. Allowing any authenticated low-privilege account to write to it collapses the admin/user trust boundary for a whole class of settings. That this is an oversight rather than an intended "self-service" feature is proven directly: the surrounding, functionally similar actions in the same file gate on `is_admin()`, and nothing in the code, comments, or SuiteCRM's admin-only Administration module UI suggests non-admins are meant to reach this endpoint (it is only ever linked from the Admin panel).

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates one fresh non-admin user **U** (`create_user`). No roles or prior state needed.
2. **Control request**, as **U**, to the admin-gated sibling (proves the gate mechanism works and U is really unprivileged):
   ```
   POST /index.php?module=Administration&action=savetabs
   Cookie: PHPSESSID=<U session>
   ```
   → body is exactly `Unauthorized access to administration.` (`ERR_NOT_ADMIN`), captured in `evidence/control_savetabs_response.txt`.
3. **Attack request**, as the same **U**:
   ```
   POST /index.php?module=Administration&action=UpdateAjaxUI
   Cookie: PHPSESSID=<U session>
   Content-Type: application/x-www-form-urlencoded

   disabled_modules=["StageTenBannedModule_e097ad22"]
   ```
   (full request in `request.http`)
4. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected terminal output ends with:
   ```
   [PROOF] marker 'StageTenBannedModule_e097ad22' present under 'addAjaxBannedModules' in config_override.php: True
   ==> VULN-034: CONFIRMED — non-admin wrote addAjaxBannedModules containing StageTenBannedModule_e097ad22 into config_override.php
   ```
5. **Observable proof** — `docker compose exec app cat config_override.php` (`evidence/config_override_after.php`) shows:
   ```php
   $sugar_config['addAjaxBannedModules'][0] = 'StageTenBannedModule_e097ad22';
   ```
   and the HTTP response itself (`response.txt`) echoes the accepted value back into the rendered page's `SUGAR.config.addAjaxBannedModules`.

## Impact
A non-admin, authenticated user can, with a single unauthenticated-by-role POST:
- Rewrite `addAjaxBannedModules` (UI degradation for every user — hide arbitrary modules from the AJAX UI instance-wide).
- Disable arbitrary languages via the sibling `action_savelanguages` sink (same missing-gate pattern, same `handleOverride()` sink) — denial of a UI feature for the whole user base.
- Flip `hide_history_contacts_emails` via `Configurator::action_historyContactsEmailsSave` — alters what History-subpanel data every user sees.

Because the write lands in the on-disk override file used for **every** request, the blast radius is the entire instance, not just the attacker's own session — and the change persists until an admin (or another attacker) overwrites it again. Shares its root cause with [VULN-027](../../vulns/VULN-027.md) (Administration module not in `$adminOnlyList`) and the incomplete-whitelist pattern in [VULN-013](../../vulns/VULN-013.md)/[VULN-049](../../vulns/VULN-049.md) (Connectors).

## Suggested fix
Add the standard guard, copy-pasted from the working sibling, to all three sinks:
```php
public function action_UpdateAjaxUI()
{
    global $current_user, $app_strings;
    if (!is_admin($current_user)) {
        sugar_die($app_strings['ERR_NOT_ADMIN']);
    }
    // ... existing body ...
}
```
Better: enforce admin authorization **once**, centrally, in `AdministrationController::process()`/`ConfiguratorController::process()` for every `action_*` that ends in a `handleOverride()` call, so no future action can forget the check (allow-list the handful of genuinely non-admin actions instead of denylisting nothing).

## References
- CWE-285 — Improper Authorization; CWE-1220 — Insufficient Granularity of Access Control.
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-03 (Testing for Privilege Escalation).
- PortSwigger Web Security Academy — "Access control vulnerabilities" (unprotected admin functionality reachable by a low-privilege user).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM UpdateAjaxUI non-admin config_override vulnerability CVE` — only unrelated CVEs (CVE-2020-8802 action_saveHTMLField, CVE-2021-41597 UpgradeWizard CSRF, CVE-2024-3641x EmailUIAjax SQLi); nothing on UpdateAjaxUI/config_override
2. `SuiteCRM Administration controller action_savelanguages missing is_admin check advisory` — community language-install threads; one 2016 SugarCRM 6.5.18 Full Disclosure post (fetched, see below) naming different Administration scripts
3. `SuiteCRM Configurator handleOverride privilege escalation non-admin write configuration CVE 2025 2026` — CVE-2025-64489 (session not invalidated on deactivation), CVE-2025-54785 (unserialize), CVE-2021-41869 (generic privesc, no component named); none involve Configurator/handleOverride
4. `SuiteCRM historyContactsEmailsSave OR "addAjaxBannedModules" security advisory` — no relevant results
5. `huntr SuiteCRM Administration module non-admin action privilege escalation "Administration" improper access control 7.14` — CVE-2025-64489 only
6. Fetched seclists.org/fulldisclosure/2016/Jun/50 (SugarCRM <= 6.5.18 Missing Authorization Check) — names `Administration/ImportCustomFieldStructure.php`, `Administration/UpgradeWizard_commit.php` and Connectors `RunTest`; does not name UpdateAjaxUI, savelanguages, historyContactsEmailsSave or Configurator
7. Fetched fix commit for CVE-2023-5353 (c43eaa311f) — HTML purification changes only; does not touch modules/Administration or modules/Configurator

**Related but distinct public references** (same class or component, not this bug):
- SugarCRM CE <= 6.5.18 "Missing Authorization Check" (Full Disclosure, June 2016) — same pattern (admin scripts without is_admin check) but in `ImportCustomFieldStructure.php` / `UpgradeWizard_commit.php` / Connectors `RunTest`, not these three actions
- CVE-2021-41869 — generic "privilege escalation" in 7.10.x/7.11.x, component unspecified, fixed long before 7.15.2
- CVE-2023-5353 — "Improper Access Control" prior to 7.14.1; fix commit touches HTML sanitization, not Administration/Configurator

**Reasoning:** No public advisory, CVE or GHSA names `action_UpdateAjaxUI`, `action_savelanguages`, `Configurator::action_historyContactsEmailsSave`, or non-admin writes to `config_override.php` via `handleOverride()`. The "admin script missing is_admin()" pattern is publicly documented for the SugarCRM parent in other scripts, and SuiteCRM has shipped several generic "improper access control" fixes whose components are not published, so a private report cannot be ruled out; but nothing public matches these specific actions on 7.15.2.
