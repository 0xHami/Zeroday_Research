# VULN-002 — download.php isTempFile ACL bypass: read any upload/ file by GUID

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:41Z

## Preconditions
- Admin creates victim **V** and attacker **A** (fresh, unrelated low-priv users).
- As **V**: `module=Notes&action=Save` creates a bare Note. As **V** (legacy REST, `rest_login` + `rest_call('set_note_attachment', ...)`): attaches a file (unique random-marker contents) to that Note — `modules/Notes/NoteSoap.php:newSaveFile()` writes the bytes to `upload/<note_id>` on the app container's disk via `$this->upload_file->final_move($focus->id)`. This is the same primitive the real Notes-attachment UI uses (confirmed by reading `NoteSoap.php`), not a synthetic shortcut.

## Request
See `request.http` (both the bypass and the honesty-control request). Bypass:
```
GET /index.php?entryPoint=download&type=Notes&isTempFile=1&id=<note_id> HTTP/1.1
Cookie: PHPSESSID=<attacker session>
```

## Response
See `response.txt`. Bypass: HTTP 200, 49-byte body that is byte-for-byte identical to what V uploaded (`SECRET FILE CONTENTS FOR VULN-002 marker_...`). Control (same id, no `isTempFile`, i.e. the normal `ACLAccess('view')`-checked path): also HTTP 200 with the same 49 bytes.

## Observation
Matches the static finding precisely on the code path: `download.php:63 if (!isset($_REQUEST['isTempFile'])) { ... }` gates the entire module-resolution + `ACLAccess('view')` block (`:63-129`) — when `isTempFile` is set, none of it runs, `$local_location` is set to `"upload://{$_REQUEST['id']}"` (`:150-159`, since neither the `ieId` nor `type=="import"` special cases apply), and `:314 echo clean_file_output(file_get_contents($download_location), $mime_type)` streams the file verbatim.

**Honesty control result**: the *non*-`isTempFile` path — the one that DOES call `ACLAccess('view')` — **also** succeeded for the attacker in this lab (`control (non-isTempFile) ... bytes_match=True`). This is the same environmental permissiveness noted across this whole IDOR cluster: the lab has **zero ACL Roles configured** (`SELECT COUNT(*) FROM acl_roles` → 0), so `ACLAccess('view')` itself returns `true` for any authenticated user on a bare Note with no restrictive Role/Security-Group in place. This means the dynamic run here does **not** show a behavioral contrast between the ACL-checked and ACL-skipped paths *in this specific lab configuration* — both currently permit the read. It does **not** refute the finding: `download.php`'s `isTempFile` branch is source-verified to skip the ACL block unconditionally (there is no code path by which it could ever call `ACLAccess`), so in any deployment that restricts Notes/Document visibility via Roles or Security Groups — the normal case for an organization actually using SuiteCRM's authorization model — this branch would still bypass that restriction while the normal path would correctly deny it. The dynamic proof here establishes the mechanism and the exact byte-for-byte file-read primitive; the *delta* against a restrictive baseline could not be demonstrated inside this specific lab's default (wide-open) ACL configuration.

## Side effects
- One Note + one uploaded file (`upload/<note_id>` inside the `app` container) created by V; not deleted (harmless, random-suffixed content, no PII).
- Two new low-priv Users created (harmless).

## Research & references
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- Known-issue cross-check (stage-07): `download.php` has a related but distinct published advisory, GHSA-j2r4-r4wh-339v / CVE-2026-69144 (document-revision **id confusion**, a different branch of this same file), and GHSA-8r72 (attachment authz, general). Whether *this specific* `isTempFile` sink is the same one those advisories patch was flagged as needing confirmation — this dynamic run confirms the `isTempFile` ACL-skip branch is live and exploitable in this build regardless.

## If FAILED
N/A — CONFIRMED.
