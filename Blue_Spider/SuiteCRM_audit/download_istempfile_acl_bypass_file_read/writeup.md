# VULN-002 — download.php `isTempFile` ACL bypass: read any file under `upload/` by GUID

**ID**: VULN-002
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1: 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — `download.php:47` only requires `$_SESSION['authenticated_user_id']` to be set; no module-specific grant.
**What an attacker gains**: byte-for-byte read of any file stored under `upload/` (Note attachments, Document revisions, image fields) instance-wide, by GUID, bypassing whatever ACL/Security-Group restriction would normally apply to the owning record.

## Summary
`download.php` normally resolves the owning bean for a requested file and checks `ACLAccess('view')` before streaming it. Setting the undocumented `isTempFile` request flag skips that entire resolution-and-ACL block and streams `upload/<id>` directly. Any authenticated user who obtains a Note-attachment/Document-revision/field-file GUID can read its raw bytes.

## How it works (mechanism & code trace)

**The ACL block, and its skip condition** — `download.php:63-129`:
```php
63: if (!isset($_REQUEST['isTempFile'])) {
        // module resolution, $focus = BeanFactory::newBean($module); $focus->retrieve($_REQUEST['id']);
101:    if (empty($focus->id) || !$focus->ACLAccess('view')) {
            die($mod_strings['LBL_NO_ACCESS']);
        }
        // ... document-revision handling, remote doc_url redirects ...
    } // if
```
The `if (!isset($_REQUEST['isTempFile']))` guard means: **the entire block, including the `ACLAccess('view')` call, only executes when `isTempFile` is absent.** Set it, and none of this runs.

**Where the file path comes from once the block is skipped** — `download.php:149-159`:
```php
150: if (isset($_REQUEST['ieId']) && isset($_REQUEST['isTempFile'])) {
         $local_location = sugar_cached("modules/Emails/{$_REQUEST['ieId']}/attachments/{$_REQUEST['id']}");
152: } elseif (isset($_REQUEST['isTempFile']) && $file_type == "import") {
         $local_location = "upload://import/{$_REQUEST['tempName']}";
     } else {
159:     $local_location = "upload://{$_REQUEST['id']}";     // <-- our case: isTempFile set, neither special case applies
     }
```
`$_REQUEST['id']` — fully attacker-controlled — becomes the filename read from the `upload://` stream wrapper (SuiteCRM's `upload/` directory). Traversal (`..`) is separately blocked (`download.php:166` checks `strpos($local_location, "..")`), so this is an ID-space enumeration problem (IDOR), not a path-traversal one.

**The read** — `download.php:314`:
```php
314: echo clean_file_output(file_get_contents($download_location), $mime_type);
```
The full file is streamed back; `clean_file_output` only affects encoding/sanitisation of the *output framing*, not access control.

**The exact defect**: the `isTempFile` flag was almost certainly intended for a narrow use case (reading a file the *current* upload session just staged, before it's attached to a real record) but the code never scopes it to "a file this session itself just uploaded" — it accepts *any* GUID, including files that belong to permanently-saved records owned by other users.

## Why it is a vulnerability (reasoning)
The non-`isTempFile` branch demonstrates SuiteCRM's own intended invariant for this exact code path: "before streaming a file under `upload/`, resolve its owning bean and check `ACLAccess('view')`." The `isTempFile` branch reaches the *same* final sink (`file_get_contents` on an `upload://` path, streamed to the client) via a route that skips that check entirely — there is no independent, narrower authorization applied to temp-file reads instead; the check is just absent. A flag whose presence alone removes an authorization gate is inherently a bypass vector, regardless of what the flag's original narrow use case might have been, because nothing constrains it to that narrow case at request time.

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates **V** and **A** (unrelated). As **V**, create a bare Note, then attach a file to it via the legacy REST `set_note_attachment` method (writes `upload/<note_id>` on the app container).
2. **Attack request**, as **A**:
   ```
   GET /index.php?entryPoint=download&type=Notes&isTempFile=1&id=<note_id>
   Cookie: PHPSESSID=<attacker session>
   ```
   (full request, plus the honesty-control request, in `request.http`)
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected tail:
   ```
   [PROOF] attacker's response bytes exactly match V's uploaded file: True
   ==> VULN-002: CONFIRMED — attacker read 49 bytes of V's upload/<note_id> via isTempFile=1, zero ACL check
   ```
4. **Observable proof** — `response.txt` shows a 200 OK whose body is byte-for-byte identical to the marker string V's session uploaded — see `evidence/leaked_file_bytes.txt` for the side-by-side comparison.

**Honesty note**: a control request to the same id *without* `isTempFile` (i.e. through the ACL-checked branch) also succeeded in this lab, because this instance has zero ACL Roles configured and `ACLAccess('view')` is therefore permissive by default for any authenticated user on a bare Note. This does not change the finding: the `isTempFile` branch is source-verified to never call `ACLAccess` under any configuration, so it bypasses restrictions that a production deployment using Roles/Security Groups would otherwise enforce; this lab's default permissiveness simply means the *specific* dynamic run couldn't show a before/after contrast on top of the already-confirmed code-level bypass.

## Impact
- **Confidentiality (broad)**: read any file under `upload/` — Note/Email attachments, Document revisions, uploaded images — instance-wide, by any authenticated user, independent of the owning record's ACL/Security-Group configuration.
- Chains directly with GUID-harvesting findings ([VULN-001] JSON-RPC enumeration, [VULN-024] SubPanelViewer) to turn "one leaked GUID" into "read the underlying file."
- No integrity/availability impact; read-only.

## Suggested fix
Resolve the owning bean and enforce `ACLAccess('view')` on the `isTempFile` path exactly as the normal path does, or — better — scope `isTempFile` reads to files the *current session* itself staged (e.g. a per-session temp namespace / a short-lived signed token issued at upload time) rather than accepting an arbitrary, permanent GUID:
```php
if (isset($_REQUEST['isTempFile'])) {
    // Only allow reading files the CURRENT session uploaded and hasn't
    // yet attached to a record, e.g. verify $_REQUEST['id'] is present
    // in $_SESSION['temp_upload_ids'], or resolve the owning bean and
    // still call ACLAccess('view') before streaming.
}
```

## References
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- GHSA-j2r4-r4wh-339v / CVE-2026-69144 — `download.php` document-revision ID confusion (same file, different branch — known-issue cross-check flagged this `isTempFile` sink as a distinct, separately-confirmable angle, now dynamically confirmed live).
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (IDOR).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM download.php isTempFile ACL bypass vulnerability` — no match; results were CVE-2026-32697 / CVE-2026-29189 (other components) and old traversal CVEs.
2. `GHSA-j2r4-r4wh-339v SuiteCRM download.php` + advisory fetched — CVE-2026-69144: document-revision ID confusion inside the ACL-checked (non-isTempFile) branch, patched 7.15.2; different branch and root cause.
3. `GHSA-8r72-224q-g9fv SuiteCRM` + advisory/OSV fetched — CVE-2025-54787: unauthenticated download from the upload directory, affects 7.14.6 only; download.php at v7.14.6 and v7.14.7 both already require an authenticated session, so that bug is a different (unauthenticated) root cause.
4. Source check at the audited commit: download.php still skips the bean-resolution/ACL block when `isTempFile` is set and builds the upload path from the request id.
5. GitHub Advisory DB `SuiteCRM download` — three unrelated advisories (CVE-2019-25663, CVE-2019-25664, CVE-2020-15301); GitHub issue search `isTempFile` — none.
6. NVD SuiteCRM (107) and SugarCRM (66) CVE descriptions reviewed — nothing mentions isTempFile.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-69144 / GHSA-j2r4-r4wh-339v — same file, different branch (type=Documents revision confusion), fixed before the audited commit.
- CVE-2025-54787 / GHSA-8r72-224q-g9fv — unauthenticated upload-directory download in 7.14.6 only; different root cause.
- CVE-2019-16922, CVE-2019-18782 — public exposure of files / .htaccess enforcement; different mechanism.
- CVE-2020-8803 — directory traversal via add_to_prospect_list; different entry point.

**Reasoning:** Two recent advisories target authorization in download.php, but neither describes the `isTempFile` flag skipping the ACL block, and the audited (post-7.15.2) file still contains it. The file is under active researcher attention, so a pending private report is plausible; confidence is therefore moderate.
