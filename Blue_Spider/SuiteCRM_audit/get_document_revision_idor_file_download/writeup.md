# VULN-003 — `get_document_revision`: Authenticated IDOR, Download Any Document File

**ID**: VULN-003
**Software / Repository**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2, commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: High — **CVSS 3.1 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Status**: `CONFIRMED (dynamic)`
**Auth required**: Any authenticated web-service user (lowest privilege) — a valid legacy `login` session id
**What an attacker gains**: Byte-exact download of any uploaded document/attachment file in the
instance, regardless of the caller's own Documents ACL or Security-Group membership.

## Summary

The legacy web-service method `get_document_revision` retrieves a `DocumentRevisions` bean by a
caller-supplied id and returns its file contents (base64-encoded) after checking only that the
caller has *some* valid session — never whether that caller may see the specific Document the
revision belongs to. Its sibling getter, `get_entry`, does the ACL check correctly. Live testing
confirms the exact contrast: a low-priv user whose Role explicitly denies Documents view/list gets
"Access Denied" from `get_entry` on the parent Document, then downloads that Document's file bytes
in full via `get_document_revision` in the same session.

## How it works (mechanism & code trace)

**Entry point**: `POST /service/v4_1/rest.php` with `method=get_document_revision`,
`rest_data=["<any valid session>", "<document_revision_id>"]`.

**The defect** — `service/core/SugarWebServiceImpl.php:877-905`:
```php
public function get_document_revision($session, $id)
{
    ...
    if (!self::$helperObject->checkSessionAndModuleAccess($session, 'invalid_session', '', '', '', $error)) {
        // :883  module arg is '' -- reduces this call to a SESSION-ONLY check
        return;
    } // if

    require_once('modules/DocumentRevisions/DocumentRevision.php');
    $dr = BeanFactory::newBean('DocumentRevisions');
    $dr->retrieve($id);                                        // :890  NO checkACLAccess() call
    if (!empty($dr->filename)) {
        $filename = "upload://{$dr->id}";
        ...
        $contents = base64_encode($contents);
        return array('document_revision'=>array('id' => $dr->id, 'document_name' => $dr->document_name,
                     'revision' => $dr->revision, 'filename' => $dr->filename, 'file' => $contents));
    }
    ...
}
```
Compare the correctly-gated sibling getter, `get_note_attachment` (`:818`, not the target of this
finding but the pattern the SuiteCRM authors clearly know):
```php
$note->retrieve($id);
if (!self::$helperObject->checkACLAccess($note, 'DetailView', $error, 'no_access')) {
    return;
}
```
and, used directly as the live control in this test, `get_entry`→`get_entries`
(`SugarWebServiceImpl.php:138`):
```php
if (!self::$helperObject->checkACLAccess($seed, 'DetailView', $error, 'no_access')) {
    return;
}
```
`get_document_revision` has neither: no ACL call on the `DocumentRevision` bean, and no ACL call
on the parent `Document` it belongs to. The GUID-keyed `upload://{$dr->id}` path means there is no
path traversal either — this is a pure authorization gap, not a file-path bug.

**Live confirmation** (full transcript in `run.log`): a low-priv user was assigned a Role denying
`Documents` `view` and `list`. Over one legacy-REST session:
- `get_entry` on the parent Document → `{"name":"Access Denied","number":40,"description":"You do
  not have access"}` (correctly denied).
- `get_document_revision` on that Document's revision id → full JSON including
  `"file":"<base64>"`, which decodes to `CVEHUNTER-SECRET-FILE-doc_53f458f3\n` — the exact bytes
  independently confirmed present in `/var/www/html/upload/<revision-id>` inside the app
  container before the low-priv call was ever made.

## Why it is a vulnerability (reasoning)

The trust boundary is the same one VULN-001 describes for records: a user's read access to a
resource is governed by ACL/Role/Security-Group evaluation, and every comparable getter in this
same file enforces it. `get_document_revision`'s own doc comment says it exists "as a result of
the .htaccess lock down on the cache directory" specifically "to allow a properly authenticated
user to download a document **that they have proper rights to download**" — the method's own
documentation states the intended contract, and the implementation does not enforce it; it checks
only that a session exists, not that the rights are proper. This is not a deliberate "documents
are public to all logged-in users" design decision — the Documents module ships with its own ACL
actions (`view`, `list`, `edit`, ...) precisely so an admin can restrict it, and the classic
web-service getter (`get_entry`) already honors that; the file-download variant simply forgot to.

## Reproduction

1. **Preconditions** (built by `automation.py`; concrete ids in `notes.md`):
   - Low-priv user with a Role denying Documents view+list.
   - Admin-owned Document + DocumentRevision carrying a random secret file, confirmed on disk.
2. Low-priv user logs in over the legacy REST API (fresh session, so the Role applies).
3. **Decisive request** (`request.http`):
   ```
   POST /service/v4_1/rest.php
   method=get_document_revision&input_type=JSON&response_type=JSON&
     rest_data=["<low-priv session>","<victim revision id>"]
   ```
4. Run `./run.sh` (`run.log` has the full transcript). Expected:
   ```
   ==> VULN-003: CONFIRMED — low-priv user w/ Documents view=list=NONE downloaded revision
   <id> via get_document_revision; bytes match planted secret b'CVEHUNTER-SECRET-FILE-...\n';
   get_entry() on the parent Document via the same session was denied
   ```
5. **Observable proof**: `response.txt` has the full JSON with the base64 `file` field;
   `evidence/leaked_file.bin` is the raw decoded bytes, byte-identical to the file planted on disk;
   `evidence/get_entry_control_response.json` shows the "Access Denied" control response.

## Impact

Any authenticated user — even one an admin has explicitly locked out of the Documents module —
can exfiltrate any document/attachment file in the CRM by iterating `DocumentRevisions` ids
(harvested via [VULN-001](../../vulns/VULN-001.md)'s JSON-RPC `retrieve` IDOR, the UI, or list
endpoints). This is a full confidentiality break on uploaded document content — contracts,
exports, proposals, anything stored via the Documents module — instance-wide, from the lowest
privilege level. It is the direct read-side counterpart of the write-side IDOR
[VULN-079](../../vulns/VULN-079.md) (which can also *plant* a revision on a victim's Document),
and both chain from the GUID-harvesting primitive in VULN-001.

## Suggested fix

Load the parent Document and enforce ACL before returning bytes, exactly like `get_entry` already
does:
```php
// service/core/SugarWebServiceImpl.php:887 -- suggested, before building $filename
$parentDoc = BeanFactory::newBean('Documents');
$parentDoc->retrieve($dr->document_id);
if (!self::$helperObject->checkACLAccess($parentDoc, 'DetailView', $error, 'no_access')) {
    return;
}
```
and pass the real module name (`'Documents'`) into `checkSessionAndModuleAccess` instead of an
empty string, so the module-level gate is meaningful too.

## References

- CWE-639 — Authorization Bypass Through User-Controlled Key
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- PortSwigger — Access control vulnerabilities (IDOR / file access): https://portswigger.net/web-security/access-control/idor
- Adjacent public issue class: GHSA-8r72-224q-g9fv / GHSA-j2r4-r4wh-339v (SuiteCRM document/attachment read-authz); patch status in this fork commit unconfirmed by this test (this specific sink was reproduced live regardless).
- Technique used: differential authorization testing (ACL'd `get_entry` vs. unguarded `get_document_revision`, same session) plus an out-of-band disk read on the app container to independently verify the leaked bytes.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM get_document_revision IDOR vulnerability CVE` — nothing naming the method; results were CVE-2026-32697 / CVE-2026-29189 (other components).
2. GitHub Advisory DB `SuiteCRM document revision` — 0 results; GitHub issue search `get_document_revision` — none.
3. All 77 SuiteCRM GHSA titles reviewed — only GHSA-j2r4-r4wh-339v (download.php revision confusion) and GHSA-xg3m-xvc9-j55j (GetLatestRevision.php SQLi); neither is in the legacy v4_1 web service.
4. NVD SuiteCRM (107) and SugarCRM (66) CVE descriptions reviewed — none mention get_document_revision or SugarWebServiceImpl.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-69144 / GHSA-j2r4-r4wh-339v — document-revision authorization bypass in download.php (UI path), fixed 7.15.2.
- CVE-2025-54787 / GHSA-8r72-224q-g9fv — unauthenticated upload-directory download in 7.14.6.
- CVE-2026-69140 / GHSA-xg3m-xvc9-j55j — SQL injection in GetLatestRevision.php; different class.
- GHSA-gjgm-wrr6-hrmp — SQL injection in v4_1 get_entry_list; same API family, different class.

**Reasoning:** No public advisory names the v4_1 `get_document_revision` method or its missing ACL check; the related items cover the UI download path or injection bugs. Document-authorization bugs in SuiteCRM have drawn several reports in 2025-2026, so a private report on this method is possible.
