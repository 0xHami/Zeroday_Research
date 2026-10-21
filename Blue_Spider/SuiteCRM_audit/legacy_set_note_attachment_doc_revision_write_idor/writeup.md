# VULN-079 — Legacy `set_note_attachment`/`set_document_revision`: Write-Side IDOR

**ID**: VULN-079
**Software / Repository**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2, commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 5.4** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L`
(dynamic testing shows the real-world impact of the Document half is understated by this vector —
see Impact)
**Status**: `CONFIRMED (dynamic)`
**Auth required**: Any authenticated web-service user — the lowest privilege, with **zero**
special ACL/Role configuration required
**What an attacker gains**: The ability to silently overwrite the file content of any Note
attachment, and to hijack any Document's "latest revision" so that legitimate viewers download
attacker-controlled content by default — both by id, with no ownership or ACL check at all.

## Summary

`set_note_attachment` and `set_document_revision` are the write-side counterparts of the read IDOR
in [VULN-003](../../vulns/VULN-003.md). Both accept a target record id from the caller and write
file content to it after checking only that *a* session exists — never that the caller has any
right to that specific Note or Document. Live testing confirms both, and finds the Document half
is worse than the static description suggested: writing a new revision doesn't just add an orphan
row, it overwrites the parent Document's "current version" pointer, so every future legitimate
download of that Document serves the attacker's content by default.

## How it works (mechanism & code trace)

**Entry points**: `POST /service/v4_1/rest.php`, `method=set_note_attachment` or
`method=set_document_revision`.

**Part A defect** — `service/core/SugarWebServiceImpl.php:772-793`:
```php
public function set_note_attachment($session, $note)
{
    $module_access = '';
    if (!empty($note['related_module_id']) && !empty($note['related_module_name'])) {
        $module_name   = $note['related_module_name'];
        $module_access = 'read';                                        // :782  ONLY if caller supplies one
    }
    if (!self::$helperObject->checkSessionAndModuleAccess($session, 'invalid_session',
            $module_name, $module_access, 'no_access', $error)) {       // :784  else empty -> session-only
        return;
    }
    require_once('modules/Notes/NoteSoap.php');
    $ns = new NoteSoap();
    return array('id'=>$ns->newSaveFile($note));                        // :792  overwrites Note $note['id']
}
```
`NoteSoap::newSaveFile()` (`modules/Notes/NoteSoap.php:115-152`) loads the Note by the caller's id,
writes the new filename/mime type, saves, and physically moves the uploaded bytes to
`upload/{$focus->id}` — the *same* on-disk path the original attachment lived at. There is no
`checkACLAccess()` on the Note anywhere in this path; the only "check" that can ever fire is on a
module of the *attacker's own choosing*, and only if they choose to supply one.

**Part B defect** — `service/core/SugarWebServiceImpl.php:849-861`:
```php
public function set_document_revision($session, $document_revision)
{
    if (!self::$helperObject->checkSessionAndModuleAccess($session, 'invalid_session',
            '', '', '', $error)) {                                      // :853  empty module -> session-only
        return;
    }
    require_once('modules/Documents/DocumentSoap.php');
    $dr = new DocumentSoap();
    return array('id'=>$dr->saveFile($document_revision));             // :861
}
```
`DocumentSoap::saveFile()` (`modules/Documents/DocumentSoap.php:61-106`) loads the **parent**
Document by the caller's id (must already exist), creates a new `DocumentRevisions` row, and then:
```php
$focus->document_revision_id = $revision->id;   // the Document's "which revision is current" pointer
$focus->save();
```
This is the detail that makes live testing more alarming than the static excerpt alone suggested:
the write doesn't just add a new, separate revision — it **repoints the Document itself** at the
attacker's revision as the current one.

**Live confirmation** (full transcript in `run.log`):
- **Part A**: admin's Note held `ORIGINAL-OWNER-CONTENT-orig_64678735`. A brand-new, completely
  unprivileged user called `set_note_attachment` with that Note's id and no
  `related_module_id`/`name` at all. The app container's on-disk file for that Note now reads
  `ATTACKER-OVERWRITE-atk_2cf4b670`.
- **Part B**: admin's Document pointed `document_revision_id` at its original revision
  (`0d36bd9f-...`). The same unprivileged user called `set_document_revision` with that Document's
  id and new content. Afterward, `documents.document_revision_id` for that Document was
  `e9d38da9-...` — the attacker's new revision — and the on-disk bytes for that revision id
  matched the attacker's payload exactly.

## Why it is a vulnerability (reasoning)

The trust boundary is ownership/authorization over a specific record's content — the same one
every *read* counterpart in this cluster protects correctly on one side (`get_note_attachment`
does call `checkACLAccess($note,'DetailView',...)`) and incorrectly on the other
([VULN-003](../../vulns/VULN-003.md)). Here, the *write* path is even more permissive than its own
read sibling: `set_note_attachment` checks ACL on a module the attacker themselves names — a
check that is trivially satisfiable by naming any module the attacker legitimately can read, and
which never touches the actual Note being modified. `set_document_revision` doesn't even offer
that illusion — it is unconditionally session-only. Nothing about either method's purpose requires
skipping ownership checks: a legitimate client attaching a file to *their own* Note or adding a
revision to *their own* Document would pass a proper `checkACLAccess($bean,'Save',...)` check just
as easily as the UI's own upload flow does.

## Reproduction

1. **Preconditions**: admin creates a Note with an attachment and a Document with a revision.
   Attacker needs only a valid low-priv session — no special ACL/Role.
2. **Decisive request, Part A**:
   ```
   POST /service/v4_1/rest.php
   method=set_note_attachment&input_type=JSON&response_type=JSON&rest_data=
     ["<low-priv session>",{"id":"<victim note id>","filename":"pwned.txt","file":"<base64>"}]
   ```
3. **Decisive request, Part B**:
   ```
   method=set_document_revision&rest_data=
     ["<low-priv session>",{"id":"<victim document id>","revision":"2","filename":"malicious.txt","file":"<base64>"}]
   ```
4. Run `./run.sh` (`run.log` has the full transcript). Expected:
   ```
   ==> VULN-079: CONFIRMED — Part A: Note ... attachment overwritten (...); Part B: Document ...
   latest-revision pointer hijacked to attacker revision ... (...)
   ```
5. **Observable proof**: `response.txt` (Part A's raw request/response);
   `evidence/partA_note_file_after.bin` (the overwritten file, byte-identical to the attacker's
   payload); `evidence/partB_new_revision_file.bin` and the `documents.document_revision_id`
   before/after values captured in `run.log`.

## Impact

Any authenticated user — the lowest privilege level, no special configuration needed — can
silently corrupt another user's Note attachments and Documents. The Document half is the more
severe: because `document_revision_id` is repointed, the corruption is not merely "an extra file
exists" but "the next time anyone opens this Document, they get the attacker's content" — a
content-integrity attack against a shared, trusted resource, reachable by the lowest-privileged
account in the system. Extensions/uploads are extension-sanitized (`upload_badext` forces
dangerous extensions to `.txt`), so this is not a direct code-execution primitive, but planting
misleading or malicious file content into a business document workflow (contracts, deliverables,
compliance records) is a meaningful integrity and trust attack on its own. It is the write-side
counterpart of [VULN-003](../../vulns/VULN-003.md) (the matching read IDOR) and chains with the
GUID-harvesting primitive in [VULN-001](../../vulns/VULN-001.md) to locate targets.

## Suggested fix

Before writing, load the target Note/Document by its id and enforce
`checkACLAccess($bean, 'Save')`:
```php
// service/core/SugarWebServiceImpl.php:772 -- suggested, before newSaveFile()
$targetNote = BeanFactory::newBean('Notes');
$targetNote->retrieve($note['id']);
if (empty($targetNote->id) || !self::$helperObject->checkACLAccess($targetNote, 'Save', $error, 'no_access')) {
    return;
}
```
and equivalently for `set_document_revision`, checking the parent Document. Do not derive the ACL
module from caller-supplied `related_module_*` fields — check the actual record being modified.

## References

- CWE-639 — Authorization Bypass Through User-Controlled Key
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- Adjacent public issue class: GHSA-8r72-224q-g9fv (attachment authorization), CVE-2022-45185 / GHSA-qjmp-rfrj-7cv5 (upload-related); the write-side "hijack the current revision pointer" angle demonstrated here is specific to this test.
- Technique used: content-integrity differential (plant known content as the legitimate owner, overwrite as an unrelated unprivileged user, verify the change on the app container's disk and, for Documents, in the `documents.document_revision_id` pointer — independent of the API's own success response).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched GHSA-8r72-224q-g9fv (CVE-2025-54787) — *unauthenticated download* of any `upload/` file by id (read side), fixed 7.14.7; not the write-side setters.
2. Fetched GHSA-j2r4-r4wh-339v (CVE-2026-69144) — `download.php` ACL run against an empty Documents bean when a revision id is supplied (read side), fixed 7.15.2; not `set_document_revision`.
3. CVE record CVE-2022-45185 (cited by the scanner) — authenticated upload of malicious files + deserialization RCE in 7.12.7; different class.
4. GitHub Advisory Database queries `suitecrm attachment` (only CVE-2021-45903 persistent XSS) and `suitecrm document` (CVE-2020-15300 SVG open redirect, CVE-2020-14208 stored XSS in Documents preview) — no authorization advisory on the setters.
5. GitHub issue searches `repo:SuiteCRM/SuiteCRM set_note_attachment` (0 results) and `set_document_revision` (2 results: feature PR #10766 and a how-to question #8842; no security report).
6. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) reviewed — no advisory for `set_note_attachment` / `set_document_revision` or `NoteSoap::newSaveFile()` / `DocumentSoap::saveFile()`.
7. GitHub commit history of `service/core/SugarWebServiceImpl.php` — no ACL added to either setter.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-54787 / GHSA-8r72-224q-g9fv — attachment *download* authorization; read direction, different endpoint.
- CVE-2026-69144 / GHSA-j2r4-r4wh-339v — document-revision id confusion in `download.php`; read direction.
- CVE-2022-45185 — upload + deserialization RCE; different class.

**Reasoning:** Public SuiteCRM attachment/document advisories cover unauthorized *reads* and malicious uploads; none describes the legacy service setters writing to a Note/Document selected purely by caller-supplied id, nor the `document_revision_id` pointer hijack. Confidence is moderate because the legacy SOAP/REST file methods are inherited from SugarCRM CE and have attracted many historical reports (so an old SugarCRM-era advisory on `set_note_attachment` cannot be fully excluded without a general web search), and the read-side counterparts were only recently patched, suggesting researchers are actively probing this surface.
